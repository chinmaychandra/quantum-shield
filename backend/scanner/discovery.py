# discovery.py — discovers targets (hosts, services, endpoints) to be scanned

# the first phase of every scan 
# discovers all hosts, services, and endpoints to be scanned
# Answers: what IPs, what ports, any forgotten subdomains?
# Called by scan_task.py as the first step

import json
import asyncio,aiohttp,socket
import dns.resolver,
from dataclasses import dataclass,field # to build result objects
from config import Settings

# Result object for discovery phase
@dataclass
class DiscoveryResult:
    host: str
    ip_addresses: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    cdn_detected: bool = False
    cdn_provider: str = None
    hsts_present: bool = False
    error: str = None

    def to_dict(self):
        return {
            "host": self.host,
            "ip_addresses": self.ip_addresses,
            "subdomains": self.subdomains,
            "open_ports": self.open_ports,
            "cdn_detected": self.cdn_detected,
            "cdn_provider": self.cdn_provider,
            "hsts_present": self.hsts_present,
        }


# Actual discovery logic
def run_discovery(host: str) -> DiscoveryResult:
    # Runs all discovery steps and return a DiscoveryResult object
    result = DiscoveryResult(host=host)

    # 1. Resolve IP addresses
    try:
       result.ip_addresses =  resolve_dns(host)
    except Exception as e:
        result.error = f"DNS resolution failed: {e}"
        return result

    # 2. Discover subdomains
    try:
        result.subdomains = query_ct_logs(host)
    except Exception as e:
        result.error = f"Subdomain discovery failed: {e}"
        return result

    # 3. Discover open ports
    try:
        result.open_ports = scan_ports(host)
    except Exception as e:
        result.open_ports = []

    # 4. Detect CDN
    try:
        result.cdn_detected, result.cdn_provider = detect_cdn(host)
    except Exception as e:
        result.cdn_detected = False

    # 5. Check HSTS
    try:
        result.hsts_present = check_hsts(host)
    except Exception as e:
        result.hsts_present = False

    return result

# dns resolution function,returns all the ip addresses for a given host
def resolve_dns(host: str) -> list[str]:
    ips = []

    try:
        answers = dns.resolver.resolve(host, "A")
        ips.extend([r.address for r in answers])
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(host, "AAAA")
        ips.extend([r.address for r in answers])
    except Exception:
        pass

    if not ips:
        # Fallback to basic socket if dnspython fails
        ip = socket.gethostbyname(host)
        ips.append(ip)

    return list(set(ips))

# ct log query function,returns all the subdomains for a given host
def query_ct_logs(host: str) -> list[str]:
    # Queries crt.sh — a public certificate transparency log
    # Finds ALL certificates ever issued for this domain
    # This reveals forgotten subdomains attackers might use
    # e.g. old-api.bank.com, staging.bank.com still exposed

    import urllib.request
    url = f"https://crt.sh/?q=%.{host}&output=json"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode())

        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            # CT logs can have multiple names separated by newlines
            for n in name.split("\n"):
                n = n.strip().lower()
                if n.endswith(host) and n != host:
                    subdomains.add(n)

        return list(subdomains)[:20]  # cap at 20 for demo

    except Exception:
        return []


# port scanning function,returns all the open ports for a given host
def scan_ports(host: str) -> list[int]:
    # Checks which TLS-capable ports are actually open
    # These are the ports we'll TLS scan in the next phase
    tls_ports = [443, 8443, 8080, 9443]
    open_ports = []

    for port in tls_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # 3 second timeout per port
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass

    return open_ports


# cdn detection function,returns if a given host is behind a cdn and the provider
def detect_cdn(host: str) -> tuple[bool, str | None]:
    # Checks if asset sits behind a CDN
    # Important because if CDN is detected, the TLS we see
    # might be the CDN's TLS, not the bank's actual TLS
    # This gets flagged in the CBOM as a note

    cdn_signatures = {
        "cloudflare": ["cloudflare", "cdn.cloudflare"],
        "akamai":     ["akamai", "akamaitechnologies"],
        "fastly":     ["fastly"],
        "cloudfront": ["cloudfront.net"],
        "incapsula":  ["incapdns", "incapsula"],
    }

    try:
        answers = dns.resolver.resolve(host, "CNAME")
        cname = str(answers[0].target).lower()

        for provider, signatures in cdn_signatures.items():
            if any(sig in cname for sig in signatures):
                return True, provider

    except Exception:
        pass

    return False, None


# hsts check function,returns if a given host has hsts enabled
def check_hsts(host: str) -> bool:
    # Checks if Strict-Transport-Security header is present
    # HSTS forces browsers to always use HTTPS
    # Missing HSTS = potential downgrade attack vector

    import urllib.request
    import ssl

    try:
        ctx = ssl.create_default_context()
        url = f"https://{host}"

        req = urllib.request.Request(url, headers={"User-Agent": "QuantumShieldScanner/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            headers = dict(response.headers)
            return "strict-transport-security" in {k.lower(): v for k, v in headers.items()}

    except Exception:
        return False

