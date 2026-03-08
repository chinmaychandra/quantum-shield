# scanner/api_prober.py
# Third scanning phase after certificate analysis.
# Goes one layer deeper than TLS — checks HTTP level security.
# Inspects security headers, detects auth mechanisms,
# extracts JWT algorithm if present.
# Called by scan_task.py after parse_cert_chain() completes.

import httpx
import base64
import json
from dataclasses import dataclass, field
from typing import Optional


# ─── RESULT OBJECT ──────────────────────────────────────────
@dataclass
class APIProbeResult:
    host: str

    # Security headers
    hsts_present:           bool        = False
    hsts_max_age:           int         = None
    csp_present:            bool        = False
    x_content_type:         bool        = False
    x_frame_options:        bool        = False
    referrer_policy:        bool        = False

    # CORS
    cors_present:           bool        = False
    cors_wildcard:          bool        = False
    # wildcard (*) means any domain can call this API = dangerous

    # Auth
    auth_mechanism:         str         = None
    # "JWT" | "OAuth2" | "APIKey" | "BasicAuth" | "mTLS" | "None"
    jwt_algorithm:          str         = None
    # e.g. "RS256", "ES256", "HS256"

    # Info leakage
    server_header:          str         = None
    # e.g. "nginx/1.18.0" — version leakage is a risk
    x_powered_by:           str         = None
    # e.g. "Express" — framework leakage

    # Overall
    warnings:               list[str]   = field(default_factory=list)
    insecure_endpoints:     list[str]   = field(default_factory=list)
    error:                  str         = None

    def to_dict(self):
        return {
            "host": self.host,
            "hsts_present": self.hsts_present,
            "hsts_max_age": self.hsts_max_age,
            "csp_present": self.csp_present,
            "x_content_type": self.x_content_type,
            "cors_wildcard": self.cors_wildcard,
            "auth_mechanism": self.auth_mechanism,
            "jwt_algorithm": self.jwt_algorithm,
            "server_header": self.server_header,
            "warnings": self.warnings,
            "insecure_endpoints": self.insecure_endpoints,
        }


# ─── MAIN FUNCTION ──────────────────────────────────────────
def probe_api(host: str) -> APIProbeResult:
    # Entry point called by scan_task.py
    result = APIProbeResult(host=host)

    try:
        url = f"https://{host}"

        # httpx with SSL verification
        # timeout=10 so scanner doesn't hang forever
        with httpx.Client(
            verify=True,
            timeout=10,
            follow_redirects=True,
            headers={"User-Agent": "QuantumShieldScanner/1.0"}
        ) as client:
            response = client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Run all checks
            check_security_headers(headers, result)
            check_cors(headers, result)
            check_auth(headers, response, result)
            check_info_leakage(headers, result)

    except httpx.SSLError as e:
        result.error = f"SSL error: {e}"
        result.warnings.append("CRITICAL: SSL certificate error on probe")
    except httpx.ConnectError as e:
        result.error = f"Connection failed: {e}"
    except httpx.TimeoutException:
        result.error = "Probe timed out after 10 seconds"
    except Exception as e:
        result.error = f"Probe failed: {e}"

    return result


# ─── SECURITY HEADERS ───────────────────────────────────────
def check_security_headers(headers: dict, result: APIProbeResult):
    # HSTS — forces HTTPS, prevents downgrade attacks
    hsts = headers.get("strict-transport-security")
    if hsts:
        result.hsts_present = True
        try:
            # Extract max-age value
            for part in hsts.split(";"):
                if "max-age" in part.lower():
                    result.hsts_max_age = int(
                        part.strip().split("=")[1].strip()
                    )
        except Exception:
            pass

        if result.hsts_max_age and result.hsts_max_age < 31536000:
            result.warnings.append(
                "WARNING: HSTS max-age less than 1 year"
            )
    else:
        result.warnings.append("WARNING: HSTS header missing")

    # CSP — prevents XSS attacks
    if "content-security-policy" in headers:
        result.csp_present = True
    else:
        result.warnings.append("WARNING: Content-Security-Policy missing")

    # X-Content-Type-Options — prevents MIME sniffing
    if "x-content-type-options" in headers:
        result.x_content_type = True
    else:
        result.warnings.append("WARNING: X-Content-Type-Options missing")

    # X-Frame-Options — prevents clickjacking
    if "x-frame-options" in headers:
        result.x_frame_options = True
    else:
        result.warnings.append("WARNING: X-Frame-Options missing")

    # Referrer-Policy — controls referrer info
    if "referrer-policy" in headers:
        result.referrer_policy = True


# ─── CORS CHECK ─────────────────────────────────────────────
def check_cors(headers: dict, result: APIProbeResult):
    cors = headers.get("access-control-allow-origin")

    if cors:
        result.cors_present = True
        if cors.strip() == "*":
            result.cors_wildcard = True
            result.warnings.append(
                "CRITICAL: CORS wildcard (*) — any domain can call this API"
            )


# ─── AUTH DETECTION ─────────────────────────────────────────
def check_auth(headers: dict, response, result: APIProbeResult):
    # Detect what auth mechanism the API uses
    # by looking at WWW-Authenticate header and
    # Authorization patterns in response

    www_auth = headers.get("www-authenticate", "").lower()

    if "bearer" in www_auth:
        result.auth_mechanism = "JWT"
        # Try to find a sample JWT to extract algorithm
        jwt_algo = extract_jwt_algorithm_from_headers(headers)
        if jwt_algo:
            result.jwt_algorithm = jwt_algo

            # Flag classical JWT algorithms
            # (no PQC JWT standard exists yet)
            if jwt_algo in ["RS256", "RS384", "RS512"]:
                result.warnings.append(
                    f"WARNING: JWT uses RSA algorithm ({jwt_algo}) — quantum vulnerable"
                )
            elif jwt_algo in ["ES256", "ES384", "ES512"]:
                result.warnings.append(
                    f"WARNING: JWT uses ECDSA algorithm ({jwt_algo}) — quantum vulnerable"
                )
            elif jwt_algo == "HS256":
                result.warnings.append(
                    "INFO: JWT uses HMAC (HS256) — symmetric, not quantum vulnerable"
                )

    elif "basic" in www_auth:
        result.auth_mechanism = "BasicAuth"
        result.warnings.append(
            "WARNING: Basic Auth detected — credentials sent base64 encoded"
        )

    elif "oauth" in www_auth or "oauth" in str(response.url).lower():
        result.auth_mechanism = "OAuth2"

    else:
        # Check for API key patterns in response headers
        api_key_headers = ["x-api-key", "api-key", "x-auth-token"]
        for h in api_key_headers:
            if h in headers:
                result.auth_mechanism = "APIKey"
                break

    if not result.auth_mechanism:
        result.auth_mechanism = "None"
        result.warnings.append(
            "INFO: No auth mechanism detected on root endpoint"
        )


# ─── JWT ALGORITHM EXTRACTION ───────────────────────────────
def extract_jwt_algorithm_from_headers(headers: dict) -> Optional[str]:
    # If a JWT token is present anywhere in headers,
    # decode its header (base64) and extract the 'alg' field
    # JWT format: header.payload.signature
    # header is base64url encoded JSON

    for header_name, header_value in headers.items():
        if "authorization" in header_name.lower():
            parts = header_value.split(".")
            if len(parts) == 3:
                try:
                    # Add padding if needed for base64
                    padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    decoded = base64.urlsafe_b64decode(padded)
                    jwt_header = json.loads(decoded)
                    return jwt_header.get("alg")
                except Exception:
                    pass

    return None


# ─── INFO LEAKAGE ───────────────────────────────────────────
def check_info_leakage(headers: dict, result: APIProbeResult):
    # Server header reveals web server + version
    # e.g. "nginx/1.18.0" tells attacker exactly what to exploit
    server = headers.get("server")
    if server:
        result.server_header = server
        # If version number is present, flag it
        if any(char.isdigit() for char in server):
            result.warnings.append(
                f"WARNING: Server header reveals version: {server}"
            )

    # X-Powered-By reveals framework
    powered_by = headers.get("x-powered-by")
    if powered_by:
        result.x_powered_by = powered_by
        result.warnings.append(
            f"WARNING: X-Powered-By reveals framework: {powered_by}"
        )
        