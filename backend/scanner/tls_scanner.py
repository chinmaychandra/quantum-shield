# tls_scanner.py — performs TLS handshakes and collects cipher suite and protocol data

# this file is called by scan_task.py to perform the tls scanning phase which is done afetr the discovery phase

# about:
# performs TLS handshakes and collects cipher suite and protocol data
# Discovers every cipher suite, TLS version, key exchange
# the server supports — not just what it negotiates by default.
# Uses sslyze under the hood.

# Returns everything as TLSScanResult which cert_parser.py and pqc_classifier.py
# will consume in the next phases

from sslyze import (
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ScanCommand,
    ServerConnectivityTester,
)

from sslyze.errors import ServerNotReachable, ServerTlsConfigurationNotSupported
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class TLSScanResult:
    host: str 
    port: int

    supported_versions: list[str] = field(default_factory=list)
    supported_cipher_suites: list[str] = field(default_factory=list)
    key_exchange: str
    key_exchange_curve: str
    key_exchange_bits: int

    cert_chain: list = field(default_factory=list)

    # TLS session features
    session_resumption: bool                = False
    compression_enabled: bool              = False
    fallback_scsv: bool                    = False
    # fallback_scsv = protection against downgrade attacks

    # Vulnerabilities
    heartbleed_vulnerable: bool            = False
    robot_vulnerable: bool                 = False

    # Best and worst versions found
    best_version: str                      = None
    worst_version: str                     = None

    error: str = None

    def to_dict(self):
        return {
            "host": self.host,
            "port": self.port,
            "supported_versions": self.supported_versions,
            "supported_cipher_suites": self.supported_cipher_suites,
            "key_exchange": self.key_exchange,
            "key_exchange_curve": self.key_exchange_curve,
            "key_exchange_bits": self.key_exchange_bits,
            "cert_chain": self.cert_chain,
            "session_resumption": self.session_resumption,
            "compression_enabled": self.compression_enabled,
            "fallback_scsv": self.fallback_scsv,
            "heartbleed_vulnerable": self.heartbleed_vulnerable,
            "robot_vulnerable": self.robot_vulnerable,
            "best_version": self.best_version,
            "worst_version": self.worst_version,
            "error": self.error,
        }


VERSION_PRIORITY = {
    "SSL_2_0": 0,
    "SSL_3_0": 1,
    "TLS_1_0": 2,
    "TLS_1_1": 3,
    "TLS_1_2": 4,
    "TLS_1_3": 5,
}

#core engine
# public api to run a full TLS scan against one host:port
def run_tls_scan(host: str,port: int = 443) -> TLSScanResult:
    result = TLSScanResult(host: host,port: port)

    # Test connectivity
    try:
        # packages the target
        server_location = ServerNetworkLocation(host,port)
        # tries to connect and perform a basic TLS handshake
        server_info = ServerConnectivityTester().perform(server_location)

    except ServerNotReachable as e:
        result.error = f"Server not reachable: {e}"
        return result
    except Exception as e:
        result.error = f"Connectivity test failed: {e}"
        return result
    
    # build a scan request with all commands
    try:
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                # Check every TLS version
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,

                # Certificate info
                ScanCommand.CERTIFICATE_INFO,

                # Session features
                ScanCommand.SESSION_RESUMPTION,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.TLS_FALLBACK_SCSV,

                # Elliptic curves supported
                ScanCommand.ELLIPTIC_CURVES,

                # Known vulnerabilities
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
            }
        )
        
        # Run the scan
        scanner = Scanner()
        scanner.queue_scan(scan_request)
        scan_result = next(scanner.get_results())

        # parse everything
        result = parse_sslyze_result(scan_result,host,port)

    except Exception as e:
        result.error = f"TLS Scan failed: {e}"

    return result

#PARSE SSLYZE RESULT 
def parse_sslyze_result(scan_result, host: str, port: int) -> TLSScanResult:
    result = TLSScanResult(host=host, port=port)

    # Map of scan commands to version names
    version_commands = {
        ScanCommand.SSL_2_0_CIPHER_SUITES: "SSL_2_0",
        ScanCommand.SSL_3_0_CIPHER_SUITES: "SSL_3_0",
        ScanCommand.TLS_1_0_CIPHER_SUITES: "TLS_1_0",
        ScanCommand.TLS_1_1_CIPHER_SUITES: "TLS_1_1",
        ScanCommand.TLS_1_2_CIPHER_SUITES: "TLS_1_2",
        ScanCommand.TLS_1_3_CIPHER_SUITES: "TLS_1_3",
    }

    for command, version_name in version_commands.items():
        try:
            attempt = scan_result.scan_result
            cipher_result = getattr(attempt, command.value, None)

            if cipher_result and not isinstance(
                cipher_result, Exception
            ):
                accepted = cipher_result.accepted_cipher_suites

                if accepted:
                    # This version is supported
                    result.supported_versions.append(version_name)

                    for suite in accepted:
                        cipher_entry = {
                            "name": suite.cipher_suite.name,
                            "version": version_name,
                            "key_size": getattr(
                                suite.cipher_suite,
                                "key_size", None
                            ),
                        }
                        result.supported_ciphers.append(cipher_entry)

                        # Extract key exchange from cipher name
                        if result.key_exchange is None:
                            result.key_exchange = extract_key_exchange(
                                suite.cipher_suite.name
                            )

        except Exception:
            continue

    # best and worst versions
    if result.supported_versions:
        result.best_version = max(
            result.supported_versions,
            key=lambda v: VERSION_PRIORITY.get(v, 0)
        )
        result.worst_version = min(
            result.supported_versions,
            key=lambda v: VERSION_PRIORITY.get(v, 0)
        )

    #certchain
    try:
        cert_info = scan_result.scan_result.certificate_info
        if cert_info and not isinstance(cert_info, Exception):
            deployment = cert_info.certificate_deployments[0]
            result.cert_chain = [
                cert.public_bytes(
                    __import__('cryptography').hazmat.primitives.serialization.Encoding.DER
                )
                for cert in deployment.received_certificate_chain
            ]

            # Extract key exchange from certificate
            leaf_cert = deployment.received_certificate_chain[0]
            pub_key = leaf_cert.public_key()
            result.key_exchange_bits = pub_key.key_size if hasattr(
                pub_key, 'key_size'
            ) else None

    except Exception:
        pass

    try:
        resumption = scan_result.scan_result.session_resumption
        if resumption and not isinstance(resumption, Exception):
            result.session_resumption = (
                resumption.is_ticket_resumption_supported or
                resumption.is_session_id_resumption_supported
            )
    except Exception:
        pass


    try:
        compression = scan_result.scan_result.tls_compression
        if compression and not isinstance(compression, Exception):
            result.compression_enabled = compression.supports_compression
    except Exception:
        pass

    #fallback
    try:
        fallback = scan_result.scan_result.tls_fallback_scsv
        if fallback and not isinstance(fallback, Exception):
            result.fallback_scsv = fallback.supports_fallback_scsv
    except Exception:
        pass

    #Heartbleed
    try:
        heartbleed = scan_result.scan_result.heartbleed
        if heartbleed and not isinstance(heartbleed, Exception):
            result.heartbleed_vulnerable = heartbleed.is_vulnerable_to_heartbleed
    except Exception:
        pass

    #ROBOT
    try:
        robot = scan_result.scan_result.robot
        if robot and not isinstance(robot, Exception):
            from sslyze.plugins.robot.implementation import RobotScanResultEnum
            result.robot_vulnerable = (
                robot.robot_result == RobotScanResultEnum.VULNERABLE_WEAK_ORACLE or
                robot.robot_result == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE
            )
    except Exception:
        pass

    return result


def extract_key_exchange(cipher_name: str) -> str:
    # Extracts key exchange algorithm from cipher suite name
    # e.g. "ECDHE_RSA_WITH_AES_256_GCM_SHA384" → "ECDHE"
    # e.g. "TLS_AES_256_GCM_SHA384" → "X25519" (TLS 1.3 default)

    cipher_upper = cipher_name.upper()

    if cipher_upper.startswith("TLS_AES") or \
       cipher_upper.startswith("TLS_CHACHA"):
        # TLS 1.3 cipher — key exchange is separate
        return "X25519"

    if "ECDHE" in cipher_upper:
        return "ECDHE"
    if "DHE" in cipher_upper:
        return "DHE"
    if "ECDH" in cipher_upper:
        return "ECDH"
    if "DH" in cipher_upper:
        return "DH"
    if "RSA" in cipher_upper:
        return "RSA"

    return "UNKNOWN"