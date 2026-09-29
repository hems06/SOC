"""
Headers Scanner - Checks HTTP security headers
"""
from typing import List
import httpx
from app.scanners.base import BaseScanner, BaseFinding
from app.models.finding import Severity, Confidence
from app.models.evidence import EvidenceType
from app.config import settings


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "cwe_id": "CWE-523",
        "cwe_name": "Unprotected Transport of Credentials",
        "description": "HTTP Strict Transport Security (HSTS) header is missing. This header forces browsers to use HTTPS.",
        "impact": "Users could be subjected to protocol downgrade attacks or cookie hijacking.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
    },
    "Content-Security-Policy": {
        "severity": Severity.LOW,
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "description": "Content Security Policy header is missing. CSP helps prevent XSS and data injection attacks.",
        "impact": "The application may be more vulnerable to XSS attacks without CSP.",
        "remediation": "Implement a Content-Security-Policy header appropriate for the application's requirements.",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "description": "X-Content-Type-Options header is missing. This header prevents MIME type sniffing.",
        "impact": "Browsers may interpret files as a different MIME type, potentially leading to security issues.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
    },
    "X-Frame-Options": {
        "severity": Severity.LOW,
        "cwe_id": "CWE-1021",
        "cwe_name": "Improper Restriction of Rendered UI Layers or Frames",
        "description": "X-Frame-Options header is missing. This header prevents clickjacking attacks.",
        "impact": "The application could be embedded in an iframe on a malicious site for clickjacking.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
    },
    "Referrer-Policy": {
        "severity": Severity.INFORMATIONAL,
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information",
        "description": "Referrer-Policy header is missing. This header controls how much referrer information is sent.",
        "impact": "Sensitive URL parameters may be leaked to third-party sites through the Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or a more restrictive policy.",
    },
    "Permissions-Policy": {
        "severity": Severity.INFORMATIONAL,
        "cwe_id": "CWE-693",
        "cwe_name": "Protection Mechanism Failure",
        "description": "Permissions-Policy header is missing. This header controls browser feature access.",
        "impact": "The application does not restrict browser features like camera, microphone, or geolocation.",
        "remediation": "Add a Permissions-Policy header to restrict unnecessary browser features.",
    },
}


class HeadersScanner(BaseScanner):
    """Scans HTTP response headers for security issues."""

    async def scan(self) -> List[BaseFinding]:
        findings = []
        target_url = self.project.target_url

        if not target_url:
            return findings

        if settings.safe_mode and not settings.is_target_allowed(target_url):
            return findings

        self.update_progress(10)

        try:
            async with httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.get(target_url)

                self.update_progress(50)

                response_headers = dict(response.headers)
                response_headers_lower = {k.lower(): v for k, v in response_headers.items()}

                for header_name, header_info in SECURITY_HEADERS.items():
                    if header_name.lower() not in response_headers_lower:
                        finding = BaseFinding(
                            title=f"Missing Security Header: {header_name}",
                            severity=header_info["severity"],
                            confidence=Confidence.CONFIRMED,
                            category="security_headers",
                            cwe_id=header_info["cwe_id"],
                            cwe_name=header_info["cwe_name"],
                            affected_component=target_url,
                            affected_endpoint=target_url,
                            description=header_info["description"],
                            technical_details=f"The HTTP response from {target_url} does not include the {header_name} header.",
                            impact=header_info["impact"],
                            remediation=header_info["remediation"],
                            scanner_source="headers_scanner",
                            retest_procedure=f"Send a GET request to {target_url} and verify the {header_name} header is present in the response.",
                        )

                        # Format response headers for evidence
                        headers_text = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
                        finding.add_evidence(
                            evidence_type=EvidenceType.HTTP_RESPONSE,
                            title=f"HTTP Response Headers from {target_url}",
                            content=headers_text,
                            request_method="GET",
                            request_url=target_url,
                            response_status=str(response.status_code),
                            response_headers=response_headers,
                        )

                        findings.append(finding)
                        self.save_finding(finding)

                # Check for server version disclosure
                server_header = response_headers_lower.get("server", "")
                if server_header and any(
                    v in server_header.lower()
                    for v in ["apache/", "nginx/", "iis/", "express"]
                ):
                    finding = BaseFinding(
                        title=f"Server Version Disclosure: {server_header}",
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.CONFIRMED,
                        category="information_disclosure",
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information",
                        affected_component=target_url,
                        affected_endpoint=target_url,
                        description=f"The server discloses its version: {server_header}",
                        technical_details=f"Server header value: {server_header}",
                        impact="Server version information aids attackers in finding known vulnerabilities.",
                        remediation="Configure the web server to suppress or generalize the Server header.",
                        scanner_source="headers_scanner",
                    )
                    finding.add_evidence(
                        evidence_type=EvidenceType.HTTP_RESPONSE,
                        title="Server Header Disclosure",
                        content=f"Server: {server_header}",
                        request_method="GET",
                        request_url=target_url,
                        response_status=str(response.status_code),
                        response_headers=response_headers,
                    )
                    findings.append(finding)
                    self.save_finding(finding)

        except httpx.ConnectError:
            pass  # Target not reachable - not a finding
        except Exception as e:
            pass

        self.update_progress(100)
        return findings
