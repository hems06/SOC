"""
API Scanner - Tests API endpoint security
"""
from typing import List
import httpx
from app.scanners.base import BaseScanner, BaseFinding
from app.models.finding import Severity, Confidence
from app.models.evidence import EvidenceType
from app.config import settings


class ApiScanner(BaseScanner):
    """Scans API endpoints for security issues."""

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
                # Test 1: HTTP Methods
                self.update_progress(20)
                await self._check_http_methods(client, target_url, findings)

                # Test 2: Error information disclosure
                self.update_progress(40)
                await self._check_error_disclosure(client, target_url, findings)

                # Test 3: Information in response headers
                self.update_progress(60)
                await self._check_info_headers(client, target_url, findings)

                # Test 4: HTTPS enforcement
                self.update_progress(80)
                await self._check_https(client, target_url, findings)

        except httpx.ConnectError:
            pass
        except Exception:
            pass

        self.update_progress(100)
        return findings

    async def _check_http_methods(self, client, url, findings):
        """Check which HTTP methods are allowed."""
        try:
            response = await client.options(url)
            allow_header = response.headers.get("allow", "")

            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(",")]
                dangerous_methods = [m for m in methods if m in ["DELETE", "PUT", "PATCH", "TRACE"]]

                if "TRACE" in dangerous_methods:
                    finding = BaseFinding(
                        title="HTTP TRACE Method Enabled",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category="api_security",
                        cwe_id="CWE-693",
                        cwe_name="Protection Mechanism Failure",
                        affected_component=url,
                        affected_endpoint=url,
                        description="TRACE method is enabled, which can be exploited for Cross-Site Tracing (XST) attacks.",
                        technical_details=f"Allow header: {allow_header}",
                        impact="TRACE can be used to steal credentials via XST attacks.",
                        remediation="Disable TRACE method on the web server.",
                        scanner_source="api_scanner",
                    )
                    finding.add_evidence(
                        evidence_type=EvidenceType.HTTP_RESPONSE,
                        title="OPTIONS Response",
                        request_method="OPTIONS",
                        request_url=url,
                        response_status=str(response.status_code),
                        response_headers=dict(response.headers),
                    )
                    findings.append(finding)
                    self.save_finding(finding)

        except Exception:
            pass

    async def _check_error_disclosure(self, client, url, findings):
        """Check for information disclosure in error responses."""
        test_paths = [
            "/api/nonexistent-endpoint-test",
            "/api/%00",
            "/api/../../../etc/passwd",
        ]

        for path in test_paths:
            try:
                test_url = url.rstrip("/") + path
                if settings.safe_mode and not settings.is_target_allowed(test_url):
                    continue

                response = await client.get(test_url)

                if response.status_code >= 400:
                    body = response.text[:2000]

                    # Check for stack traces or debug info
                    indicators = [
                        ("stack trace", "Stack trace exposed in error response"),
                        ("traceback", "Python traceback in error response"),
                        ("at Object.", "Node.js stack trace in error response"),
                        ("SQLSTATE", "SQL error information in response"),
                        ("MongoError", "MongoDB error in response"),
                        ("TypeError:", "Unhandled TypeError in response"),
                        ("SyntaxError:", "Unhandled SyntaxError in response"),
                    ]

                    for indicator, title in indicators:
                        if indicator.lower() in body.lower():
                            finding = BaseFinding(
                                title=f"Information Disclosure: {title}",
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                category="information_disclosure",
                                cwe_id="CWE-209",
                                cwe_name="Generation of Error Message Containing Sensitive Information",
                                affected_component=test_url,
                                affected_endpoint=path,
                                description="Error response contains detailed technical information that could assist an attacker.",
                                technical_details=f"URL: {test_url}\nStatus: {response.status_code}\nIndicator: {indicator}",
                                impact="Technical details in error responses help attackers understand the application's internals.",
                                remediation="Implement custom error pages. Never expose stack traces, debug information, or internal paths in production.",
                                scanner_source="api_scanner",
                            )
                            finding.add_evidence(
                                evidence_type=EvidenceType.HTTP_RESPONSE,
                                title=f"Error Response from {path}",
                                content=body[:500],
                                request_method="GET",
                                request_url=test_url,
                                response_status=str(response.status_code),
                                response_body=body[:500],
                            )
                            findings.append(finding)
                            self.save_finding(finding)
                            break

            except Exception:
                continue

    async def _check_info_headers(self, client, url, findings):
        """Check for information disclosure in response headers."""
        try:
            response = await client.get(url)
            headers = dict(response.headers)

            info_headers = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
            for header in info_headers:
                if header in {k.lower() for k in headers.keys()}:
                    value = headers.get(header, "") or next(
                        (v for k, v in headers.items() if k.lower() == header), ""
                    )
                    finding = BaseFinding(
                        title=f"Technology Disclosure: {header}",
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.CONFIRMED,
                        category="information_disclosure",
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information",
                        affected_component=url,
                        description=f"Response header '{header}' discloses technology information: {value}",
                        impact="Technology stack disclosure helps attackers target known vulnerabilities.",
                        remediation=f"Remove or suppress the {header} header.",
                        scanner_source="api_scanner",
                    )
                    finding.add_evidence(
                        evidence_type=EvidenceType.HTTP_RESPONSE,
                        title=f"Header: {header}",
                        content=f"{header}: {value}",
                        request_method="GET",
                        request_url=url,
                        response_status=str(response.status_code),
                        response_headers=headers,
                    )
                    findings.append(finding)
                    self.save_finding(finding)

        except Exception:
            pass

    async def _check_https(self, client, url, findings):
        """Check HTTPS enforcement."""
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            try:
                response = await client.get(http_url, follow_redirects=False)
                if response.status_code not in [301, 302, 307, 308]:
                    finding = BaseFinding(
                        title="HTTP to HTTPS Redirect Not Enforced",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category="transport_security",
                        cwe_id="CWE-319",
                        cwe_name="Cleartext Transmission of Sensitive Information",
                        affected_component=url,
                        description="HTTP requests are not automatically redirected to HTTPS.",
                        impact="Users accessing the site over HTTP transmit data in cleartext.",
                        remediation="Configure the server to redirect all HTTP traffic to HTTPS with a 301 redirect.",
                        scanner_source="api_scanner",
                    )
                    finding.add_evidence(
                        evidence_type=EvidenceType.HTTP_RESPONSE,
                        title="HTTP Response (no redirect)",
                        request_method="GET",
                        request_url=http_url,
                        response_status=str(response.status_code),
                        response_headers=dict(response.headers),
                    )
                    findings.append(finding)
                    self.save_finding(finding)

            except Exception:
                pass  # HTTP port not open - acceptable
