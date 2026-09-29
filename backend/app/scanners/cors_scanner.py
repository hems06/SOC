"""
CORS Scanner - Checks Cross-Origin Resource Sharing configuration
"""
from typing import List
import httpx
from app.scanners.base import BaseScanner, BaseFinding
from app.models.finding import Severity, Confidence
from app.models.evidence import EvidenceType
from app.config import settings


class CorsScanner(BaseScanner):
    """Scans CORS configuration for security issues."""

    async def scan(self) -> List[BaseFinding]:
        findings = []
        target_url = self.project.target_url

        if not target_url:
            return findings

        if settings.safe_mode and not settings.is_target_allowed(target_url):
            return findings

        self.update_progress(10)

        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]

        try:
            async with httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,
            ) as client:
                # Test 1: Check wildcard CORS
                self.update_progress(20)
                response = await client.get(target_url)
                acao = response.headers.get("access-control-allow-origin", "")

                if acao == "*":
                    credentials = response.headers.get("access-control-allow-credentials", "")
                    if credentials.lower() == "true":
                        severity = Severity.HIGH
                        desc = "Wildcard CORS origin with credentials allowed. Any website can make authenticated cross-origin requests."
                    else:
                        severity = Severity.LOW
                        desc = "Wildcard CORS origin configured. Any website can read responses, but credentials are not included."

                    finding = BaseFinding(
                        title="Wildcard CORS Origin Configured",
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        category="cors",
                        cwe_id="CWE-942",
                        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
                        affected_component=target_url,
                        affected_endpoint=target_url,
                        description=desc,
                        technical_details=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {credentials}",
                        impact="Cross-origin data theft possible from any website.",
                        remediation="Restrict Access-Control-Allow-Origin to specific trusted domains.",
                        scanner_source="cors_scanner",
                        retest_procedure="Send a request with an arbitrary Origin header and check if the response includes matching ACAO header.",
                    )
                    finding.add_evidence(
                        evidence_type=EvidenceType.HTTP_RESPONSE,
                        title="Wildcard CORS Response",
                        content=f"Access-Control-Allow-Origin: {acao}",
                        request_method="GET",
                        request_url=target_url,
                        response_status=str(response.status_code),
                        response_headers=dict(response.headers),
                    )
                    findings.append(finding)
                    self.save_finding(finding)

                # Test 2: Check origin reflection
                self.update_progress(40)
                for test_origin in test_origins:
                    try:
                        response = await client.get(
                            target_url,
                            headers={"Origin": test_origin}
                        )
                        acao = response.headers.get("access-control-allow-origin", "")

                        if acao == test_origin:
                            credentials = response.headers.get("access-control-allow-credentials", "")

                            if credentials.lower() == "true":
                                severity = Severity.HIGH
                            else:
                                severity = Severity.MEDIUM

                            finding = BaseFinding(
                                title=f"CORS Origin Reflection: {test_origin}",
                                severity=severity,
                                confidence=Confidence.CONFIRMED,
                                category="cors",
                                cwe_id="CWE-942",
                                cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
                                affected_component=target_url,
                                affected_endpoint=target_url,
                                description=f"The server reflects the Origin header value '{test_origin}' in Access-Control-Allow-Origin without validation.",
                                technical_details=f"Request Origin: {test_origin}\nResponse ACAO: {acao}\nCredentials: {credentials}",
                                impact="An attacker-controlled website can make cross-origin requests that the application trusts.",
                                remediation="Validate the Origin header against a strict allowlist of trusted domains.",
                                scanner_source="cors_scanner",
                            )
                            finding.add_evidence(
                                evidence_type=EvidenceType.HTTP_REQUEST,
                                title=f"CORS Test with Origin: {test_origin}",
                                content=f"Origin: {test_origin}",
                                request_method="GET",
                                request_url=target_url,
                                request_headers={"Origin": test_origin},
                                response_status=str(response.status_code),
                                response_headers=dict(response.headers),
                            )
                            findings.append(finding)
                            self.save_finding(finding)
                            break  # One reflection finding is enough

                    except Exception:
                        continue

                # Test 3: Preflight check
                self.update_progress(70)
                try:
                    preflight_response = await client.options(
                        target_url,
                        headers={
                            "Origin": "https://test.example.com",
                            "Access-Control-Request-Method": "POST",
                            "Access-Control-Request-Headers": "Content-Type, Authorization",
                        }
                    )
                    preflight_acao = preflight_response.headers.get("access-control-allow-origin", "")
                    allowed_methods = preflight_response.headers.get("access-control-allow-methods", "")
                    allowed_headers = preflight_response.headers.get("access-control-allow-headers", "")

                    if preflight_acao and (preflight_acao == "*" or preflight_acao == "https://test.example.com"):
                        finding = BaseFinding(
                            title="Permissive CORS Preflight Response",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            category="cors",
                            cwe_id="CWE-942",
                            cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
                            affected_component=target_url,
                            description=f"Preflight response allows cross-origin requests.\nAllowed Methods: {allowed_methods}\nAllowed Headers: {allowed_headers}",
                            technical_details=f"ACAO: {preflight_acao}\nMethods: {allowed_methods}\nHeaders: {allowed_headers}",
                            impact="Cross-origin requests with non-simple methods/headers are permitted.",
                            remediation="Restrict preflight responses to trusted origins and necessary methods/headers.",
                            scanner_source="cors_scanner",
                        )
                        finding.add_evidence(
                            evidence_type=EvidenceType.HTTP_RESPONSE,
                            title="CORS Preflight Response",
                            request_method="OPTIONS",
                            request_url=target_url,
                            response_status=str(preflight_response.status_code),
                            response_headers=dict(preflight_response.headers),
                        )
                        findings.append(finding)
                        self.save_finding(finding)

                except Exception:
                    pass

        except httpx.ConnectError:
            pass
        except Exception:
            pass

        self.update_progress(100)
        return findings
