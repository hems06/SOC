"""
Source Code Scanner - Analyzes source code for security issues
"""
import os
import re
from pathlib import Path
from typing import List
from app.scanners.base import BaseScanner, BaseFinding
from app.models.finding import Severity, Confidence
from app.models.evidence import EvidenceType


# Security rules for source code analysis
SOURCE_CODE_RULES = [
    # --- Authentication Issues ---
    {
        "id": "AUTH-001",
        "title": "Hardcoded credentials detected",
        "pattern": r"""(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token)\s*[=:]\s*['\"][^'\"]{4,}['\"]""",
        "severity": Severity.HIGH,
        "confidence": Confidence.POTENTIAL,
        "category": "authentication",
        "cwe_id": "CWE-798",
        "cwe_name": "Use of Hard-coded Credentials",
        "description": "Hardcoded credentials found in source code. This can lead to unauthorized access if the code is exposed.",
        "impact": "Unauthorized access to the application or external services using exposed credentials.",
        "remediation": "Move credentials to environment variables or a secrets management solution. Never commit credentials to source control.",
        "file_types": [".js", ".jsx", ".ts", ".tsx", ".py", ".env", ".json", ".yml", ".yaml"],
    },
    {
        "id": "AUTH-002",
        "title": "Insecure token storage in localStorage",
        "pattern": r"""localStorage\.setItem\s*\(\s*['\"](?:token|auth|jwt|session|access_token|refresh_token)['\"]""",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.POTENTIAL,
        "category": "authentication",
        "cwe_id": "CWE-922",
        "cwe_name": "Insecure Storage of Sensitive Information",
        "description": "Authentication tokens stored in localStorage are accessible to any JavaScript running on the page, making them vulnerable to XSS attacks.",
        "impact": "Token theft via XSS could lead to session hijacking.",
        "remediation": "Use httpOnly cookies for session tokens. If localStorage must be used, implement additional protections against XSS.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "AUTH-003",
        "title": "Missing authentication check on API route",
        "pattern": r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"][^'\"]+['\"](?:(?!auth|protect|middleware|guard|verify|token|session).)*\)""",
        "severity": Severity.INFORMATIONAL,
        "confidence": Confidence.POTENTIAL,
        "category": "authentication",
        "cwe_id": "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "description": "API route definition that may lack authentication middleware. Manual verification required.",
        "impact": "Unauthenticated access to sensitive functionality if authentication is indeed missing.",
        "remediation": "Ensure all sensitive API endpoints require authentication middleware.",
        "file_types": [".js", ".ts"],
    },
    # --- XSS / Injection ---
    {
        "id": "XSS-001",
        "title": "Use of dangerouslySetInnerHTML",
        "pattern": r"""dangerouslySetInnerHTML""",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.POTENTIAL,
        "category": "input_validation",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "description": "React's dangerouslySetInnerHTML bypasses DOM sanitization, potentially allowing XSS if user-controlled input is rendered.",
        "impact": "Cross-site scripting if the HTML content includes user-controlled data.",
        "remediation": "Sanitize all HTML content before rendering with dangerouslySetInnerHTML. Consider using DOMPurify or a safer rendering approach.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "XSS-002",
        "title": "Direct innerHTML assignment",
        "pattern": r"""\.innerHTML\s*=(?!=)""",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.POTENTIAL,
        "category": "input_validation",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "description": "Direct innerHTML assignment can lead to DOM-based XSS if user input is injected without sanitization.",
        "impact": "Cross-site scripting through DOM manipulation.",
        "remediation": "Use textContent instead of innerHTML when rendering text. Sanitize HTML content with DOMPurify before using innerHTML.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "XSS-003",
        "title": "Use of eval() or Function constructor",
        "pattern": r"""(?:eval|Function)\s*\(""",
        "severity": Severity.HIGH,
        "confidence": Confidence.POTENTIAL,
        "category": "input_validation",
        "cwe_id": "CWE-95",
        "cwe_name": "Improper Neutralization of Directives in Dynamically Evaluated Code",
        "description": "eval() and the Function constructor execute arbitrary code. If user input reaches these functions, it enables code injection.",
        "impact": "Remote code execution or arbitrary JavaScript execution in the browser.",
        "remediation": "Avoid eval() and Function(). Use JSON.parse() for data parsing. Use safer alternatives for dynamic behavior.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    # --- Authorization ---
    {
        "id": "AUTHZ-001",
        "title": "Client-side role/permission check",
        "pattern": r"""(?:role|permission|isAdmin|is_admin|isAuthorized|userRole)\s*(?:===?|!==?)\s*['\"]""",
        "severity": Severity.LOW,
        "confidence": Confidence.POTENTIAL,
        "category": "authorization",
        "cwe_id": "CWE-602",
        "cwe_name": "Client-Side Enforcement of Server-Side Security",
        "description": "Authorization check appears to be performed client-side. Client-side checks can be bypassed.",
        "impact": "Authorization bypass if server-side checks are not also implemented.",
        "remediation": "Always enforce authorization on the server side. Client-side checks should only be used for UI/UX purposes.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "AUTHZ-002",
        "title": "Potential IDOR - User ID from request parameter",
        "pattern": r"""(?:req\.params|req\.query|req\.body|request\.args|request\.form)\s*(?:\[|\.)\s*['\"]?(?:user_?id|userId|account_?id|profile_?id)""",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.POTENTIAL,
        "category": "authorization",
        "cwe_id": "CWE-639",
        "cwe_name": "Authorization Bypass Through User-Controlled Key",
        "description": "User identifier taken directly from request parameters without authorization verification, potentially leading to IDOR.",
        "impact": "Unauthorized access to other users' data by manipulating ID parameters.",
        "remediation": "Validate that the authenticated user is authorized to access the requested resource. Use session-based user identification.",
        "file_types": [".js", ".ts", ".py"],
    },
    # --- CORS ---
    {
        "id": "CORS-001",
        "title": "Wildcard CORS origin",
        "pattern": r"""(?:Access-Control-Allow-Origin|origin)\s*[=:]\s*['\"]?\*['\"]?""",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.POTENTIAL,
        "category": "cors",
        "cwe_id": "CWE-942",
        "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
        "description": "Wildcard (*) CORS origin allows any website to make cross-origin requests to this application.",
        "impact": "Any website can interact with the API, potentially leading to data theft if combined with credentials.",
        "remediation": "Restrict Access-Control-Allow-Origin to specific trusted domains.",
        "file_types": [".js", ".ts", ".py", ".json"],
    },
    {
        "id": "CORS-002",
        "title": "CORS origin reflection",
        "pattern": r"""(?:origin|req\.headers\.origin|request\.headers\.get\(['\"]origin['\"])""",
        "severity": Severity.LOW,
        "confidence": Confidence.POTENTIAL,
        "category": "cors",
        "cwe_id": "CWE-942",
        "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
        "description": "Origin header value may be reflected in CORS response without validation. Requires manual verification.",
        "impact": "If the origin is reflected without validation, any website could make authenticated cross-origin requests.",
        "remediation": "Validate the Origin header against an allowlist of trusted domains.",
        "file_types": [".js", ".ts", ".py"],
    },
    # --- Information Disclosure ---
    {
        "id": "INFO-001",
        "title": "Sensitive data in console.log",
        "pattern": r"""console\.log\s*\(.*(?:password|token|secret|key|credential|auth)""",
        "severity": Severity.LOW,
        "confidence": Confidence.POTENTIAL,
        "category": "information_disclosure",
        "cwe_id": "CWE-532",
        "cwe_name": "Insertion of Sensitive Information into Log File",
        "description": "Sensitive information may be logged to the browser console.",
        "impact": "Sensitive data exposure through browser developer tools.",
        "remediation": "Remove console.log statements containing sensitive data. Use a proper logging framework with appropriate log levels.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "INFO-002",
        "title": "Environment variable exposure",
        "pattern": r"""process\.env\.(?:API_KEY|SECRET|TOKEN|PASSWORD|DATABASE_URL|DB_PASSWORD|PRIVATE_KEY)""",
        "severity": Severity.LOW,
        "confidence": Confidence.POTENTIAL,
        "category": "information_disclosure",
        "cwe_id": "CWE-526",
        "cwe_name": "Exposure of Sensitive Information Through Environmental Variables",
        "description": "Sensitive environment variables referenced in code. If this is client-side code, these values may be bundled into the build.",
        "impact": "Exposure of sensitive configuration values in client-side bundles.",
        "remediation": "Ensure sensitive environment variables are only used server-side. Use NEXT_PUBLIC_ or VITE_ prefixes only for non-sensitive values.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    # --- Insecure Communication ---
    {
        "id": "TRANSPORT-001",
        "title": "Hardcoded HTTP URL (non-HTTPS)",
        "pattern": r"""['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z]""",
        "severity": Severity.LOW,
        "confidence": Confidence.POTENTIAL,
        "category": "transport_security",
        "cwe_id": "CWE-319",
        "cwe_name": "Cleartext Transmission of Sensitive Information",
        "description": "Non-localhost HTTP URL found. Data sent over HTTP is transmitted in cleartext.",
        "impact": "Sensitive data could be intercepted by network attackers.",
        "remediation": "Use HTTPS for all non-local communications.",
        "file_types": [".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".yml", ".yaml"],
    },
    # --- SSRF ---
    {
        "id": "SSRF-001",
        "title": "Potential SSRF - User-controlled URL in server request",
        "pattern": r"""(?:fetch|axios|http\.get|httpx\.get|requests\.get|urllib\.request)\s*\(.*(?:req\.|request\.|params\.|query\.|body\.)""",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.POTENTIAL,
        "category": "ssrf",
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery",
        "description": "Server-side HTTP request appears to use user-controlled input as the URL or part of the URL.",
        "impact": "An attacker could make the server send requests to internal services or external systems.",
        "remediation": "Validate and sanitize user input used in URLs. Implement URL allowlisting. Block requests to internal IP ranges.",
        "file_types": [".js", ".ts", ".py"],
    },
    # --- Unsafe URL Handling ---
    {
        "id": "URL-001",
        "title": "Unsafe URL construction with user input",
        "pattern": r"""(?:window\.location|document\.location|location\.href)\s*=\s*(?!['\"https])""",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.POTENTIAL,
        "category": "input_validation",
        "cwe_id": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site",
        "description": "URL assignment using potentially user-controlled values could lead to open redirect.",
        "impact": "Users could be redirected to malicious websites.",
        "remediation": "Validate redirect URLs against an allowlist. Never use unvalidated user input in URL assignments.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    # --- Unsafe postMessage ---
    {
        "id": "POSTMSG-001",
        "title": "postMessage without origin check",
        "pattern": r"""addEventListener\s*\(\s*['\"]message['\"]""",
        "severity": Severity.LOW,
        "confidence": Confidence.POTENTIAL,
        "category": "client_side",
        "cwe_id": "CWE-346",
        "cwe_name": "Origin Validation Error",
        "description": "Message event listener detected. Verify that the handler checks event.origin before processing the message.",
        "impact": "Malicious websites could send messages to the application if origin is not validated.",
        "remediation": "Always check event.origin against trusted origins before processing postMessage data.",
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
]


class SourceCodeScanner(BaseScanner):
    """Scans source code for security vulnerabilities using deterministic rules."""

    async def scan(self) -> List[BaseFinding]:
        findings = []
        source_path = self.project.local_source_path

        if not source_path or not os.path.exists(source_path):
            return findings

        self.update_progress(5)

        # Collect files to scan
        files_to_scan = self._collect_files(source_path)
        total_files = len(files_to_scan)

        if total_files == 0:
            return findings

        for idx, file_path in enumerate(files_to_scan):
            progress = 5 + int((idx / total_files) * 90)
            self.update_progress(progress)

            try:
                rel_path = os.path.relpath(file_path, source_path)
                ext = os.path.splitext(file_path)[1].lower()

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.split("\n")

                for rule in SOURCE_CODE_RULES:
                    if ext not in rule.get("file_types", []):
                        continue

                    pattern = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)

                    for line_num, line in enumerate(lines, 1):
                        matches = pattern.finditer(line)
                        for match in matches:
                            # Skip comments and test files
                            stripped = line.strip()
                            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                                continue
                            if "test" in rel_path.lower() or "spec" in rel_path.lower() or "mock" in rel_path.lower():
                                continue

                            # Get context lines
                            start = max(0, line_num - 4)
                            end = min(len(lines), line_num + 3)
                            snippet_lines = lines[start:end]
                            snippet = "\n".join(
                                f"{'→ ' if i + start + 1 == line_num else '  '}{i + start + 1}: {l}"
                                for i, l in enumerate(snippet_lines)
                            )

                            finding = BaseFinding(
                                title=f"{rule['title']} in {rel_path}",
                                severity=rule["severity"],
                                confidence=rule["confidence"],
                                category=rule["category"],
                                cwe_id=rule["cwe_id"],
                                cwe_name=rule["cwe_name"],
                                affected_component=rel_path,
                                affected_file=rel_path,
                                affected_line=str(line_num),
                                description=rule["description"],
                                technical_details=f"Rule {rule['id']} matched at {rel_path}:{line_num}\nMatched: {match.group()[:200]}",
                                code_snippet=snippet,
                                rule_id=rule["id"],
                                impact=rule.get("impact", ""),
                                remediation=rule.get("remediation", ""),
                                scanner_source="source_code_scanner",
                                retest_procedure=f"Review the code at {rel_path} line {line_num} and verify if the pattern represents an actual vulnerability.",
                            )

                            finding.add_evidence(
                                evidence_type=EvidenceType.SOURCE_CODE,
                                title=f"Source code: {rel_path}:{line_num}",
                                content=snippet,
                                file_path=rel_path,
                                line_start=str(line_num),
                                code_snippet=snippet,
                            )

                            findings.append(finding)
                            self.save_finding(finding)

            except Exception as e:
                continue

        self.update_progress(100)
        return findings

    def _collect_files(self, source_path: str) -> List[str]:
        """Collect all scannable files from the source directory."""
        scannable_extensions = {
            ".js", ".jsx", ".ts", ".tsx", ".py",
            ".json", ".yml", ".yaml", ".env",
            ".html", ".htm", ".vue", ".svelte",
        }
        skip_dirs = {
            "node_modules", ".git", "__pycache__", "dist", "build",
            ".next", ".nuxt", "coverage", ".venv", "venv",
        }

        files = []
        for root, dirs, filenames in os.walk(source_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext in scannable_extensions:
                    files.append(os.path.join(root, filename))

        return files
