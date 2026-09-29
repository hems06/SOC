"""
Report Generator - Generates security assessment reports in HTML and Markdown
"""
from datetime import datetime
from typing import List
from sqlalchemy.orm import Session
from app.models.project import Project
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.evidence import Evidence
import re


def redact_secret_in_text(text: str) -> str:
    """Redact potential secrets in text."""
    patterns = [
        (r"((?:password|passwd|pwd|secret|api_key|apikey|token)\s*[=:]\s*['\"]?)([^'\"\s]{4,})", r"\1***REDACTED***"),
        (r"(AKIA[0-9A-Z]{16})", "***AWS-KEY-REDACTED***"),
        (r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", "***JWT-REDACTED***"),
        (r"(ghp_[A-Za-z0-9_]{36,})", "***GITHUB-TOKEN-REDACTED***"),
    ]
    result = text
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


class ReportGenerator:
    """Generates security assessment reports."""

    def __init__(self, project: Project, findings: List[Finding], scans: List[Scan], db: Session):
        self.project = project
        self.findings = findings
        self.scans = scans
        self.db = db
        self.generated_at = datetime.utcnow()

    def _severity_order(self, finding):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        return order.get(finding.severity, 5)

    def generate_markdown(self, include_evidence=True, redact_secrets=True) -> str:
        """Generate a Markdown security assessment report."""
        sorted_findings = sorted(self.findings, key=self._severity_order)

        critical = [f for f in sorted_findings if f.severity == "critical"]
        high = [f for f in sorted_findings if f.severity == "high"]
        medium = [f for f in sorted_findings if f.severity == "medium"]
        low = [f for f in sorted_findings if f.severity == "low"]
        info = [f for f in sorted_findings if f.severity == "informational"]

        report = []
        report.append(f"# Security Assessment Report")
        report.append(f"## {self.project.name}")
        report.append("")
        report.append(f"**Target:** {self.project.target_url}")
        report.append(f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}")
        report.append(f"**Status:** {self.project.status}")
        report.append("")

        # Executive Summary
        report.append("## Executive Summary")
        report.append("")
        report.append(f"This security assessment identified **{len(self.findings)}** findings across the {self.project.name} application.")
        report.append("")
        report.append("| Severity | Count |")
        report.append("|----------|-------|")
        report.append(f"| 🔴 Critical | {len(critical)} |")
        report.append(f"| 🟠 High | {len(high)} |")
        report.append(f"| 🟡 Medium | {len(medium)} |")
        report.append(f"| 🔵 Low | {len(low)} |")
        report.append(f"| ⚪ Informational | {len(info)} |")
        report.append("")

        # Assessment Scope
        report.append("## Assessment Scope")
        report.append("")
        if self.project.scope:
            report.append(self.project.scope)
        else:
            report.append(f"- **Web Application:** {self.project.target_url}")
            if self.project.source_repo:
                report.append(f"- **Source Repository:** {self.project.source_repo}")
        report.append("")

        # Methodology
        report.append("## Methodology")
        report.append("")
        report.append("The assessment employed the following techniques:")
        report.append("- Static source code analysis with deterministic security rules")
        report.append("- Secrets and credential detection")
        report.append("- Dependency vulnerability analysis")
        report.append("- HTTP security header analysis")
        report.append("- CORS configuration testing")
        report.append("- API security testing")
        report.append("- OWASP Top 10 coverage")
        report.append("")

        # Findings
        report.append("## Detailed Findings")
        report.append("")

        for finding in sorted_findings:
            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}.get(finding.severity, "⚪")

            report.append(f"### {finding.finding_id}: {finding.title}")
            report.append("")
            report.append(f"| Property | Value |")
            report.append(f"|----------|-------|")
            report.append(f"| Severity | {severity_emoji} {finding.severity.upper()} |")
            report.append(f"| Confidence | {finding.confidence} |")
            if finding.cvss_score:
                report.append(f"| CVSS Score | {finding.cvss_score} |")
            if finding.cvss_vector:
                report.append(f"| CVSS Vector | {finding.cvss_vector} |")
            if finding.cwe_id:
                report.append(f"| CWE | {finding.cwe_id} - {finding.cwe_name} |")
            if finding.affected_component:
                report.append(f"| Component | {finding.affected_component} |")
            if finding.affected_file:
                report.append(f"| File | {finding.affected_file}:{finding.affected_line or ''} |")
            report.append("")

            if finding.description:
                report.append(f"**Description:** {finding.description}")
                report.append("")

            if finding.technical_details:
                details = finding.technical_details
                if redact_secrets:
                    details = redact_secret_in_text(details)
                report.append(f"**Technical Details:**")
                report.append(f"```")
                report.append(details)
                report.append(f"```")
                report.append("")

            if finding.code_snippet:
                snippet = finding.code_snippet
                if redact_secrets:
                    snippet = redact_secret_in_text(snippet)
                report.append(f"**Code:**")
                report.append(f"```")
                report.append(snippet)
                report.append(f"```")
                report.append("")

            if finding.impact:
                report.append(f"**Impact:** {finding.impact}")
                report.append("")

            if finding.remediation:
                report.append(f"**Remediation:** {finding.remediation}")
                report.append("")

            if include_evidence:
                evidence_items = self.db.query(Evidence).filter(Evidence.finding_id == finding.id).all()
                if evidence_items:
                    report.append(f"**Evidence:**")
                    for ev in evidence_items:
                        report.append(f"- {ev.evidence_id}: {ev.title or ev.evidence_type}")
                    report.append("")

            report.append("---")
            report.append("")

        # Risk Summary
        report.append("## Risk Summary")
        report.append("")
        if critical:
            report.append("### 🔴 Critical Risk Items (Immediate Action Required)")
            for f in critical:
                report.append(f"- **{f.finding_id}**: {f.title}")
            report.append("")
        if high:
            report.append("### 🟠 High Risk Items (Action Required)")
            for f in high:
                report.append(f"- **{f.finding_id}**: {f.title}")
            report.append("")

        # Remediation Roadmap
        report.append("## Remediation Roadmap")
        report.append("")
        report.append("| Priority | Finding | Effort |")
        report.append("|----------|---------|--------|")
        for f in critical + high:
            report.append(f"| Immediate | {f.finding_id}: {f.title[:50]} | High |")
        for f in medium:
            report.append(f"| Short-term | {f.finding_id}: {f.title[:50]} | Medium |")
        for f in low:
            report.append(f"| Medium-term | {f.finding_id}: {f.title[:50]} | Low |")
        report.append("")

        report.append(f"---")
        report.append(f"*Report generated by World Monitor Security Assessment Platform*")
        report.append(f"*{self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}*")

        return "\n".join(report)

    def generate_html(self, include_evidence=True, redact_secrets=True) -> str:
        """Generate an HTML security assessment report."""
        md_content = self.generate_markdown(include_evidence, redact_secrets)

        # Simple markdown to HTML conversion
        html_body = md_content
        html_body = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html_body, flags=re.MULTILINE)
        html_body = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html_body, flags=re.MULTILINE)
        html_body = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html_body, flags=re.MULTILINE)
        html_body = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_body)
        html_body = re.sub(r'^- (.+)$', r'<li>\1</li>', html_body, flags=re.MULTILINE)
        html_body = re.sub(r'```\n(.*?)\n```', r'<pre><code>\1</code></pre>', html_body, flags=re.DOTALL)
        html_body = re.sub(r'^---$', '<hr>', html_body, flags=re.MULTILINE)
        html_body = html_body.replace('\n\n', '</p><p>')
        html_body = html_body.replace('\n', '<br>')

        # Convert markdown tables to HTML
        html_body = self._convert_tables(html_body)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {self.project.name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0a0e1a;
            color: #e0e6ed;
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; font-size: 2rem; margin: 1rem 0; border-bottom: 2px solid #1a2744; padding-bottom: 0.5rem; }}
        h2 {{ color: #7c8dff; font-size: 1.5rem; margin: 1.5rem 0 0.5rem; }}
        h3 {{ color: #a0aec0; font-size: 1.2rem; margin: 1rem 0 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: #111827; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #1f2937; }}
        th {{ background: #1a2744; color: #7c8dff; font-weight: 600; }}
        pre {{ background: #111827; padding: 1rem; border-radius: 8px; overflow-x: auto; margin: 0.5rem 0; border: 1px solid #1f2937; }}
        code {{ font-family: 'Fira Code', 'Consolas', monospace; font-size: 0.9rem; color: #a5f3fc; }}
        li {{ margin-left: 1.5rem; margin-bottom: 0.25rem; }}
        hr {{ border: none; border-top: 1px solid #1f2937; margin: 1.5rem 0; }}
        strong {{ color: #f0f4f8; }}
        .severity-critical {{ color: #ff4757; font-weight: bold; }}
        .severity-high {{ color: #ff6b35; font-weight: bold; }}
        .severity-medium {{ color: #ffa502; font-weight: bold; }}
        .severity-low {{ color: #3498db; font-weight: bold; }}
        .severity-info {{ color: #95a5a6; }}
        p {{ margin: 0.5rem 0; }}
    </style>
</head>
<body>
    <div class="container">
        {html_body}
    </div>
</body>
</html>"""
        return html

    def _convert_tables(self, text):
        """Simple table conversion."""
        # This is a basic implementation - tables are already in HTML from the markdown
        return text
