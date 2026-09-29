export interface Project {
  id: string;
  name: string;
  description: string | null;
  target_url: string;
  source_repo: string | null;
  local_source_path: string | null;
  scope: string | null;
  authorization_notes: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  scan_count: number;
  finding_count: number;
}

export interface Scan {
  id: string;
  project_id: string;
  scan_type: string;
  status: string;
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  finding_id: string;
  project_id: string;
  scan_id: string | null;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  confidence: 'confirmed' | 'potential' | 'informational';
  status: 'open' | 'confirmed' | 'false_positive' | 'remediated' | 'accepted';
  category: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_details: any | null;
  cwe_id: string | null;
  cwe_name: string | null;
  affected_component: string | null;
  affected_file: string | null;
  affected_line: string | null;
  affected_endpoint: string | null;
  description: string | null;
  technical_details: string | null;
  code_snippet: string | null;
  rule_id: string | null;
  steps_to_reproduce: string | null;
  poc: string | null;
  impact: string | null;
  root_cause: string | null;
  remediation: string | null;
  retest_procedure: string | null;
  scanner_source: string | null;
  is_ai_assisted: string | null;
  evidence_count: number;
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  confirmed: number;
  potential: number;
  source_findings: number;
  runtime_findings: number;
  evidence_count: number;
  categories: Record<string, number>;
  components: Record<string, number>;
}
