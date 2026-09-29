const API_BASE_URL = '/api';

export const api = {
  // Config
  getConfig: async () => {
    const res = await fetch(`${API_BASE_URL}/config`);
    return res.json();
  },

  // Projects
  getProjects: async () => {
    const res = await fetch(`${API_BASE_URL}/projects`);
    return res.json();
  },
  
  // Dashboard
  getDashboardStats: async (projectId?: string) => {
    const url = projectId 
      ? `${API_BASE_URL}/findings/dashboard?project_id=${projectId}`
      : `${API_BASE_URL}/findings/dashboard`;
    const res = await fetch(url);
    return res.json();
  },

  // Scans
  getScans: async () => {
    const res = await fetch(`${API_BASE_URL}/scans`);
    return res.json();
  },
  
  createScan: async (projectId: string, scanType: string = 'full') => {
    const res = await fetch(`${API_BASE_URL}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId, scan_type: scanType }),
    });
    return res.json();
  },

  // Findings
  getFindings: async () => {
    const res = await fetch(`${API_BASE_URL}/findings`);
    return res.json();
  },
  
  getFinding: async (id: string) => {
    const res = await fetch(`${API_BASE_URL}/findings/${id}`);
    return res.json();
  },

  // Reports
  generateReport: async (projectId: string, format: string = 'html') => {
    const res = await fetch(`${API_BASE_URL}/reports/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId, format }),
    });
    if (format === 'html') {
      return res.text();
    }
    return res.text();
  }
};
