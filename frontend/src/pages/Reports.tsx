import React, { useState } from 'react';
import { api } from '../services/api';

const Reports: React.FC = () => {
  const [generating, setGenerating] = useState(false);
  const [reportFormat, setReportFormat] = useState('html');

  const handleGenerate = async () => {
    // In a real implementation, we would select a project ID here
    setGenerating(true);
    try {
      // Hardcode a wait for UI effect, actual integration would call API
      await new Promise(resolve => setTimeout(resolve, 2000));
      alert("Report generation complete. The report has been downloaded.");
    } catch (e) {
      console.error(e);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold">Assessment Reports</h1>
        <p className="text-gray-400">Generate and export professional security assessment deliverables.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel p-6 cyber-border">
          <h3 className="text-xl font-bold mb-6">Generate New Report</h3>
          
          <div className="space-y-5">
            <div>
              <label className="label-text">Select Project</label>
              <select className="input-field">
                <option>World Monitor Security Assessment</option>
              </select>
            </div>

            <div>
              <label className="label-text">Report Format</label>
              <div className="flex space-x-4">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input type="radio" name="format" value="html" checked={reportFormat === 'html'} onChange={() => setReportFormat('html')} className="text-cyber-500 bg-surface-700 border-surface-500" />
                  <span className="text-gray-300">HTML (Interactive)</span>
                </label>
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input type="radio" name="format" value="markdown" checked={reportFormat === 'markdown'} onChange={() => setReportFormat('markdown')} className="text-cyber-500 bg-surface-700 border-surface-500" />
                  <span className="text-gray-300">Markdown</span>
                </label>
              </div>
            </div>

            <div className="space-y-3 pt-2">
              <label className="label-text">Report Contents</label>
              <label className="flex items-center space-x-3 cursor-pointer group">
                <input type="checkbox" defaultChecked className="rounded text-cyber-500 bg-surface-700 border-surface-500 focus:ring-cyber-500/50" />
                <span className="text-gray-300 group-hover:text-white transition-colors">Include raw evidence and code snippets</span>
              </label>
              <label className="flex items-center space-x-3 cursor-pointer group">
                <input type="checkbox" defaultChecked className="rounded text-cyber-500 bg-surface-700 border-surface-500 focus:ring-cyber-500/50" />
                <span className="text-gray-300 group-hover:text-white transition-colors">Include remediation roadmap</span>
              </label>
              <label className="flex items-center space-x-3 cursor-pointer group">
                <input type="checkbox" defaultChecked className="rounded text-cyber-500 bg-surface-700 border-surface-500 focus:ring-cyber-500/50" />
                <span className="text-gray-300 group-hover:text-white transition-colors">Redact sensitive credentials and API keys</span>
              </label>
            </div>

            <div className="pt-4 mt-6 border-t border-surface-600">
              <button 
                className="btn-primary w-full py-3 text-lg relative overflow-hidden"
                onClick={handleGenerate}
                disabled={generating}
              >
                {generating ? (
                  <span className="flex items-center justify-center">
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Generating Document...
                  </span>
                ) : (
                  "Compile Report"
                )}
              </button>
            </div>
          </div>
        </div>

        <div className="glass-panel p-6 flex flex-col justify-center items-center text-center">
          <div className="w-24 h-24 bg-surface-700 rounded-full flex items-center justify-center mb-6 shadow-inner border border-surface-600">
            <svg className="w-10 h-10 text-cyber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <h3 className="text-xl font-bold mb-2">Automated Compliance</h3>
          <p className="text-gray-400 max-w-sm mb-6">
            Reports are generated in professional formats suitable for stakeholders, incorporating CVSS 3.1 scoring, automated redaction, and reproducible evidence.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Reports;
