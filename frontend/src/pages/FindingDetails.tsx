import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Finding } from '../types';

const FindingDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFinding = async () => {
      if (!id) return;
      try {
        const data = await api.getFinding(id);
        setFinding(data);
      } catch (error) {
        console.error("Failed to fetch finding", error);
      } finally {
        setLoading(false);
      }
    };
    fetchFinding();
  }, [id]);

  if (loading) {
    return <div className="flex justify-center p-12"><div className="w-8 h-8 border-4 border-cyber-500 border-t-transparent rounded-full animate-spin"></div></div>;
  }

  if (!finding) {
    return <div className="text-center p-12 text-gray-400">Finding not found.</div>;
  }

  return (
    <div className="space-y-6 animate-fade-in pb-12">
      <div className="flex items-center text-sm text-gray-400 mb-4">
        <button onClick={() => navigate('/findings')} className="hover:text-cyber-400 mr-2 flex items-center">
          <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to Findings
        </button>
        <span>/</span>
        <span className="ml-2 text-gray-500 font-mono">{finding.finding_id}</span>
      </div>

      <div className="flex justify-between items-start">
        <h1 className="text-3xl font-bold text-white max-w-3xl leading-tight">{finding.title}</h1>
        <div className="flex space-x-3">
          <select 
            className="input-field w-auto py-1.5 text-sm bg-surface-700"
            defaultValue={finding.status}
          >
            <option value="open">Open</option>
            <option value="confirmed">Confirmed</option>
            <option value="false_positive">False Positive</option>
            <option value="remediated">Remediated</option>
            <option value="accepted">Risk Accepted</option>
          </select>
          <button className="btn-primary py-1.5 px-3 text-sm">Save changes</button>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <span className={`badge badge-${finding.severity} px-3 py-1 text-sm`}>
          {finding.severity.toUpperCase()}
        </span>
        <span className="badge bg-surface-700 text-gray-200 border-surface-600 px-3 py-1 text-sm">
          {finding.confidence.toUpperCase()} CONFIDENCE
        </span>
        {finding.cvss_score && (
          <span className="badge bg-surface-700 text-cyber-300 border-surface-600 px-3 py-1 font-mono text-sm">
            CVSS: {finding.cvss_score}
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-8">
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-lg font-semibold border-b border-surface-600 pb-2 mb-4 text-cyber-100">Description</h3>
            <p className="text-gray-300 whitespace-pre-wrap">{finding.description}</p>
          </div>

          {(finding.technical_details || finding.code_snippet) && (
            <div className="glass-panel p-6">
              <h3 className="text-lg font-semibold border-b border-surface-600 pb-2 mb-4 text-cyber-100">Technical Details</h3>
              {finding.technical_details && (
                <div className="mb-4">
                  <pre className="code-block font-mono text-sm whitespace-pre-wrap">{finding.technical_details}</pre>
                </div>
              )}
              {finding.code_snippet && (
                <div>
                  <h4 className="text-sm font-medium text-gray-400 mb-2">Code Evidence:</h4>
                  <pre className="code-block language-javascript">
                    <code>{finding.code_snippet}</code>
                  </pre>
                </div>
              )}
            </div>
          )}

          {(finding.impact || finding.remediation) && (
            <div className="glass-panel p-6">
              <h3 className="text-lg font-semibold border-b border-surface-600 pb-2 mb-4 text-cyber-100">Impact & Remediation</h3>
              {finding.impact && (
                <div className="mb-6">
                  <h4 className="text-sm font-bold text-accent-red mb-2 uppercase tracking-wide">Business Impact</h4>
                  <p className="text-gray-300 bg-accent-red/5 p-4 rounded-lg border border-accent-red/20">{finding.impact}</p>
                </div>
              )}
              {finding.remediation && (
                <div>
                  <h4 className="text-sm font-bold text-accent-green mb-2 uppercase tracking-wide">Remediation Guidance</h4>
                  <p className="text-gray-300 bg-accent-green/5 p-4 rounded-lg border border-accent-green/20 whitespace-pre-wrap">{finding.remediation}</p>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="glass-panel p-6">
            <h3 className="text-lg font-semibold border-b border-surface-600 pb-2 mb-4">Metadata</h3>
            <dl className="space-y-3 text-sm">
              <div>
                <dt className="text-gray-500 font-medium">Affected Component</dt>
                <dd className="font-mono mt-1 text-gray-300 bg-surface-900 p-2 rounded border border-surface-700 break-all">{finding.affected_component || '-'}</dd>
              </div>
              {finding.cwe_id && (
                <div>
                  <dt className="text-gray-500 font-medium">CWE</dt>
                  <dd className="mt-1 text-gray-300"><a href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`} target="_blank" rel="noreferrer" className="text-cyber-400 hover:underline">{finding.cwe_id}</a> - {finding.cwe_name}</dd>
                </div>
              )}
              {finding.cvss_vector && (
                <div>
                  <dt className="text-gray-500 font-medium">CVSS Vector</dt>
                  <dd className="mt-1 font-mono text-xs text-gray-400 bg-surface-900 p-2 rounded">{finding.cvss_vector}</dd>
                </div>
              )}
              <div>
                <dt className="text-gray-500 font-medium">Discovered By</dt>
                <dd className="mt-1 text-gray-300 capitalize">{finding.scanner_source?.replace('_', ' ') || '-'}</dd>
              </div>
              <div>
                <dt className="text-gray-500 font-medium">First Seen</dt>
                <dd className="mt-1 text-gray-300">{new Date(finding.created_at).toLocaleString()}</dd>
              </div>
            </dl>
          </div>

          <div className="glass-panel p-6">
            <div className="flex justify-between items-center border-b border-surface-600 pb-2 mb-4">
              <h3 className="text-lg font-semibold">Evidence Hub</h3>
              <span className="bg-surface-700 text-gray-300 px-2 rounded-full text-xs py-0.5">{finding.evidence_count} items</span>
            </div>
            
            {finding.evidence_count > 0 ? (
              <div className="space-y-3">
                <button 
                  onClick={() => navigate(`/evidence?finding_id=${finding.id}`)}
                  className="w-full text-left p-3 rounded-lg border border-surface-600 bg-surface-700/50 hover:bg-surface-700 transition-colors flex items-center justify-between group"
                >
                  <div className="flex items-center">
                    <svg className="w-5 h-5 text-cyber-500 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <span className="text-sm font-medium text-gray-200">View Attached Evidence</span>
                  </div>
                  <svg className="w-4 h-4 text-gray-500 group-hover:text-cyber-400 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </button>
              </div>
            ) : (
              <p className="text-sm text-gray-500 italic">No specific evidence attached.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default FindingDetails;
