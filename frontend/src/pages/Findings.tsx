import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Finding } from '../types';

const Findings: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const data = await api.getFindings();
        setFindings(data);
      } catch (error) {
        console.error("Failed to fetch findings", error);
      } finally {
        setLoading(false);
      }
    };
    fetchFindings();
  }, []);

  const getSeverityBadge = (severity: string) => {
    return <span className={`badge badge-${severity}`}>{severity.toUpperCase()}</span>;
  };

  const getConfidenceBadge = (confidence: string) => {
    switch (confidence) {
      case 'confirmed': return <span className="text-accent-green text-xs font-medium border border-accent-green/30 bg-accent-green/10 px-2 py-0.5 rounded-sm">CONFIRMED</span>;
      case 'potential': return <span className="text-accent-orange text-xs font-medium border border-accent-orange/30 bg-accent-orange/10 px-2 py-0.5 rounded-sm">POTENTIAL</span>;
      default: return <span className="text-gray-400 text-xs font-medium border border-surface-500 bg-surface-600 px-2 py-0.5 rounded-sm">INFO</span>;
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">Vulnerability Findings</h1>
          <p className="text-gray-400">Review, verify, and track security issues.</p>
        </div>
        <div className="flex space-x-2">
          <input 
            type="text" 
            placeholder="Search findings..." 
            className="input-field w-64"
          />
          <button className="btn-secondary">
            <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
            </svg>
            Filter
          </button>
        </div>
      </div>

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Vulnerability</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Component</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="text-center py-8">Loading...</td></tr>
            ) : findings.length === 0 ? (
              <tr><td colSpan={6} className="text-center py-8 text-gray-500">No findings reported yet.</td></tr>
            ) : (
              findings.map((finding) => (
                <tr 
                  key={finding.id} 
                  className="cursor-pointer hover:bg-surface-700/50"
                  onClick={() => navigate(`/findings/${finding.id}`)}
                >
                  <td className="font-mono text-xs text-cyber-400">{finding.finding_id}</td>
                  <td>
                    <div className="font-medium text-white line-clamp-1">{finding.title}</div>
                    {finding.cwe_id && <div className="text-xs text-gray-500">{finding.cwe_id}</div>}
                  </td>
                  <td>{getSeverityBadge(finding.severity)}</td>
                  <td>{getConfidenceBadge(finding.confidence)}</td>
                  <td className="font-mono text-xs truncate max-w-[200px]">
                    {finding.affected_component || '-'}
                  </td>
                  <td>
                    <span className="text-sm text-gray-300 capitalize">{finding.status.replace('_', ' ')}</span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Findings;
