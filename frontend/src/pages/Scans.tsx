import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Scan } from '../types';

const Scans: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const data = await api.getScans();
        setScans(data);
      } catch (error) {
        console.error("Failed to fetch scans", error);
      } finally {
        setLoading(false);
      }
    };
    
    fetchScans();
    const interval = setInterval(fetchScans, 5000); // Poll for scan progress
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-accent-green/20 text-accent-green border-accent-green/30';
      case 'running': return 'bg-accent-blue/20 text-accent-blue border-accent-blue/30';
      case 'failed': return 'bg-accent-red/20 text-accent-red border-accent-red/30';
      case 'pending': return 'bg-accent-yellow/20 text-accent-yellow border-accent-yellow/30';
      default: return 'bg-surface-600 text-gray-300';
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">Assessment Scans</h1>
          <p className="text-gray-400">Execution history and active vulnerability scans.</p>
        </div>
        <button className="btn-primary">
          <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Run Scan
        </button>
      </div>

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Type</th>
              <th>Status</th>
              <th>Progress</th>
              <th>Findings</th>
              <th>Started</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && scans.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-8">Loading...</td></tr>
            ) : scans.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-8 text-gray-500">No scans found</td></tr>
            ) : (
              scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="font-mono text-xs">{scan.id.substring(0, 8)}</td>
                  <td>
                    <span className="capitalize">{scan.scan_type.replace('_', ' ')}</span>
                  </td>
                  <td>
                    <span className={`badge border ${getStatusColor(scan.status)}`}>
                      {scan.status.toUpperCase()}
                      {scan.status === 'running' && (
                        <span className="ml-2 w-1.5 h-1.5 rounded-full bg-accent-blue animate-ping"></span>
                      )}
                    </span>
                  </td>
                  <td className="w-48">
                    <div className="flex items-center">
                      <div className="w-full bg-surface-700 rounded-full h-2.5 mr-2 overflow-hidden border border-surface-600">
                        <div 
                          className="bg-cyber-500 h-2.5 rounded-full relative" 
                          style={{ width: `${scan.progress}%` }}
                        >
                          {scan.status === 'running' && <div className="scanner-line"></div>}
                        </div>
                      </div>
                      <span className="text-xs text-gray-400 w-8">{scan.progress}%</span>
                    </div>
                  </td>
                  <td>
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-white">{scan.total_findings}</span>
                      {scan.critical_count > 0 && <span className="w-2 h-2 rounded-full bg-accent-red" title={`${scan.critical_count} critical`}></span>}
                      {scan.high_count > 0 && <span className="w-2 h-2 rounded-full bg-accent-orange" title={`${scan.high_count} high`}></span>}
                    </div>
                  </td>
                  <td className="text-xs text-gray-400">
                    {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}
                  </td>
                  <td>
                    <button className="text-cyber-400 hover:text-cyber-300 text-sm">View Log</button>
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

export default Scans;
