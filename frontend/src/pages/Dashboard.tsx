import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { DashboardStats } from '../types';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, Legend } from 'recharts';

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await api.getDashboardStats();
        setStats(data);
      } catch (error) {
        console.error("Failed to fetch dashboard stats", error);
      } finally {
        setLoading(false);
      }
    };
    
    fetchStats();
    const interval = setInterval(fetchStats, 10000); // Auto refresh
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return <div className="flex items-center justify-center h-full"><div className="w-10 h-10 border-4 border-cyber-500 border-t-transparent rounded-full animate-spin"></div></div>;
  }

  const severityData = [
    { name: 'Critical', value: stats?.critical || 0, color: '#ff4757' },
    { name: 'High', value: stats?.high || 0, color: '#ff6b35' },
    { name: 'Medium', value: stats?.medium || 0, color: '#ffa502' },
    { name: 'Low', value: stats?.low || 0, color: '#3498db' },
    { name: 'Info', value: stats?.informational || 0, color: '#95a5a6' },
  ].filter(d => d.value > 0);

  const confidenceData = [
    { name: 'Confirmed', value: stats?.confirmed || 0, color: '#10b981' },
    { name: 'Potential', value: stats?.potential || 0, color: '#f59e0b' },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold">Security Posture Dashboard</h1>
        <p className="text-gray-400">Overview of identified vulnerabilities and assessment progress.</p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="glass-panel p-6">
          <div className="flex items-center justify-between">
            <h3 className="text-gray-400 text-sm font-medium uppercase tracking-wider">Total Findings</h3>
            <span className="p-2 bg-surface-700 rounded-lg text-cyber-400">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </span>
          </div>
          <div className="mt-4 flex items-baseline">
            <p className="text-4xl font-bold text-white">{stats?.total_findings || 0}</p>
          </div>
        </div>

        <div className="glass-panel p-6 border-t-4 border-accent-red">
          <div className="flex items-center justify-between">
            <h3 className="text-gray-400 text-sm font-medium uppercase tracking-wider">Critical Risk</h3>
            <span className="p-2 bg-surface-700 rounded-lg text-accent-red">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </span>
          </div>
          <div className="mt-4 flex items-baseline">
            <p className="text-4xl font-bold text-white">{stats?.critical || 0}</p>
          </div>
        </div>

        <div className="glass-panel p-6 border-t-4 border-accent-orange">
          <div className="flex items-center justify-between">
            <h3 className="text-gray-400 text-sm font-medium uppercase tracking-wider">High Risk</h3>
            <span className="p-2 bg-surface-700 rounded-lg text-accent-orange">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </span>
          </div>
          <div className="mt-4 flex items-baseline">
            <p className="text-4xl font-bold text-white">{stats?.high || 0}</p>
          </div>
        </div>

        <div className="glass-panel p-6">
          <div className="flex items-center justify-between">
            <h3 className="text-gray-400 text-sm font-medium uppercase tracking-wider">Evidence Captured</h3>
            <span className="p-2 bg-surface-700 rounded-lg text-accent-green">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </span>
          </div>
          <div className="mt-4 flex items-baseline">
            <p className="text-4xl font-bold text-white">{stats?.evidence_count || 0}</p>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel p-6 h-96">
          <h3 className="text-lg font-semibold mb-6">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 5, right: 30, left: 20, bottom: 25 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                <XAxis dataKey="name" stroke="#9ca3af" tick={{fill: '#9ca3af'}} />
                <YAxis stroke="#9ca3af" tick={{fill: '#9ca3af'}} allowDecimals={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', color: '#fff' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">No data available</div>
          )}
        </div>

        <div className="glass-panel p-6 h-96">
          <h3 className="text-lg font-semibold mb-6">Discovery Source</h3>
          <div className="flex h-full pb-10">
            <div className="w-1/2 flex flex-col items-center justify-center border-r border-surface-600">
              <span className="text-5xl font-bold text-cyber-400 mb-2">{stats?.source_findings || 0}</span>
              <span className="text-gray-400">Source Code Analysis</span>
            </div>
            <div className="w-1/2 flex flex-col items-center justify-center">
              <span className="text-5xl font-bold text-accent-purple mb-2">{stats?.runtime_findings || 0}</span>
              <span className="text-gray-400">Runtime/API Testing</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
