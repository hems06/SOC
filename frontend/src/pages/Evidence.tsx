import React from 'react';

const Evidence: React.FC = () => {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">Evidence Hub</h1>
          <p className="text-gray-400">Raw data, HTTP requests, and source snippets captured during scans.</p>
        </div>
      </div>

      <div className="glass-panel p-12 text-center border-dashed">
        <svg className="w-12 h-12 text-gray-500 mx-auto mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
        </svg>
        <h3 className="text-lg font-medium text-white mb-2">Evidence vault initialized</h3>
        <p className="text-gray-400">Select a finding to view its associated raw evidence data.</p>
      </div>
    </div>
  );
};

export default Evidence;
