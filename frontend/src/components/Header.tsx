import React from 'react';

const Header: React.FC = () => {
  return (
    <header className="h-16 flex items-center justify-between px-6 border-b border-surface-600 bg-surface-900/80 backdrop-blur-md z-20">
      <div className="flex items-center">
        <h2 className="text-lg font-semibold text-gray-200 hidden md:block">World Monitor Assessment</h2>
      </div>
      
      <div className="flex items-center space-x-4">
        <div className="hidden md:flex items-center space-x-2 mr-4 border-r border-surface-600 pr-4">
          <span className="w-2 h-2 rounded-full bg-accent-green animate-pulse"></span>
          <span className="text-xs text-gray-400">Safe Mode: Active</span>
        </div>
        
        <div className="flex items-center">
          <div className="w-8 h-8 rounded-full bg-surface-700 border border-surface-600 flex items-center justify-center text-sm font-medium text-cyber-300">
            A
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
