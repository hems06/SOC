import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import Projects from './pages/Projects';
import Scans from './pages/Scans';
import Findings from './pages/Findings';
import FindingDetails from './pages/FindingDetails';
import Evidence from './pages/Evidence';
import Reports from './pages/Reports';

const App: React.FC = () => {
  return (
    <Router>
      <div className="app-container">
        {/* Background decorative elements */}
        <div className="fixed inset-0 bg-grid-pattern pointer-events-none opacity-20" />
        <div className="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] bg-cyber-900/40 rounded-full blur-[120px] pointer-events-none" />
        <div className="fixed bottom-[-20%] right-[-10%] w-[40%] h-[40%] bg-accent-purple/10 rounded-full blur-[100px] pointer-events-none" />

        {/* Sidebar Navigation */}
        <Sidebar />

        {/* Main Content Area */}
        <div className="main-content">
          <Header />
          
          <main className="page-content">
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/projects" element={<Projects />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:id" element={<FindingDetails />} />
              <Route path="/evidence" element={<Evidence />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="*" element={
                <div className="flex flex-col items-center justify-center h-full">
                  <h1 className="text-6xl font-bold text-surface-600 mb-4">404</h1>
                  <p className="text-xl text-gray-400">Page not found</p>
                </div>
              } />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
};

export default App;
