import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Project } from '../types';

const Projects: React.FC = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchProjects = async () => {
      try {
        const data = await api.getProjects();
        setProjects(data);
      } catch (error) {
        console.error("Failed to fetch projects", error);
      } finally {
        setLoading(false);
      }
    };
    fetchProjects();
  }, []);

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">Target Projects</h1>
          <p className="text-gray-400">Manage security assessment scopes and targets.</p>
        </div>
        <button className="btn-primary">
          <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Project
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center p-12"><div className="w-8 h-8 border-4 border-cyber-500 border-t-transparent rounded-full animate-spin"></div></div>
      ) : projects.length === 0 ? (
        <div className="glass-panel p-12 text-center">
          <svg className="w-12 h-12 text-gray-500 mx-auto mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
          </svg>
          <h3 className="text-lg font-medium text-white mb-2">No projects found</h3>
          <p className="text-gray-400 mb-6">Create a new project to start scanning a target application.</p>
          <button className="btn-primary">Create Project</button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <div key={project.id} className="glass-panel-hover flex flex-col h-full cyber-border">
              <div className="p-6 flex-1">
                <div className="flex justify-between items-start mb-4">
                  <h3 className="text-xl font-bold text-white">{project.name}</h3>
                  <span className={`badge ${project.status === 'in_progress' ? 'bg-accent-blue/20 text-accent-blue' : 'bg-surface-600 text-gray-300'}`}>
                    {project.status.replace('_', ' ').toUpperCase()}
                  </span>
                </div>
                <p className="text-gray-400 text-sm mb-4 line-clamp-2">{project.description || 'No description provided.'}</p>
                
                <div className="space-y-2 mb-6">
                  <div className="flex items-center text-sm">
                    <svg className="w-4 h-4 text-gray-500 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                    </svg>
                    <a href={project.target_url} target="_blank" rel="noopener noreferrer" className="text-cyber-400 hover:underline truncate">{project.target_url}</a>
                  </div>
                  {project.source_repo && (
                    <div className="flex items-center text-sm">
                      <svg className="w-4 h-4 text-gray-500 mr-2" fill="currentColor" viewBox="0 0 24 24">
                        <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                      </svg>
                      <a href={project.source_repo} target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white truncate">{project.source_repo}</a>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-4 border-t border-surface-600 pt-4 mt-auto">
                  <div>
                    <span className="block text-xs text-gray-500 uppercase tracking-wider mb-1">Scans</span>
                    <span className="text-xl font-semibold text-white">{project.scan_count}</span>
                  </div>
                  <div>
                    <span className="block text-xs text-gray-500 uppercase tracking-wider mb-1">Findings</span>
                    <span className="text-xl font-semibold text-accent-orange">{project.finding_count}</span>
                  </div>
                </div>
              </div>
              <div className="bg-surface-800 px-6 py-4 flex justify-between items-center border-t border-surface-600">
                <span className="text-xs text-gray-500">Updated {new Date(project.updated_at).toLocaleDateString()}</span>
                <button className="text-sm text-cyber-400 hover:text-cyber-300 font-medium">View Details →</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Projects;
