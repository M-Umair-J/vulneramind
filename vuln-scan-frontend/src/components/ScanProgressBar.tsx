import React from 'react';

interface ProgressBarProps {
  currentStep: string;
  isLoading: boolean;
}

export default function ScanProgressBar({ currentStep, isLoading }: ProgressBarProps) {
  const steps = [
    { id: 'input', label: 'Target', icon: '🎯' },
    { id: 'discover', label: 'Discovery', icon: '🔍' },
    { id: 'scan', label: 'Scanning', icon: '📡' },
    { id: 'exploits', label: 'Exploits', icon: '💥' },
    { id: 'ai', label: 'AI Analysis', icon: '🤖' },
    { id: 'metasploit', label: 'Metasploit', icon: '🔥' },
    { id: 'report', label: 'Report', icon: '📋' }
  ];

  const currentIndex = steps.findIndex(step => step.id === currentStep);

  return (
    <div className="bg-black/40 backdrop-blur-md border border-purple-500/30 rounded-xl p-6 mb-6">
      <h3 className="text-lg font-bold text-white mb-4 flex items-center">
        ⚡ <span className="ml-2">Assessment Progress</span>
        {isLoading && (
          <div className="ml-auto flex items-center space-x-2">
            <div className="w-4 h-4 bg-blue-500 rounded-full animate-bounce"></div>
            <div className="w-4 h-4 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
            <div className="w-4 h-4 bg-pink-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
          </div>
        )}
      </h3>
      
      <div className="flex items-center justify-between">
        {steps.map((step, index) => (
          <React.Fragment key={step.id}>
            <div className={`flex flex-col items-center ${
              index <= currentIndex ? 'text-purple-400' : 'text-gray-500'
            }`}>
              <div className={`w-12 h-12 rounded-full flex items-center justify-center text-lg font-bold transition-all duration-300 ${
                index < currentIndex 
                  ? 'bg-green-500 text-white shadow-lg shadow-green-500/50' 
                  : index === currentIndex 
                  ? `bg-purple-500 text-white shadow-lg shadow-purple-500/50 ${isLoading ? 'animate-pulse' : ''}` 
                  : 'bg-gray-700 text-gray-400'
              }`}>
                {index < currentIndex ? '✓' : step.icon}
              </div>
              <span className="text-xs mt-2 font-medium">{step.label}</span>
            </div>
            
            {index < steps.length - 1 && (
              <div className={`flex-1 h-1 mx-2 rounded transition-all duration-300 ${
                index < currentIndex 
                  ? 'bg-gradient-to-r from-green-500 to-purple-500' 
                  : 'bg-gray-700'
              }`} />
            )}
          </React.Fragment>
        ))}
      </div>
      
      <div className="mt-4">
        <div className="bg-gray-700 rounded-full h-2 overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-purple-500 to-blue-500 transition-all duration-500 ease-out"
            style={{ width: `${((currentIndex + 1) / steps.length) * 100}%` }}
          />
        </div>
        <div className="flex justify-between text-xs text-gray-400 mt-1">
          <span>Progress: {Math.round(((currentIndex + 1) / steps.length) * 100)}%</span>
          <span>{currentIndex + 1} of {steps.length} steps</span>
        </div>
      </div>
    </div>
  );
}
