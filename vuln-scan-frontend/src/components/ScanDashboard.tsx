'use client';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import SimpleTerminal from './SimpleTerminal';

// Import MetasploitTerminal dynamically to avoid SSR issues
const MetasploitTerminal = dynamic(() => import('./MetasploitTerminal'), {
  ssr: false,
  loading: () => <div>Loading Metasploit Terminal...</div>
});

interface ScanDashboardProps {
  data: any[];
}

export default function ScanDashboard({ data }: ScanDashboardProps) {
  const [selectedHostData, setSelectedHostData] = useState<any | null>(null);
  const [exploitResults, setExploitResults] = useState<any | null>(null);
  const [isExploitingInProgress, setIsExploitingInProgress] = useState(false);
  const [executionResults, setExecutionResults] = useState<any | null>(null);
  const [showExecuteButton, setShowExecuteButton] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [metasploitTerminalOpen, setMetasploitTerminalOpen] = useState(false);
  const [selectedExploitCommands, setSelectedExploitCommands] = useState<any>(null);
  const [metasploitDetails, setMetasploitDetails] = useState<any[]>([]);

  const showDetails = (entry: any) => {
    const result = entry.result?.[0] || entry;
    setSelectedHostData(result);
    setExploitResults(null);
    setExecutionResults(null);
    setShowExecuteButton(false);
    // Don't open modal, just show details on main page
  };

  const openModal = () => {
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
  };

  const startExploitFinding = async () => {
    if (!selectedHostData) return;
    
    setIsExploitingInProgress(true);
    setExploitResults(null);
    setMetasploitDetails([]); // Clear previous details
    
    try {
      const response = await fetch('http://localhost:8000/exploit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          host_data: selectedHostData
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to find exploits');
      }
      
      const result = await response.json();
      setExploitResults(result);
      setShowExecuteButton(true);
      
      // Now get the AI-generated Metasploit details
      await getMetasploitDetails();
      
    } catch (error) {
      console.error('Error finding exploits:', error);
      alert('Failed to find exploits. Make sure the backend is running.');
    } finally {
      setIsExploitingInProgress(false);
    }
  };

  const executeExploits = async () => {
    if (!selectedHostData) return;
    
    setIsExploitingInProgress(true);
    setExecutionResults(null);
    
    try {
      const response = await fetch('http://localhost:8000/execute-exploits', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          host: selectedHostData.host,
          services: selectedHostData.services || []
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to execute exploits');
      }
      
      const result = await response.json();
      setExecutionResults(result);
    } catch (error) {
      console.error('Error executing exploits:', error);
      alert('Failed to execute exploits. Make sure the backend is running.');
    } finally {
      setIsExploitingInProgress(false);
    }
  };

  const openTerminal = (exploitCommands?: any) => {
    setSelectedExploitCommands(exploitCommands);
    setTerminalOpen(true);
  };

  const closeTerminal = () => {
    setTerminalOpen(false);
    setSelectedExploitCommands(null);
  };

  const getMetasploitDetails = async () => {
    if (!selectedHostData || !exploitResults) return;
    
    try {
      // Use the exploit results data instead of just the host data
      const requestData = {
        host: selectedHostData.host,
        services: exploitResults.services || [] // This contains the enriched services with exploits
      };
      
      const response = await fetch('http://localhost:8000/metasploit-details', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
      });
      
      if (!response.ok) {
        throw new Error('Failed to get Metasploit details');
      }
      
      const result = await response.json();
      setMetasploitDetails(result.exploits || []);
    } catch (error) {
      console.error('Error getting Metasploit details:', error);
    }
  };

  return (
    <div className="max-w-5xl mx-auto mt-6 bg-white rounded shadow p-4">
      <h2 className="text-xl font-bold mb-4 text-black">🧠 Scan Results</h2>

      {data.map((entry, index) => {
        const result = entry.result?.[0] || entry;
        return (
          <div key={index} className="border-b border-gray-300 py-2 flex justify-between items-center">
            <span className="text-lg text-black font-semibold">{result.host}</span>
            <div className="flex gap-2">
              <button
                className="text-blue-600 hover:underline"
                onClick={() => showDetails(entry)}
              >
                Show Details
              </button>
              {selectedHostData?.host === result.host && (
                <button
                  className="text-green-600 hover:underline"
                  onClick={openModal}
                >
                  View Full Details
                </button>
              )}
            </div>
          </div>
        );
      })}

      {/* 🎯 Main Page Exploit Section */}
      {selectedHostData && (
        <div className="mt-6 p-6 bg-gray-50 rounded-lg border">
          <h3 className="text-xl font-bold mb-4 text-black">
            🔍 Analysis for {selectedHostData.host}
          </h3>

          {/* Services Summary */}
          <div className="mb-6">
            <h4 className="font-semibold text-gray-800 mb-2">🛡️ Services Summary</h4>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
              {selectedHostData.services?.map((srv: any, idx: number) => (
                <div key={idx} className="bg-white border rounded p-3 text-sm">
                  <p className="font-medium text-black">Port {srv.port}: {srv.service}</p>
                  <p className="text-gray-600">{srv.product} {srv.version}</p>
                  <p className="text-blue-600">
                    CVEs: {srv.cves?.length > 0 ? srv.cves.length : 'None'}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-4 mb-6">
            <button
              onClick={startExploitFinding}
              disabled={isExploitingInProgress}
              className={`px-6 py-3 rounded font-semibold text-white ${
                isExploitingInProgress 
                  ? 'bg-gray-400 cursor-not-allowed' 
                  : 'bg-red-600 hover:bg-red-700'
              }`}
            >
              {isExploitingInProgress ? '🔍 Finding Exploits...' : '🎯 Start Finding Exploits'}
            </button>

            {showExecuteButton && (
              <button
                onClick={executeExploits}
                disabled={isExploitingInProgress}
                className={`px-6 py-3 rounded font-semibold text-white ${
                  isExploitingInProgress 
                    ? 'bg-gray-400 cursor-not-allowed' 
                    : 'bg-green-600 hover:bg-green-700'
                }`}
              >
                {isExploitingInProgress ? '🚀 Executing...' : '🚀 Execute Exploits'}
              </button>
            )}

            <button
              onClick={() => openTerminal()}
              className="px-6 py-3 rounded font-semibold text-white bg-purple-600 hover:bg-purple-700"
            >
              🖥️ Open Terminal
            </button>

            <button
              onClick={() => setMetasploitTerminalOpen(true)}
              className="px-6 py-3 rounded font-semibold text-white bg-red-800 hover:bg-red-900"
            >
              ⚡ Metasploit Console
            </button>
          </div>

          {/* Exploit Discovery Results */}
          {exploitResults && (
            <div className="mb-6 p-4 bg-white rounded border">
              <h4 className="font-semibold text-gray-800 mb-3">🎯 Exploit Discovery Results</h4>
              
              {/* Overall Classification Summary */}
              {exploitResults.classification && (
                <div className="mb-4 p-4 bg-gray-50 rounded border">
                  <h5 className="font-medium text-gray-800 mb-2">📊 Overall Summary</h5>
                  <div className="flex flex-wrap gap-4 text-sm">
                    <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded">
                      🔥 Total: {exploitResults.classification.total_count}
                    </span>
                    <span className="bg-red-100 text-red-800 px-2 py-1 rounded">
                      💥 RCE: {exploitResults.classification.rce_count}
                    </span>
                    <span className="bg-purple-100 text-purple-800 px-2 py-1 rounded">
                      💀 DoS: {exploitResults.classification.dos_count}
                    </span>
                    <span className="bg-yellow-100 text-yellow-800 px-2 py-1 rounded">
                      🔓 Auth Bypass: {exploitResults.classification.auth_bypass_count}
                    </span>
                    <span className="bg-green-100 text-green-800 px-2 py-1 rounded">
                      📊 Info Disclosure: {exploitResults.classification.info_disclosure_count}
                    </span>
                  </div>
                </div>
              )}

              {/* Services with Exploits */}
              {exploitResults.services?.length > 0 ? (
                <div className="space-y-3">
                  <h5 className="font-medium text-gray-800 mb-2">🔍 Exploits by Service</h5>
                  {exploitResults.services.map((service: any, idx: number) => (
                    <div key={idx} className="bg-gray-50 p-4 rounded border">
                      <p className="font-medium text-black mb-2">
                        {service.service || 'Unknown Service'} (Port {service.port})
                      </p>
                      {service.exploits?.length > 0 ? (
                        <div className="space-y-2">
                          <p className="text-sm text-gray-600">Found {service.exploits.length} exploits:</p>
                          <div className="max-h-40 overflow-y-auto space-y-1">
                            {service.exploits.slice(0, 5).map((exploit: any, eIdx: number) => (
                              <div key={eIdx} className="text-xs bg-white p-2 rounded border">
                                <span className="font-medium text-red-600">{exploit.Title}</span>
                                <br />
                                <span className="text-gray-500">Path: {exploit.Path}</span>
                              </div>
                            ))}
                            {service.exploits.length > 5 && (
                              <p className="text-xs text-gray-500">...and {service.exploits.length - 5} more</p>
                            )}
                          </div>
                        </div>
                      ) : (
                        <p className="text-sm text-gray-500">No exploits found for this service</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-600">No services with exploits found for this host.</p>
              )}
            </div>
          )}

          {/* Execution Results */}
          {executionResults && (
            <div className="mb-6 p-4 bg-white rounded border">
              <h4 className="font-semibold text-gray-800 mb-3">🚀 Exploitation Results</h4>
              <div className="bg-gray-50 p-4 rounded">
                <p className="text-lg font-medium text-black mb-3">
                  {executionResults.success_count > 0 ? (
                    <span className="text-green-600">✅ SUCCESS!</span>
                  ) : (
                    <span className="text-red-600">❌ No Successful Exploits</span>
                  )}
                </p>
                <div className="text-sm text-gray-700 mb-3">
                  <p>Total Attempts: <span className="font-medium">{executionResults.total_attempts}</span></p>
                  <p>Successful: <span className="font-medium text-green-600">{executionResults.success_count}</span></p>
                </div>
                {executionResults.successful_exploits?.length > 0 && (
                  <div>
                    <p className="font-medium text-black mb-2">Working Exploits:</p>
                    <div className="space-y-1">
                      {executionResults.successful_exploits.map((exploit: any, idx: number) => (
                        <div key={idx} className="bg-green-50 text-green-800 p-2 rounded text-sm">
                          ✓ {exploit.name || exploit.path}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* AI-Generated Metasploit Details */}
          {metasploitDetails.length > 0 && (
            <div className="mb-6 p-4 bg-white rounded border">
              <h4 className="font-semibold text-gray-800 mb-3">🎯 AI-Generated Metasploit Commands</h4>
              {metasploitDetails.map((exploit: any, idx: number) => (
                <div key={idx} className="bg-gray-50 p-4 rounded border mb-3">
                  <div className="flex justify-between items-start mb-3">
                    <h5 className="font-medium text-black text-lg">{exploit.cve_id}</h5>
                    <button
                      onClick={() => openTerminal(exploit.metasploit_commands)}
                      className="px-3 py-1 bg-red-600 text-white rounded text-sm hover:bg-red-700"
                    >
                      🚀 Execute in Terminal
                    </button>
                  </div>
                  
                  <div className="space-y-2">
                    <p className="text-sm"><strong>Service:</strong> {exploit.service} (Port {exploit.port})</p>
                    <p className="text-sm"><strong>Product:</strong> {exploit.product} {exploit.version}</p>
                    <p className="text-sm"><strong>CVE:</strong> {exploit.cve_id} (Score: {exploit.cve_score})</p>
                    
                    {exploit.metasploit_commands?.commands && (
                      <div>
                        <h6 className="font-medium text-black mb-2">Commands to execute:</h6>
                        <div className="bg-black text-green-400 p-3 rounded font-mono text-sm">
                          {exploit.metasploit_commands.commands.map((cmd: string, cmdIdx: number) => (
                            <div key={cmdIdx} className="mb-1">
                              {cmd}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {exploit.metasploit_commands?.required_options && (
                      <div>
                        <h6 className="font-medium text-black mb-2">Required Options:</h6>
                        <div className="space-y-1">
                          {Object.entries(exploit.metasploit_commands.required_options).map(([key, value]) => (
                            <div key={key} className="text-sm">
                              <strong>{key}:</strong> {value}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 🔽 Optional Detailed Modal */}
      {showModal && selectedHostData && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white w-full max-w-4xl max-h-[90vh] overflow-y-auto p-6 rounded-lg shadow-lg relative">
            {/* Close Button */}
            <button
              onClick={closeModal}
              className="absolute top-3 right-4 text-gray-600 text-2xl hover:text-black"
              aria-label="Close"
            >
              &times;
            </button>

            <h3 className="text-2xl font-bold mb-4 text-black">
              🔍 Detailed View for {selectedHostData.host}
            </h3>

            {/* Open Ports */}
            <div className="mb-4">
              <h4 className="font-semibold text-gray-800 mb-1">🔌 Open Ports</h4>
              {selectedHostData.open_ports?.length > 0 ? (
                <ul className="list-disc list-inside text-black text-sm">
                  {selectedHostData.open_ports.map((port: any, idx: number) => (
                    <li key={idx}>
                      Port {port.port} / {port.protocol}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-gray-600">No open ports detected.</p>
              )}
            </div>

            {/* Detailed Services + CVEs */}
            <div className="mb-6">
              <h4 className="font-semibold text-gray-800 mb-1">🛡️ Detailed Services & CVEs</h4>
              {selectedHostData.services?.length > 0 ? (
                <ul className="space-y-3 text-sm text-black">
                  {selectedHostData.services.map((srv: any, idx: number) => (
                    <li key={idx} className="bg-gray-100 border rounded p-3">
                      <p><strong>Port:</strong> {srv.port} ({srv.protocol})</p>
                      <p><strong>Service:</strong> {srv.service}</p>
                      <p><strong>Product:</strong> {srv.product}</p>
                      <p><strong>Version:</strong> {srv.version}</p>
                      <p><strong>Confidence:</strong> {srv.confidence}</p>
                      {srv.cves?.length > 0 ? (
                        <div className="mt-2">
                          <p><strong>CVEs Found:</strong> {srv.cves.length}</p>
                          <div className="mt-1 space-y-1">
                            {srv.cves.slice(0, 3).map((cve: any, cveIdx: number) => (
                              <div key={cveIdx} className="text-xs bg-red-50 p-2 rounded">
                                <span className="font-medium">{cve.id}</span> - 
                                <span className="text-red-600 ml-1">{cve.severity}</span>
                                <span className="ml-1">(Score: {cve.score})</span>
                                <p className="text-gray-600 mt-1">{cve.description?.substring(0, 100)}...</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : (
                        <p><strong>CVEs:</strong> None found</p>
                      )}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-gray-600">No services found.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Terminal */}
      <SimpleTerminal 
        isOpen={terminalOpen} 
        onClose={closeTerminal}
        exploitCommands={selectedExploitCommands}
      />

      {/* Metasploit Terminal */}
      <MetasploitTerminal
        isOpen={metasploitTerminalOpen}
        onClose={() => setMetasploitTerminalOpen(false)}
      />
    </div>
  );
}
