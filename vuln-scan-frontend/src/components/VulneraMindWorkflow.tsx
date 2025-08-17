import React, { useState } from 'react';

interface Host {
  ip: string;
}

interface ScanResult {
  port: number;
  protocol: string;
  service: string;
  product: string;
  version: string;
  confidence: string;
  cves: any[];
  cve_summary: any;
}

interface ExploitResult {
  Title: string;
  Description: string;
  Type: string;
  Platform: string;
  Path: string;
}

interface AIRecommendation {
  exploit: any;
  ai_suggestion: any;
  exploit_data: any;
}

interface WorkflowState {
  step: 'input' | 'discover' | 'scan' | 'exploits' | 'ai' | 'metasploit';
  target: string;
  hosts: string[];
  selectedHost: string;
  scanResults: ScanResult[];
  exploitResults: any[];
  aiRecommendations: AIRecommendation[];
}

export default function VulneraMindWorkflow() {
  const [state, setState] = useState<WorkflowState>({
    step: 'input',
    target: '',
    hosts: [],
    selectedHost: '',
    scanResults: [],
    exploitResults: [],
    aiRecommendations: []
  });
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const apiCall = async (endpoint: string, data: any) => {
    const response = await fetch(`http://localhost:8000${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.statusText}`);
    }
    
    return response.json();
  };

  // Step 1: Discover hosts or scan single IP
  const handleTargetSubmit = async () => {
    if (!state.target.trim()) {
      setError('Please enter an IP address or subnet');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Check if it's a single IP or subnet
      const isSingleIP = !state.target.includes('/') && !state.target.includes('-');
      
      if (isSingleIP) {
        // Single IP - go directly to scanning
        setState(prev => ({ ...prev, selectedHost: state.target, step: 'scan' }));
        await scanHost(state.target);
      } else {
        // Subnet - discover hosts first
        console.log('🔍 Discovering hosts in:', state.target);
        const response = await apiCall('/discover-hosts', { target: state.target });
        
        setState(prev => ({ 
          ...prev, 
          hosts: response.hosts, 
          step: 'discover' 
        }));
        console.log('✅ Found hosts:', response.hosts);
      }
    } catch (err: any) {
      setError(err.message);
      console.error('❌ Discovery failed:', err);
    } finally {
      setLoading(false);
    }
  };

  // Step 2: Select host from discovered hosts
  const handleHostSelect = async (host: string) => {
    setState(prev => ({ ...prev, selectedHost: host, step: 'scan' }));
    await scanHost(host);
  };

  // Step 3: Scan selected host
  const scanHost = async (host: string) => {
    setLoading(true);
    setError('');

    try {
      console.log('🎯 Scanning host:', host);
      const response = await apiCall('/scan-host', { host, ports: '1-1000' });
      
      setState(prev => ({ 
        ...prev, 
        scanResults: response.scan_results 
      }));
      console.log('✅ Scan completed:', response.scan_results.length, 'services found');
    } catch (err: any) {
      setError(err.message);
      console.error('❌ Scan failed:', err);
    } finally {
      setLoading(false);
    }
  };

  // Step 4: Find exploits
  const handleFindExploits = async () => {
    if (!state.scanResults.length) return;

    setLoading(true);
    setError('');

    try {
      console.log('💥 Finding exploits for:', state.selectedHost);
      const response = await apiCall('/find-exploits', {
        host: state.selectedHost,
        scan_results: state.scanResults
      });
      
      setState(prev => ({ 
        ...prev, 
        exploitResults: response.exploits,
        step: 'exploits'
      }));
      console.log('✅ Found exploits:', response.total_exploits);
    } catch (err: any) {
      setError(err.message);
      console.error('❌ Exploit search failed:', err);
    } finally {
      setLoading(false);
    }
  };

  // Step 5: Get AI recommendations
  const handleAIRecommendations = async () => {
    if (!state.exploitResults.length) return;

    setLoading(true);
    setError('');

    try {
      console.log('🤖 Getting AI recommendations for:', state.selectedHost);
      const response = await apiCall('/ai-recommendations', {
        host: state.selectedHost,
        exploit_results: state.exploitResults
      });
      
      setState(prev => ({ 
        ...prev, 
        aiRecommendations: response.recommendations,
        step: 'ai'
      }));
      console.log('✅ Generated AI recommendations:', response.total_recommendations);
    } catch (err: any) {
      setError(err.message);
      console.error('❌ AI recommendations failed:', err);
    } finally {
      setLoading(false);
    }
  };

  // Step 6: Open Metasploit terminal
  const handleOpenMetasploit = async () => {
    setLoading(true);
    setError('');

    try {
      console.log('🔥 Opening Metasploit terminal...');
      const response = await apiCall('/open-metasploit', {});
      
      alert('✅ ' + response.message);
      setState(prev => ({ ...prev, step: 'metasploit' }));
    } catch (err: any) {
      setError(err.message);
      console.error('❌ Failed to open Metasploit:', err);
    } finally {
      setLoading(false);
    }
  };

  const resetWorkflow = () => {
    setState({
      step: 'input',
      target: '',
      hosts: [],
      selectedHost: '',
      scanResults: [],
      exploitResults: [],
      aiRecommendations: []
    });
    setError('');
  };

  return (
    <div className="max-w-6xl mx-auto p-6 bg-gray-50 min-h-screen">
      <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
        <h1 className="text-3xl font-bold text-gray-800 mb-4">
          🛡️ VulneraMind Security Scanner
        </h1>
        <div className="bg-blue-50 p-4 rounded-lg mb-4">
          <p className="text-blue-800">
            📋 <strong>Workflow:</strong> Enter IP/Subnet → Discover Hosts → Select Host → Scan Services → Find Exploits → AI Recommendations → Open Metasploit
          </p>
        </div>

        {/* Progress Indicator */}
        <div className="flex items-center space-x-4 mb-6">
          {['input', 'discover', 'scan', 'exploits', 'ai', 'metasploit'].map((step, index) => (
            <div
              key={step}
              className={`flex items-center ${
                ['input', 'discover', 'scan', 'exploits', 'ai'].indexOf(state.step) >= index
                  ? 'text-blue-600'
                  : 'text-gray-400'
              }`}
            >
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                  ['input', 'discover', 'scan', 'exploits', 'ai'].indexOf(state.step) >= index
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-200 text-gray-400'
                }`}
              >
                {index + 1}
              </div>
              <span className="ml-2 text-sm font-medium">
                {step === 'input' && 'Target'}
                {step === 'discover' && 'Discover'}
                {step === 'scan' && 'Scan'}
                {step === 'exploits' && 'Exploits'}
                {step === 'ai' && 'AI'}
                {step === 'metasploit' && 'Metasploit'}
              </span>
              {index < 5 && <span className="mx-2">→</span>}
            </div>
          ))}
        </div>

        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            ❌ {error}
          </div>
        )}
      </div>

      {/* Step 1: Input Target */}
      {state.step === 'input' && (
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-bold mb-4">🎯 Enter Target</h2>
          <p className="text-gray-600 mb-4">
            Enter a single IP address (e.g., 192.168.1.1) or subnet (e.g., 192.168.1.1-10 or 192.168.1.0/24)
          </p>
          
          <div className="flex gap-4">
            <input
              type="text"
              value={state.target}
              onChange={(e) => setState(prev => ({ ...prev, target: e.target.value }))}
              placeholder="e.g., 192.168.1.1 or 192.168.1.1-10"
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={handleTargetSubmit}
              disabled={loading}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? '🔍 Processing...' : 'Start Scan'}
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Host Discovery Results */}
      {state.step === 'discover' && state.hosts.length > 0 && (
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-bold mb-4">📡 Discovered Hosts ({state.hosts.length})</h2>
          <p className="text-gray-600 mb-4">Select a host to scan:</p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {state.hosts.map((host) => (
              <button
                key={host}
                onClick={() => handleHostSelect(host)}
                disabled={loading}
                className="p-4 border border-gray-200 rounded-lg hover:border-blue-300 hover:bg-blue-50 transition-colors text-left"
              >
                <div className="font-medium text-gray-800">{host}</div>
                <div className="text-sm text-gray-500">Click to scan</div>
              </button>
            ))}
          </div>
          
          <button
            onClick={resetWorkflow}
            className="mt-4 px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600"
          >
            ← Back to Target Input
          </button>
        </div>
      )}

      {/* Step 3: Scan Results */}
      {state.step === 'scan' && state.scanResults.length > 0 && (
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-bold mb-4">
            📊 Scan Results for {state.selectedHost} ({state.scanResults.length} services)
          </h2>
          
              <div className="space-y-4 mb-6">
            {state.scanResults.map((result, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-4">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="font-bold text-blue-600">
                      Port {result.port}/{result.protocol}
                    </span>
                    <div className="text-gray-700 mt-1">
                      <strong>{result.service}</strong>
                      {result.product && ` - ${result.product}`}
                      {result.version && ` ${result.version}`}
                    </div>
                    <div className="text-sm text-gray-500">Confidence: {result.confidence}</div>
                  </div>
                  {result.cves && result.cves.length > 0 && (
                    <div>
                      <button
                        onClick={() => {
                          const cveDetails = result.cves.map((cve: any) => 
                            `${cve.id} (${cve.severity}) - Score: ${cve.score}\n${cve.description}`
                          ).join('\n\n');
                          alert(`CVEs found for ${result.service}:\n\n${cveDetails}`);
                        }}
                        className="px-3 py-1 bg-red-100 text-red-600 rounded text-sm hover:bg-red-200 transition-colors"
                      >
                        {result.cves.length} CVEs (Click to view)
                      </button>
                    </div>
                  )}
                </div>
                
                {/* CVE Summary */}
                {result.cve_summary && (
                  <div className="mt-3 text-xs text-gray-600">
                    <span className="inline-block mr-4">
                      🔥 High/Critical: {result.cve_summary.high_severity_count || 0}
                    </span>
                    <span className="inline-block mr-4">
                      📊 Avg Score: {result.cve_summary.average_score ? result.cve_summary.average_score.toFixed(1) : '0.0'}
                    </span>
                    <span className="inline-block">
                      📈 Source: {result.cve_summary.data_source || 'unknown'}
                    </span>
                  </div>
                )}
              </div>
            ))}
          </div>
          
          <div className="flex gap-4">
            <button
              onClick={handleFindExploits}
              disabled={loading}
              className="px-6 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 font-medium"
            >
              {loading ? '💥 Finding...' : '🔍 Find Exploits'}
            </button>
            <button
              onClick={resetWorkflow}
              className="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600"
            >
              ← Start Over
            </button>
          </div>
        </div>
      )}

      {/* Step 4: Exploit Results */}
      {state.step === 'exploits' && state.exploitResults.length > 0 && (
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-bold mb-4">
            💥 Exploit Analysis for {state.selectedHost}
          </h2>
          
          <div className="space-y-4 mb-6 max-h-96 overflow-y-auto">
            {state.exploitResults.map((service, serviceIndex) => (
              service.exploits && service.exploits.length > 0 && (
                <div key={serviceIndex} className="border border-gray-200 rounded-lg p-4">
                  <h3 className="font-bold text-gray-800 mb-2">
                    Port {service.port}: {service.service} - {service.exploits.length} exploits found
                  </h3>
                  <div className="space-y-2">
                    {service.exploits.slice(0, 3).map((exploit: any, exploitIndex: number) => (
                      <div key={exploitIndex} className="bg-gray-50 p-3 rounded">
                        <h4 className="font-medium text-gray-800">{exploit.Title}</h4>
                        <p className="text-sm text-gray-600 mt-1">{exploit.Description}</p>
                        <div className="flex gap-2 mt-2">
                          <span className="text-xs bg-blue-100 text-blue-600 px-2 py-1 rounded">
                            {exploit.Platform}
                          </span>
                          <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">
                            {exploit.Type}
                          </span>
                        </div>
                      </div>
                    ))}
                    {service.exploits.length > 3 && (
                      <div className="text-sm text-gray-500">
                        ... and {service.exploits.length - 3} more exploits
                      </div>
                    )}
                  </div>
                </div>
              )
            ))}
          </div>
          
          <div className="flex gap-4">
            <button
              onClick={handleAIRecommendations}
              disabled={loading}
              className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 font-medium"
            >
              {loading ? '🤖 Generating...' : '🤖 Get AI Metasploit Recommendations'}
            </button>
            <button
              onClick={resetWorkflow}
              className="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600"
            >
              ← Start Over
            </button>
          </div>
        </div>
      )}

      {/* Step 5: AI Recommendations */}
      {state.step === 'ai' && state.aiRecommendations.length > 0 && (
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-bold mb-4">
            🤖 AI Metasploit Recommendations for {state.selectedHost} ({state.aiRecommendations.length})
          </h2>
          
          <div className="space-y-6 mb-6 max-h-96 overflow-y-auto">
            {state.aiRecommendations.map((rec, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-4 bg-gray-50">
                <h3 className="font-bold text-lg text-gray-800 mb-2">
                  {rec.exploit.Title}
                </h3>
                <p className="text-sm text-gray-600 mb-3">{rec.exploit.Description}</p>
                
                {rec.ai_suggestion.error ? (
                  <div className="p-3 bg-red-100 text-red-700 rounded">
                    ❌ {rec.ai_suggestion.error}
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-blue-50 p-3 rounded">
                        <span className="font-semibold text-blue-800">Module:</span>
                        <code className="block mt-1 text-sm bg-white p-2 rounded">
                          {rec.ai_suggestion.exploit_module}
                        </code>
                      </div>
                      <div className="bg-green-50 p-3 rounded">
                        <span className="font-semibold text-green-800">Payload:</span>
                        <code className="block mt-1 text-sm bg-white p-2 rounded">
                          {rec.ai_suggestion.payload}
                        </code>
                      </div>
                    </div>
                    
                    {rec.ai_suggestion.commands && (
                      <div className="bg-gray-100 p-3 rounded">
                        <span className="font-semibold text-gray-800">Commands:</span>
                        <div className="mt-2 bg-black text-green-400 p-3 rounded font-mono text-sm">
                          {rec.ai_suggestion.commands.map((cmd: string, cmdIndex: number) => (
                            <div key={cmdIndex} className="mb-1">
                              <span className="text-green-600">msf6 &gt;</span> {cmd}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
          
          <div className="flex gap-4">
            <button
              onClick={handleOpenMetasploit}
              disabled={loading}
              className="px-6 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 font-medium"
            >
              {loading ? '🔥 Opening...' : '🔥 Open Metasploit Terminal'}
            </button>
            <button
              onClick={resetWorkflow}
              className="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600"
            >
              ← Start Over
            </button>
          </div>
        </div>
      )}

      {/* Step 6: Metasploit Opened */}
      {state.step === 'metasploit' && (
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-bold mb-4">🔥 Metasploit Terminal Opened</h2>
          <div className="bg-green-50 p-4 rounded-lg mb-4">
            <p className="text-green-800">
              ✅ Metasploit RPC terminal has been opened in a new window. You can now use the AI recommendations above to exploit the target.
            </p>
          </div>
          
          <div className="bg-yellow-50 p-4 rounded-lg mb-4">
            <p className="text-yellow-800">
              💡 <strong>Next Steps:</strong>
              <br />• Use the AI-generated commands in your Metasploit terminal
              <br />• Set the required options (RHOSTS, LHOST, etc.)
              <br />• Run the exploits and establish connections
            </p>
          </div>
          
          <button
            onClick={resetWorkflow}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
          >
            🔄 Start New Scan
          </button>
        </div>
      )}
    </div>
  );
}
