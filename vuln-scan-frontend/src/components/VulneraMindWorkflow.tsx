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
  step: 'input' | 'discover' | 'scan' | 'exploits' | 'ai' | 'metasploit' | 'report';
  target: string;
  hosts: string[];
  selectedHost: string;
  scanResults: ScanResult[];
  exploitResults: any[];
  aiRecommendations: AIRecommendation[];
  selectedServiceCVEs: ScanResult | null;
  generatedReport: any;
}

export default function VulneraMindWorkflow() {
  const [state, setState] = useState<WorkflowState>({
    step: 'input',
    target: '',
    hosts: [],
    selectedHost: '',
    scanResults: [],
    exploitResults: [],
    aiRecommendations: [],
    selectedServiceCVEs: null,
    generatedReport: null
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
    const trimmedTarget = state.target.trim();
    if (!trimmedTarget) {
      setError('Please enter an IP address or subnet');
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Check if it's a single IP or subnet
      const isSingleIP = !trimmedTarget.includes('/') && !trimmedTarget.includes('-');
      
      if (isSingleIP) {
        // Single IP - go directly to scanning
        setState(prev => ({ ...prev, selectedHost: trimmedTarget, step: 'scan' }));
        await scanHost(trimmedTarget);
      } else {
        // Subnet - discover hosts first
        console.log('🔍 Discovering hosts in:', trimmedTarget);
        const response = await apiCall('/discover-hosts', { target: trimmedTarget });
        
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

  // Step 7: Generate AI vulnerability report
  const handleGenerateReport = async () => {
    if (!state.scanResults.length) return;

    setLoading(true);
    setError('');

    try {
      console.log('📋 Generating AI vulnerability report for:', state.selectedHost);
      const response = await apiCall('/generate-report', {
        host: state.selectedHost,
        scan_results: state.scanResults,
        exploit_results: state.exploitResults,
        ai_recommendations: state.aiRecommendations
      });
      
      setState(prev => ({ 
        ...prev, 
        generatedReport: response,
        step: 'report'
      }));
      console.log('✅ Report generated successfully');
    } catch (err: any) {
      setError(err.message);
      console.error('❌ Report generation failed:', err);
    } finally {
      setLoading(false);
    }
  };

  // Download report as markdown file
  const downloadReport = () => {
    if (!state.generatedReport?.markdown) return;

    const blob = new Blob([state.generatedReport.markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `VulneraMind_Report_${state.selectedHost}_${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const resetWorkflow = () => {
    setState({
      step: 'input',
      target: '',
      hosts: [],
      selectedHost: '',
      scanResults: [],
      exploitResults: [],
      aiRecommendations: [],
      selectedServiceCVEs: null,
      generatedReport: null
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
            📋 <strong>Workflow:</strong> Enter IP/Subnet → Discover Hosts → Select Host → Scan Services → Find Exploits → AI Recommendations → Open Metasploit → Generate AI Report
          </p>
        </div>

        {/* Progress Indicator */}
        <div className="flex items-center space-x-4 mb-6">
          {['input', 'discover', 'scan', 'exploits', 'ai', 'metasploit', 'report'].map((step, index) => (
            <div
              key={step}
              className={`flex items-center ${
                ['input', 'discover', 'scan', 'exploits', 'ai', 'metasploit', 'report'].indexOf(state.step) >= index
                  ? 'text-blue-600'
                  : 'text-gray-400'
              }`}
            >
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                  ['input', 'discover', 'scan', 'exploits', 'ai', 'metasploit', 'report'].indexOf(state.step) >= index
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
                {step === 'report' && 'Report'}
              </span>
              {index < 6 && <span className="mx-2">→</span>}
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
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Services List */}
            <div className="space-y-4">
              <h3 className="font-semibold text-gray-800 mb-3">Services Found:</h3>
              {state.scanResults.map((result, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
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
                          onClick={() => setState(prev => ({ ...prev, selectedServiceCVEs: result }))}
                          className={`px-3 py-1 rounded text-sm transition-colors ${
                            state.selectedServiceCVEs === result 
                              ? 'bg-red-600 text-white' 
                              : 'bg-red-100 text-red-600 hover:bg-red-200'
                          }`}
                        >
                          {result.cves.length} CVE{result.cves.length !== 1 ? 's' : ''}
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

            {/* CVE Details Panel */}
            <div className="lg:sticky lg:top-6">
              {state.selectedServiceCVEs ? (
                <div className="border border-gray-200 rounded-lg p-4 bg-red-50">
                  <div className="flex justify-between items-start mb-4">
                    <h3 className="font-bold text-red-800">
                      CVE Details for Port {state.selectedServiceCVEs.port}
                    </h3>
                    <button
                      onClick={() => setState(prev => ({ ...prev, selectedServiceCVEs: null }))}
                      className="text-gray-500 hover:text-gray-700"
                    >
                      ✕
                    </button>
                  </div>
                  
                  <div className="mb-4">
                    <p className="text-sm text-gray-700">
                      <strong>Service:</strong> {state.selectedServiceCVEs.service}
                      {state.selectedServiceCVEs.product && ` - ${state.selectedServiceCVEs.product}`}
                      {state.selectedServiceCVEs.version && ` ${state.selectedServiceCVEs.version}`}
                    </p>
                  </div>

                  <div className="max-h-96 overflow-y-auto space-y-3">
                    <h4 className="font-semibold text-red-800 mb-2">
                      Found CVEs ({state.selectedServiceCVEs.cves?.length || 0}):
                    </h4>
                    {state.selectedServiceCVEs.cves && state.selectedServiceCVEs.cves.length > 0 ? (
                      state.selectedServiceCVEs.cves.map((cve: any, cveIndex: number) => (
                        <div key={cveIndex} className="bg-white border border-red-200 rounded p-3">
                          <div className="flex justify-between items-start mb-2">
                            <span className="font-bold text-red-700">{cve.id}</span>
                            <div className="flex gap-2">
                              <span className={`px-2 py-1 rounded text-xs font-medium ${
                                cve.severity === 'HIGH' || cve.severity === 'CRITICAL' 
                                  ? 'bg-red-100 text-red-800'
                                  : cve.severity === 'MEDIUM' 
                                  ? 'bg-yellow-100 text-yellow-800'
                                  : 'bg-green-100 text-green-800'
                              }`}>
                                {cve.severity}
                              </span>
                              <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded text-xs font-medium">
                                {cve.score}
                              </span>
                            </div>
                          </div>
                          <p className="text-sm text-gray-700 leading-relaxed">
                            {cve.description}
                          </p>
                        </div>
                      ))
                    ) : (
                      <p className="text-gray-500 text-sm">No CVEs found for this service.</p>
                    )}
                  </div>
                </div>
              ) : (
                <div className="border border-gray-200 rounded-lg p-4 bg-gray-50">
                  <h3 className="font-semibold text-gray-700 mb-2">CVE Details</h3>
                  <p className="text-gray-500 text-sm">
                    Click on a CVE button from the services list to view detailed vulnerability information.
                  </p>
                </div>
              )}
            </div>
          </div>
          
          <div className="flex gap-4 mt-6">
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
              onClick={handleGenerateReport}
              disabled={loading}
              className="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 font-medium"
            >
              {loading ? '📋 Generating...' : '📋 Generate AI Report'}
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
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium mr-4"
          >
            🔄 Start New Scan
          </button>
          
          <button
            onClick={handleGenerateReport}
            disabled={loading}
            className="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 font-medium"
          >
            {loading ? '📋 Generating...' : '📋 Generate AI Report'}
          </button>
        </div>
      )}

      {/* Step 7: AI Vulnerability Report */}
      {state.step === 'report' && state.generatedReport && (
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-bold mb-4">📋 AI Vulnerability Assessment Report</h2>
          
          <div className="bg-green-50 p-4 rounded-lg mb-6">
            <p className="text-green-800 mb-2">
              ✅ Comprehensive vulnerability assessment report has been generated for <strong>{state.selectedHost}</strong>
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="font-semibold">Total Vulnerabilities:</span>
                <br />
                {state.generatedReport.metadata?.total_vulnerabilities || 0}
              </div>
              <div>
                <span className="font-semibold">Services Scanned:</span>
                <br />
                {state.generatedReport.metadata?.total_services || 0}
              </div>
              <div>
                <span className="font-semibold">Report Length:</span>
                <br />
                {Math.round((state.generatedReport.metadata?.report_length || 0) / 1000)}K chars
              </div>
              <div>
                <span className="font-semibold">Risk Level:</span>
                <br />
                <span className="font-bold text-red-600">
                  {state.generatedReport.report?.risk_assessment?.overall_risk_level || 'Unknown'}
                </span>
              </div>
            </div>
          </div>

          {/* Report Actions */}
          <div className="flex gap-4 mb-6">
            <button
              onClick={downloadReport}
              className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
            >
              💾 Download Report (Markdown)
            </button>
            <button
              onClick={() => {
                const reportWindow = window.open('', '_blank');
                if (reportWindow) {
                  reportWindow.document.write(`
                    <html>
                      <head>
                        <title>VulneraMind Report - ${state.selectedHost}</title>
                        <style>
                          body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
                          h1, h2, h3 { color: #1f2937; }
                          .metadata { background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0; }
                          .critical { color: #dc2626; font-weight: bold; }
                          .high { color: #ea580c; font-weight: bold; }
                          .medium { color: #d97706; font-weight: bold; }
                          .low { color: #16a34a; font-weight: bold; }
                          pre { background: #f8fafc; padding: 15px; border-radius: 8px; overflow-x: auto; }
                          code { background: #e5e7eb; padding: 2px 6px; border-radius: 4px; }
                        </style>
                      </head>
                      <body>
                        <pre>${state.generatedReport.markdown}</pre>
                      </body>
                    </html>
                  `);
                  reportWindow.document.close();
                }
              }}
              className="px-6 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 font-medium"
            >
              👁️ Preview Report
            </button>
            <button
              onClick={resetWorkflow}
              className="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600"
            >
              ← Start Over
            </button>
          </div>

          {/* Report Summary */}
          <div className="bg-gray-50 p-6 rounded-lg">
            <h3 className="font-bold text-gray-800 mb-4">Report Summary</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Executive Summary Preview */}
              <div>
                <h4 className="font-semibold text-gray-700 mb-2">Executive Summary Preview</h4>
                <div className="bg-white p-4 rounded border text-sm text-gray-600 max-h-48 overflow-y-auto">
                  {state.generatedReport.report?.executive_summary?.substring(0, 500) || 'No summary available'}
                  {(state.generatedReport.report?.executive_summary?.length || 0) > 500 && '...'}
                </div>
              </div>

              {/* Key Metrics */}
              <div>
                <h4 className="font-semibold text-gray-700 mb-2">Key Security Metrics</h4>
                <div className="bg-white p-4 rounded border space-y-2">
                  <div className="flex justify-between">
                    <span>Risk Score:</span>
                    <span className="font-bold">
                      {state.generatedReport.report?.risk_assessment?.risk_score || 0}/100
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Avg CVSS Score:</span>
                    <span className="font-bold">
                      {state.generatedReport.report?.risk_assessment?.average_cvss_score || 0}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Critical Issues:</span>
                    <span className="font-bold text-red-600">
                      {state.generatedReport.report?.technical_findings?.length || 0}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Report Generated:</span>
                    <span className="text-sm">
                      {new Date(state.generatedReport.metadata?.generation_timestamp || '').toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 p-4 bg-yellow-50 rounded border-l-4 border-yellow-400">
              <p className="text-yellow-800 text-sm">
                <strong>📋 Report Contents:</strong> Executive Summary, Technical Findings, Risk Assessment, 
                Exploit Analysis, Remediation Strategies, Compliance Impact, and Strategic Recommendations.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
