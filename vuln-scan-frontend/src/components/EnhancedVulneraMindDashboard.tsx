import React, { useState, useEffect, useRef } from 'react';
import AnimatedBackground from './AnimatedBackground';
import ScanProgressBar from './ScanProgressBar';

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

interface LogEntry {
  timestamp: string;
  level: 'info' | 'success' | 'warning' | 'error';
  message: string;
  category: 'system' | 'scan' | 'exploit' | 'ai' | 'metasploit';
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

export default function EnhancedVulneraMindDashboard() {
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
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activePanel, setActivePanel] = useState<'scan' | 'exploits' | 'ai' | 'console' | 'report'>('scan');
  const [expandedExploits, setExpandedExploits] = useState<string[]>([]);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs to bottom
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Add log entry
  const addLog = (level: LogEntry['level'], message: string, category: LogEntry['category'] = 'system') => {
    const newLog: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      level,
      message,
      category
    };
    setLogs(prev => [...prev, newLog]);
  };

  const apiCall = async (endpoint: string, data: any) => {
    addLog('info', `🔄 API Call: ${endpoint}`, 'system');
    
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
      addLog('error', '❌ No target specified', 'system');
      return;
    }

    setLoading(true);
    setError('');
    addLog('info', `🎯 Starting scan for target: ${state.target}`, 'scan');

    try {
      const isSingleIP = !state.target.includes('/') && !state.target.includes('-');
      
      if (isSingleIP) {
        addLog('info', '🔍 Single IP detected, proceeding directly to scan', 'scan');
        setState(prev => ({ ...prev, selectedHost: state.target, step: 'scan' }));
        await scanHost(state.target);
      } else {
        addLog('info', '🌐 Subnet detected, starting host discovery', 'scan');
        const response = await apiCall('/discover-hosts', { target: state.target });
        
        setState(prev => ({ 
          ...prev, 
          hosts: response.hosts, 
          step: 'discover' 
        }));
        addLog('success', `✅ Discovered ${response.hosts.length} live hosts`, 'scan');
      }
    } catch (err: any) {
      setError(err.message);
      addLog('error', `❌ Discovery failed: ${err.message}`, 'scan');
    } finally {
      setLoading(false);
    }
  };

  // Step 2: Select host from discovered hosts
  const handleHostSelect = async (host: string) => {
    addLog('info', `🎯 Selected host: ${host}`, 'scan');
    setState(prev => ({ ...prev, selectedHost: host, step: 'scan' }));
    await scanHost(host);
  };

  // Step 3: Scan selected host
  const scanHost = async (host: string) => {
    setLoading(true);
    setError('');
    addLog('info', `🔍 Starting port scan on ${host}`, 'scan');

    try {
      const response = await apiCall('/scan-host', { host, ports: '1-1000' });
      
      setState(prev => ({ 
        ...prev, 
        scanResults: response.scan_results 
      }));
      addLog('success', `✅ Scan completed: ${response.scan_results.length} services found`, 'scan');
      
      // Log each service found
      response.scan_results.forEach((service: any) => {
        const cveCount = service.cves?.length || 0;
        addLog('info', `📊 Port ${service.port}: ${service.service} (${cveCount} CVEs)`, 'scan');
      });
      
    } catch (err: any) {
      setError(err.message);
      addLog('error', `❌ Scan failed: ${err.message}`, 'scan');
    } finally {
      setLoading(false);
    }
  };

  // Step 4: Find exploits
  const handleFindExploits = async () => {
    if (!state.scanResults.length) return;

    setLoading(true);
    setError('');
    addLog('info', `💥 Searching for exploits on ${state.selectedHost}`, 'exploit');

    try {
      const response = await apiCall('/find-exploits', {
        host: state.selectedHost,
        scan_results: state.scanResults
      });
      
      setState(prev => ({ 
        ...prev, 
        exploitResults: response.exploits,
        step: 'exploits'
      }));
      addLog('success', `✅ Found ${response.total_exploits} exploits`, 'exploit');
      setActivePanel('exploits');
    } catch (err: any) {
      setError(err.message);
      addLog('error', `❌ Exploit search failed: ${err.message}`, 'exploit');
    } finally {
      setLoading(false);
    }
  };

  // Step 5: Get AI recommendations
  const handleAIRecommendations = async () => {
    if (!state.exploitResults.length) return;

    setLoading(true);
    setError('');
    addLog('info', `🤖 Generating AI recommendations for ${state.selectedHost}`, 'ai');

    try {
      const response = await apiCall('/ai-recommendations', {
        host: state.selectedHost,
        exploit_results: state.exploitResults
      });
      
      setState(prev => ({ 
        ...prev, 
        aiRecommendations: response.recommendations,
        step: 'ai'
      }));
      addLog('success', `✅ Generated ${response.total_recommendations} AI recommendations`, 'ai');
    } catch (err: any) {
      setError(err.message);
      addLog('error', `❌ AI recommendations failed: ${err.message}`, 'ai');
    } finally {
      setLoading(false);
    }
  };

  // Step 6: Open Metasploit terminal
  const handleOpenMetasploit = async () => {
    setLoading(true);
    setError('');
    addLog('info', '🔥 Opening Metasploit terminal...', 'metasploit');

    try {
      const response = await apiCall('/open-metasploit', {});
      
      setState(prev => ({ ...prev, step: 'metasploit' }));
      addLog('success', '✅ Metasploit terminal opened successfully', 'metasploit');
    } catch (err: any) {
      setError(err.message);
      addLog('error', `❌ Failed to open Metasploit: ${err.message}`, 'metasploit');
    } finally {
      setLoading(false);
    }
  };

  // Step 7: Generate AI vulnerability report
  const handleGenerateReport = async () => {
    if (!state.scanResults.length) return;

    setLoading(true);
    setError('');
    addLog('info', `📋 Generating vulnerability report for ${state.selectedHost}`, 'system');

    try {
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
      addLog('success', '✅ Report generated successfully', 'system');
      setActivePanel('report');
    } catch (err: any) {
      setError(err.message);
      addLog('error', `❌ Report generation failed: ${err.message}`, 'system');
    } finally {
      setLoading(false);
    }
  };

  // Download report as markdown file
  const downloadReport = (format: 'markdown' | 'pdf' = 'markdown') => {
    if (!state.generatedReport?.markdown) return;

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('.')[0];
    const baseFilename = `VulneraMind_Report_${state.selectedHost}_${timestamp}`;

    if (format === 'markdown') {
      const blob = new Blob([state.generatedReport.markdown], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${baseFilename}.md`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      addLog('success', '📁 Markdown report downloaded successfully', 'system');
    } else if (format === 'pdf') {
      // Convert markdown to PDF using browser's print functionality
      
      // Function to properly convert markdown to HTML
      const convertMarkdownToHtml = (markdown: string) => {
        let html = markdown;
        
        // Convert headers
        html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');
        html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
        html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
        
        // Convert bold text **text** to <strong>text</strong>
        html = html.replace(/\*\*([^*\n]+?)\*\*/g, '<strong>$1</strong>');
        
        // Convert bullet points
        html = html.replace(/^- (.*?)$/gm, '<li>$1</li>');
        
        // Wrap li elements in ul tags
        html = html.replace(/(<li>.*?<\/li>\s*)+/g, match => `<ul>${match}</ul>`);
        
        // Convert line breaks to proper HTML
        html = html.replace(/\n\n/g, '</p><p>');
        html = '<p>' + html + '</p>';
        
        // Clean up formatting
        html = html.replace(/<p><\/p>/g, '');
        html = html.replace(/<p>(<h[123]>)/g, '$1');
        html = html.replace(/(<\/h[123]>)<\/p>/g, '$1');
        html = html.replace(/<p>(<ul>)/g, '$1');
        html = html.replace(/(<\/ul>)<\/p>/g, '$1');
        html = html.replace(/\n/g, '<br>');
        
        return html;
      };
      
      const htmlContent = convertMarkdownToHtml(state.generatedReport.markdown);
      
      const reportWindow = window.open('', '_blank');
      if (reportWindow) {
        reportWindow.document.write(`
          <html>
            <head>
              <title>VulneraMind Report - ${state.selectedHost}</title>
              <style>
                @media print {
                  body { margin: 0; }
                  .no-print { display: none; }
                }
                body { 
                  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                  max-width: 1200px; 
                  margin: 0 auto; 
                  padding: 20px; 
                  background: white; 
                  color: #333; 
                  line-height: 1.6;
                  font-size: 14px; /* Normal text size */
                }
                /* Only titles should be big and bold */
                h1 { 
                  color: #8b5cf6; 
                  border-bottom: 2px solid #8b5cf6; 
                  padding-bottom: 5px; 
                  font-size: 1.8em; /* Bigger for main title */
                  font-weight: bold; 
                  text-align: center; 
                }
                h2 { 
                  color: #8b5cf6; 
                  border-bottom: 1px solid #8b5cf6; 
                  padding-bottom: 3px; 
                  font-size: 1.4em; /* Medium for section headers */
                  font-weight: bold; 
                  margin-top: 30px; 
                }
                h3 { 
                  color: #8b5cf6; 
                  font-size: 1.2em; /* Slightly bigger for sub-sections */
                  font-weight: bold; 
                  margin-top: 25px; 
                }
                /* Strong text (CVE titles) should be bold but normal size */
                strong { 
                  font-weight: bold; 
                  color: #333; 
                  font-size: inherit; /* Same size as normal text */
                }
                p { 
                  margin: 10px 0; 
                  font-size: 14px; /* Normal text size */
                }
                ul, li { 
                  font-size: 14px; /* Normal text size */
                }
                .metadata { 
                  background: #f8f9fa; 
                  padding: 15px; 
                  border-radius: 8px; 
                  margin: 20px 0; 
                  border-left: 4px solid #8b5cf6;
                }
                pre, code { 
                  background: #f1f3f4; 
                  padding: 15px; 
                  border-radius: 8px; 
                  overflow-x: auto; 
                  color: #333; 
                  border: 1px solid #ddd;
                }
                table { 
                  width: 100%; 
                  border-collapse: collapse; 
                  margin: 15px 0; 
                }
                th, td { 
                  border: 1px solid #ddd; 
                  padding: 12px; 
                  text-align: left; 
                }
                th { 
                  background: #8b5cf6; 
                  color: white; 
                  font-weight: bold;
                }
                tr:nth-child(even) { background: #f9f9f9; }
                .vulnerability { 
                  background: #fff5f5; 
                  border-left: 4px solid #ef4444; 
                  padding: 10px; 
                  margin: 10px 0; 
                }
                .exploit { 
                  background: #fffbeb; 
                  border-left: 4px solid #f59e0b; 
                  padding: 10px; 
                  margin: 10px 0; 
                }
                .button-container {
                  text-align: center;
                  margin: 20px 0;
                  padding: 20px;
                  background: #f8f9fa;
                  border-radius: 8px;
                }
                .print-btn {
                  background: #8b5cf6;
                  color: white;
                  padding: 12px 24px;
                  border: none;
                  border-radius: 6px;
                  font-size: 16px;
                  cursor: pointer;
                  margin: 0 10px;
                }
                .print-btn:hover {
                  background: #7c3aed;
                }
              </style>
            </head>
            <body>
              <div class="button-container no-print">
                <button class="print-btn" onclick="window.print()">🖨️ Save as PDF</button>
                <button class="print-btn" onclick="window.close()">❌ Close</button>
              </div>
              <div>${htmlContent}</div>
            </body>
          </html>
        `);
        reportWindow.document.close();
        addLog('success', '� PDF report window opened - use Print to save as PDF', 'system');
      }
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
      aiRecommendations: [],
      selectedServiceCVEs: null,
      generatedReport: null
    });
    setError('');
    setLogs([]);
    setActivePanel('scan');
    addLog('info', '🔄 Workflow reset', 'system');
  };

  const getLogIcon = (category: string) => {
    switch (category) {
      case 'scan': return '🔍';
      case 'exploit': return '💥';
      case 'ai': return '🤖';
      case 'metasploit': return '🔥';
      default: return '⚙️';
    }
  };

  const getLogColor = (level: string) => {
    switch (level) {
      case 'success': return 'text-green-400';
      case 'warning': return 'text-yellow-400';
      case 'error': return 'text-red-400';
      default: return 'text-blue-400';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900 relative">
      <AnimatedBackground />
      
      {/* Header */}
      <div className="bg-black/50 backdrop-blur-md border-b border-purple-500/30">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="bg-gradient-to-r from-purple-500 to-blue-500 p-3 rounded-lg">
                <span className="text-2xl font-bold text-white">🛡️</span>
              </div>
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">
                  VulneraMind Security Scanner
                </h1>
                <p className="text-gray-400 text-sm">Advanced AI-Powered Vulnerability Assessment Platform</p>
              </div>
            </div>
            
            {/* Status Indicator */}
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-2 px-3 py-1 rounded-full ${
                loading ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
              }`}>
                <div className={`w-2 h-2 rounded-full ${loading ? 'bg-yellow-400 animate-pulse' : 'bg-green-400'}`}></div>
                <span className="text-sm font-medium">
                  {loading ? 'Scanning...' : 'Ready'}
                </span>
              </div>
              
              {state.selectedHost && (
                <div className="bg-blue-500/20 text-blue-400 px-3 py-1 rounded-full">
                  <span className="text-sm font-medium">Target: {state.selectedHost}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto p-6">
        {/* Progress Bar */}
        <ScanProgressBar currentStep={state.step} isLoading={loading} />
        
        {/* Main Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          
          {/* Left Panel - Target Input & Quick Actions */}
          <div className="lg:col-span-1 space-y-6">
            
            {/* Target Input Card */}
            <div className="bg-black/40 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
              <h2 className="text-xl font-bold text-white mb-4 flex items-center">
                🎯 <span className="ml-2">Target Configuration</span>
              </h2>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    IP Address or Subnet
                  </label>
                  <input
                    type="text"
                    value={state.target}
                    onChange={(e) => setState(prev => ({ ...prev, target: e.target.value }))}
                    placeholder="e.g., 192.168.1.1 or 192.168.1.0/24"
                    className="w-full px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  />
                </div>
                
                <button
                  onClick={handleTargetSubmit}
                  disabled={loading || !state.target.trim()}
                  className="w-full px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg hover:from-purple-700 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium transition-all duration-200 transform hover:scale-105"
                >
                  {loading ? '🔍 Scanning...' : '🚀 Start Assessment'}
                </button>
              </div>
            </div>

            {/* Quick Stats */}
            {state.scanResults.length > 0 && (
              <div className="bg-black/40 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
                <h3 className="text-lg font-bold text-white mb-4">📊 Quick Stats</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-800/50 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">{state.scanResults.length}</div>
                    <div className="text-sm text-gray-400">Services</div>
                  </div>
                  <div className="bg-gray-800/50 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-red-400">
                      {state.scanResults.reduce((acc, service) => acc + (service.cves?.length || 0), 0)}
                    </div>
                    <div className="text-sm text-gray-400">CVEs</div>
                  </div>
                  <div className="bg-gray-800/50 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-purple-400">
                      {state.exploitResults.reduce((acc, service) => acc + (service.exploits?.length || 0), 0)}
                    </div>
                    <div className="text-sm text-gray-400">Exploits</div>
                  </div>
                  <div className="bg-gray-800/50 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">{state.aiRecommendations.length}</div>
                    <div className="text-sm text-gray-400">AI Recs</div>
                  </div>
                </div>
              </div>
            )}

            {/* Action Buttons */}
            {state.scanResults.length > 0 && (
              <div className="bg-black/40 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
                <h3 className="text-lg font-bold text-white mb-4">⚡ Actions</h3>
                <div className="space-y-3">
                  <button
                    onClick={handleFindExploits}
                    disabled={loading}
                    className="w-full px-4 py-2 bg-gradient-to-r from-red-600 to-orange-600 text-white rounded-lg hover:from-red-700 hover:to-orange-700 disabled:opacity-50 font-medium transition-all duration-200"
                  >
                    💥 Find Exploits
                  </button>
                  
                  {state.exploitResults.length > 0 && (
                    <button
                      onClick={handleAIRecommendations}
                      disabled={loading}
                      className="w-full px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-lg hover:from-blue-700 hover:to-cyan-700 disabled:opacity-50 font-medium transition-all duration-200"
                    >
                      🤖 AI Analysis
                    </button>
                  )}
                  
                  {state.aiRecommendations.length > 0 && (
                    <>
                      <button
                        onClick={handleOpenMetasploit}
                        disabled={loading}
                        className="w-full px-4 py-2 bg-gradient-to-r from-gray-700 to-gray-600 text-white rounded-lg hover:from-gray-800 hover:to-gray-700 disabled:opacity-50 font-medium transition-all duration-200"
                      >
                        🔥 Open Metasploit
                      </button>
                      
                      <button
                        onClick={handleGenerateReport}
                        disabled={loading}
                        className="w-full px-4 py-2 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-lg hover:from-green-700 hover:to-emerald-700 disabled:opacity-50 font-medium transition-all duration-200"
                      >
                        📋 Generate Report
                      </button>
                    </>
                  )}
                  
                  <button
                    onClick={resetWorkflow}
                    className="w-full px-4 py-2 bg-gradient-to-r from-gray-600 to-gray-500 text-white rounded-lg hover:from-gray-700 hover:to-gray-600 font-medium transition-all duration-200"
                  >
                    🔄 Reset
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Right Panel - Main Content Area */}
          <div className="lg:col-span-2">
            
            {/* Panel Tabs */}
            <div className="bg-black/40 backdrop-blur-md border border-purple-500/30 rounded-t-xl">
              <div className="flex border-b border-gray-700">
                {[
                  { id: 'scan', label: '🔍 Scan Results', count: state.scanResults.length },
                  { id: 'exploits', label: '💥 Exploits', count: state.exploitResults.reduce((acc, s) => acc + (s.exploits?.length || 0), 0) },
                  { id: 'ai', label: '🤖 AI Recommendations', count: state.aiRecommendations.length },
                  { id: 'console', label: '📟 Console', count: logs.length },
                  { id: 'report', label: '📋 Report', count: state.generatedReport ? 1 : 0 }
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActivePanel(tab.id as any)}
                    className={`px-6 py-3 font-medium transition-all duration-200 ${
                      activePanel === tab.id
                        ? 'text-purple-400 border-b-2 border-purple-500 bg-purple-500/10'
                        : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                    }`}
                  >
                    {tab.label}
                    {tab.count > 0 && (
                      <span className={`ml-2 px-2 py-1 text-xs rounded-full ${
                        activePanel === tab.id ? 'bg-purple-500 text-white' : 'bg-gray-600 text-gray-300'
                      }`}>
                        {tab.count}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Panel Content */}
            <div className="bg-black/40 backdrop-blur-md border-x border-b border-purple-500/30 rounded-b-xl p-6 min-h-[600px] max-h-[600px] overflow-y-auto">
              
              {/* Scan Results Panel */}
              {activePanel === 'scan' && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold text-white mb-4">🔍 Vulnerability Scan Results</h3>
                  
                  {state.scanResults.length === 0 ? (
                    <div className="text-center py-12">
                      <div className="text-6xl mb-4">🎯</div>
                      <p className="text-gray-400">No scan results yet. Start by entering a target above.</p>
                    </div>
                  ) : (
                    <div className="grid gap-4">
                      {state.scanResults.map((result, index) => (
                        <div key={index} className="bg-gray-800/50 border border-gray-600 rounded-lg p-4 hover:border-purple-500/50 transition-all duration-200">
                          <div className="flex justify-between items-start">
                            <div className="flex-1">
                              <div className="flex items-center space-x-3 mb-2">
                                <span className="text-lg font-bold text-blue-400">
                                  Port {result.port}/{result.protocol}
                                </span>
                                <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-sm">
                                  {result.service}
                                </span>
                              </div>
                              
                              <div className="text-gray-300 mb-2">
                                <strong>{result.product || 'Unknown'}</strong>
                                {result.version && ` v${result.version}`}
                              </div>
                              
                              <div className="text-sm text-gray-400">
                                Confidence: {result.confidence}
                              </div>
                            </div>
                            
                            {result.cves && result.cves.length > 0 && (
                              <button
                                onClick={() => setState(prev => ({ 
                                  ...prev, 
                                  selectedServiceCVEs: prev.selectedServiceCVEs === result ? null : result 
                                }))}
                                className={`px-3 py-1 rounded-lg text-sm font-medium transition-all duration-200 ${
                                  state.selectedServiceCVEs === result
                                    ? 'bg-red-500 text-white'
                                    : 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                                }`}
                              >
                                {result.cves.length} CVE{result.cves.length !== 1 ? 's' : ''}
                              </button>
                            )}
                          </div>
                          
                          {/* Expanded CVE Details */}
                          {state.selectedServiceCVEs === result && (
                            <div className="mt-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                              <h4 className="font-bold text-red-400 mb-3">CVE Details ({result.cves.length})</h4>
                              <div className="space-y-3 max-h-48 overflow-y-auto">
                                {result.cves.map((cve: any, cveIndex: number) => (
                                  <div key={cveIndex} className="bg-black/30 p-3 rounded border border-red-500/20">
                                    <div className="flex justify-between items-start mb-2">
                                      <span className="font-bold text-red-300">{cve.id}</span>
                                      <div className="flex space-x-2">
                                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                                          cve.severity === 'CRITICAL' ? 'bg-red-600 text-white' :
                                          cve.severity === 'HIGH' ? 'bg-orange-600 text-white' :
                                          cve.severity === 'MEDIUM' ? 'bg-yellow-600 text-white' :
                                          'bg-green-600 text-white'
                                        }`}>
                                          {cve.severity}
                                        </span>
                                        <span className="px-2 py-1 bg-gray-600 text-white rounded text-xs">
                                          {cve.score}
                                        </span>
                                      </div>
                                    </div>
                                    <p className="text-sm text-gray-300">{cve.description}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Exploits Panel */}
              {activePanel === 'exploits' && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold text-white mb-4">💥 Available Exploits</h3>
                  
                  {state.exploitResults.length === 0 ? (
                    <div className="text-center py-12">
                      <div className="text-6xl mb-4">💥</div>
                      <p className="text-gray-400">Run exploit search to see available exploits.</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {state.exploitResults.map((service, serviceIndex) => (
                        service.exploits && service.exploits.length > 0 && (
                          <div key={serviceIndex} className="bg-gray-800/50 border border-gray-600 rounded-lg p-4">
                            <h4 className="font-bold text-orange-400 mb-3">
                              Port {service.port} - {service.service} ({service.exploits.length} exploits)
                            </h4>
                            <div className="grid gap-3">
                              {(expandedExploits.includes(`${service.port}-${service.service}`) 
                                ? service.exploits 
                                : service.exploits.slice(0, 3)
                              ).map((exploit: any, exploitIndex: number) => (
                                <div key={exploitIndex} className="bg-black/30 p-3 rounded border border-orange-500/20">
                                  <div className="flex justify-between items-start mb-2">
                                    <h5 className="font-medium text-orange-300">{exploit.Title}</h5>
                                    <div className="flex gap-2">
                                      <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">
                                        {exploit.Platform}
                                      </span>
                                      <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                                        {exploit.Type}
                                      </span>
                                    </div>
                                  </div>
                                  <p className="text-sm text-gray-300 mb-2">{exploit.Description}</p>
                                  {exploit.Date && (
                                    <p className="text-xs text-gray-500">Published: {exploit.Date}</p>
                                  )}
                                </div>
                              ))}
                              
                              {service.exploits.length > 3 && (
                                <button
                                  onClick={() => {
                                    const serviceKey = `${service.port}-${service.service}`;
                                    setExpandedExploits(prev => 
                                      prev.includes(serviceKey) 
                                        ? prev.filter(key => key !== serviceKey)
                                        : [...prev, serviceKey]
                                    );
                                  }}
                                  className="mt-2 px-4 py-2 bg-orange-500/20 text-orange-400 rounded-lg hover:bg-orange-500/30 transition-all duration-200 font-medium text-sm"
                                >
                                  {expandedExploits.includes(`${service.port}-${service.service}`) 
                                    ? `🔼 Show Less` 
                                    : `🔽 Show ${service.exploits.length - 3} More Exploits`
                                  }
                                </button>
                              )}
                            </div>
                          </div>
                        )
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* AI Recommendations Panel */}
              {activePanel === 'ai' && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold text-white mb-4">🤖 AI-Powered Metasploit Recommendations</h3>
                  
                  {state.aiRecommendations.length === 0 ? (
                    <div className="text-center py-12">
                      <div className="text-6xl mb-4">🤖</div>
                      <p className="text-gray-400">Run AI analysis to get Metasploit module recommendations.</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {state.aiRecommendations.map((recommendation, index) => (
                        <div key={index} className="bg-gradient-to-r from-red-900/20 to-orange-900/20 border border-red-500/30 rounded-lg p-4">
                          
                          {/* Recommendation Header */}
                          <div className="flex items-start justify-between mb-4">
                            <div className="flex items-center space-x-3">
                              <span className="text-3xl">🎯</span>
                              <div>
                                <h4 className="font-bold text-red-400 text-lg">
                                  Metasploit Recommendation #{index + 1}
                                </h4>
                                <p className="text-sm text-gray-400">
                                  {recommendation.exploit?.Title || 'Exploit Module'}
                                </p>
                              </div>
                            </div>
                            <div className="flex space-x-2">
                              <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-xs font-medium">
                                Metasploit
                              </span>
                              <span className="px-3 py-1 bg-orange-500/20 text-orange-400 rounded-full text-xs font-medium">
                                AI Generated
                              </span>
                            </div>
                          </div>

                          {/* Target Service Info */}
                          <div className="bg-black/30 p-4 rounded-lg mb-4">
                            <h5 className="font-semibold text-blue-300 mb-3 flex items-center">
                              <span className="mr-2">🎯</span>
                              Target Service Details
                            </h5>
                            <div className="grid grid-cols-2 gap-4 text-sm">
                              <div>
                                <span className="text-gray-400">Host:</span>
                                <span className="ml-2 text-blue-400 font-mono">{recommendation.exploit_data?.host}</span>
                              </div>
                              <div>
                                <span className="text-gray-400">Port:</span>
                                <span className="ml-2 text-blue-400 font-mono">{recommendation.exploit_data?.port}</span>
                              </div>
                              <div>
                                <span className="text-gray-400">Service:</span>
                                <span className="ml-2 text-green-400 font-mono">{recommendation.exploit_data?.service}</span>
                              </div>
                              <div>
                                <span className="text-gray-400">Product:</span>
                                <span className="ml-2 text-yellow-400 font-mono">{recommendation.exploit_data?.product}</span>
                              </div>
                            </div>
                          </div>

                          {/* Metasploit Module Details */}
                          {recommendation.ai_suggestion && (
                            <div className="bg-red-900/20 p-4 rounded-lg mb-4">
                              <h5 className="font-semibold text-red-300 mb-3 flex items-center">
                                <span className="mr-2">⚔️</span>
                                Metasploit Module: {recommendation.ai_suggestion.exploit_module}
                              </h5>
                              
                              {/* Required Options */}
                              {recommendation.ai_suggestion.required_options && (
                                <div className="mb-4">
                                  <h6 className="text-orange-400 font-medium mb-2">Required Options:</h6>
                                  <div className="bg-black/30 p-3 rounded border border-red-500/20">
                                    {Object.entries(recommendation.ai_suggestion.required_options).map(([key, value]) => (
                                      <div key={key} className="flex justify-between py-1">
                                        <span className="text-gray-300 font-mono">{key}:</span>
                                        <span className="text-cyan-400 font-mono">{String(value)}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Payload */}
                              {recommendation.ai_suggestion.payload && (
                                <div className="mb-4">
                                  <h6 className="text-orange-400 font-medium mb-2">Recommended Payload:</h6>
                                  <div className="bg-black/30 p-3 rounded border border-red-500/20">
                                    <span className="text-purple-400 font-mono">{recommendation.ai_suggestion.payload}</span>
                                  </div>
                                </div>
                              )}

                              {/* Metasploit Commands */}
                              {recommendation.ai_suggestion.commands && (
                                <div>
                                  <h6 className="text-orange-400 font-medium mb-2">Execute in msfconsole:</h6>
                                  <div className="bg-black rounded border border-red-500/20">
                                    <div className="flex items-center justify-between bg-gray-900/50 px-3 py-2 border-b border-red-500/20">
                                      <span className="text-red-400 font-mono text-sm">msfconsole</span>
                                      <button
                                        onClick={() => {
                                          const commands = recommendation.ai_suggestion.commands.join('\n');
                                          navigator.clipboard.writeText(commands);
                                          addLog('success', '📋 Commands copied to clipboard', 'system');
                                        }}
                                        className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs hover:bg-red-500/30 transition-colors"
                                      >
                                        📋 Copy
                                      </button>
                                    </div>
                                    <div className="p-3 font-mono text-sm">
                                      {recommendation.ai_suggestion.commands.map((command: string, cmdIndex: number) => (
                                        <div key={cmdIndex} className="text-green-400 mb-1">
                                          <span className="text-red-500">msf6 &gt; </span>
                                          <span>{command}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              )}

                              {/* Error Display */}
                              {recommendation.ai_suggestion.error && (
                                <div className="mt-3 p-3 bg-red-500/10 border border-red-500/30 rounded">
                                  <span className="text-red-400 text-sm">⚠️ {recommendation.ai_suggestion.error}</span>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Original Exploit Details */}
                          <div className="bg-gray-800/30 p-3 rounded-lg">
                            <h6 className="text-gray-300 font-medium mb-2">📋 Original Exploit Info:</h6>
                            <p className="text-sm text-gray-400">{recommendation.exploit?.Description}</p>
                            <div className="flex gap-2 mt-2">
                              <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">
                                {recommendation.exploit?.Platform}
                              </span>
                              <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                                {recommendation.exploit?.Type}
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Console Panel */}
              {activePanel === 'console' && (
                <div className="h-full flex flex-col">
                  <div className="flex justify-between items-center mb-4">
                    <h3 className="text-xl font-bold text-white">📟 Live Console</h3>
                    <button
                      onClick={() => setLogs([])}
                      className="px-3 py-1 bg-gray-600 text-white rounded hover:bg-gray-700 transition-colors text-sm"
                    >
                      Clear
                    </button>
                  </div>
                  
                  <div className="flex-1 bg-black rounded-lg p-4 font-mono text-sm overflow-y-auto">
                    {logs.length === 0 ? (
                      <div className="text-gray-500">Console ready... Start a scan to see live output.</div>
                    ) : (
                      <div className="space-y-1">
                        {logs.map((log, index) => (
                          <div key={index} className={`${getLogColor(log.level)} flex`}>
                            <span className="text-gray-500 mr-2">[{log.timestamp}]</span>
                            <span className="mr-2">{getLogIcon(log.category)}</span>
                            <span>{log.message}</span>
                          </div>
                        ))}
                        <div ref={logEndRef} />
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Report Panel */}
              {activePanel === 'report' && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold text-white mb-4">📋 Vulnerability Report</h3>
                  
                  {!state.generatedReport ? (
                    <div className="text-center py-12">
                      <div className="text-6xl mb-4">📋</div>
                      <p className="text-gray-400">Generate a comprehensive vulnerability report.</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* Report Actions */}
                      <div className="flex flex-wrap gap-4 mb-6">
                        <button
                          onClick={() => downloadReport('markdown')}
                          className="px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-lg hover:from-blue-700 hover:to-cyan-700 font-medium transition-all duration-200 flex items-center space-x-2"
                        >
                          <span>�</span>
                          <span>Download Markdown</span>
                        </button>
                        
                        <button
                          onClick={() => downloadReport('pdf')}
                          className="px-6 py-3 bg-gradient-to-r from-red-600 to-pink-600 text-white rounded-lg hover:from-red-700 hover:to-pink-700 font-medium transition-all duration-200 flex items-center space-x-2"
                        >
                          <span>📋</span>
                          <span>Download PDF</span>
                        </button>
                        
                        <button
                          onClick={() => {
                            if (!state.generatedReport?.html) {
                              alert('HTML report not available');
                              return;
                            }
                            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('.')[0];
                            const baseFilename = `VulneraMind_Report_${state.selectedHost}_${timestamp}`;
                            const blob = new Blob([state.generatedReport.html], { type: 'text/html' });
                            const url = URL.createObjectURL(blob);
                            const link = document.createElement('a');
                            link.href = url;
                            link.download = `${baseFilename}.html`;
                            document.body.appendChild(link);
                            link.click();
                            document.body.removeChild(link);
                            URL.revokeObjectURL(url);
                          }}
                          className="px-6 py-3 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-lg hover:from-green-700 hover:to-emerald-700 font-medium transition-all duration-200 flex items-center space-x-2"
                        >
                          <span>🎨</span>
                          <span>Download HTML</span>
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
                                      body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #1a1a1a; color: #e5e5e5; }
                                      h1, h2, h3 { color: #8b5cf6; }
                                      .metadata { background: #2d2d2d; padding: 15px; border-radius: 8px; margin: 20px 0; }
                                      pre { background: #1e1e1e; padding: 15px; border-radius: 8px; overflow-x: auto; color: #e5e5e5; }
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
                          className="px-6 py-3 bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-lg hover:from-purple-700 hover:to-indigo-700 font-medium transition-all duration-200 flex items-center space-x-2"
                        >
                          <span>👁️</span>
                          <span>Preview Report</span>
                        </button>
                      </div>

                      {/* Report Summary */}
                      <div className="bg-gray-800/50 border border-gray-600 rounded-lg p-6">
                        <h4 className="font-bold text-green-400 mb-4">Report Summary</h4>
                        <div className="grid grid-cols-2 gap-4 mb-4">
                          <div className="bg-black/30 p-3 rounded">
                            <div className="text-2xl font-bold text-blue-400">
                              {state.generatedReport.metadata?.total_vulnerabilities || 0}
                            </div>
                            <div className="text-sm text-gray-400">Total Vulnerabilities</div>
                          </div>
                          <div className="bg-black/30 p-3 rounded">
                            <div className="text-2xl font-bold text-purple-400">
                              {state.generatedReport.metadata?.total_services || 0}
                            </div>
                            <div className="text-sm text-gray-400">Services Scanned</div>
                          </div>
                        </div>
                        
                        <div className="bg-black/30 p-4 rounded">
                          <h5 className="font-semibold text-gray-300 mb-2">Executive Summary Preview</h5>
                          <div className="text-sm text-gray-400 max-h-96 overflow-y-auto">
                            {state.generatedReport.report?.executive_summary || 'No summary available'}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4 mb-6">
            <div className="flex items-center">
              <span className="text-red-400 mr-2">❌</span>
              <span className="text-red-300">{error}</span>
            </div>
          </div>
        )}

        {/* Host Discovery Results */}
        {state.step === 'discover' && state.hosts.length > 0 && (
          <div className="bg-black/40 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
            <h2 className="text-xl font-bold text-white mb-4">📡 Discovered Hosts ({state.hosts.length})</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {state.hosts.map((host) => (
                <button
                  key={host}
                  onClick={() => handleHostSelect(host)}
                  disabled={loading}
                  className="p-4 bg-gray-800/50 border border-gray-600 rounded-lg hover:border-purple-500/50 hover:bg-gray-700/50 transition-all duration-200 text-left disabled:opacity-50"
                >
                  <div className="font-medium text-white">{host}</div>
                  <div className="text-sm text-gray-400">Click to scan</div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
