'use client';

import { useState, useEffect } from 'react';
import ScanForm from '@/components/ScanForm';
import HostList from '@/components/HostList';
import ScanDashboard from '@/components/ScanDashboard';
import ScanLog from '@/components/ScanLog';
import { setLogHandler } from '@/lib/scan';

export default function Home() {
  const [liveHosts, setLiveHosts] = useState<string[]>([]);
  const [scanData, setScanData] = useState<any[]>([]);
  const [logs, setLogs] = useState<string[]>([]); // Optional: capture logs here too if needed

 

  const handleHostDiscovery = (hosts: string[]) => {
    setLiveHosts(hosts);
    setScanData([]); // clear previous scans
  };

 const handleScanResult = (result: any) => {
  setScanData((prev) => {
    const updated = prev.filter((e) => e.host !== result.host);
    return [...updated, result]; // ✅ don't wrap in result: [...]
  });
};

  return (
    <main className="min-h-screen bg-gray-100 py-6">
      <h1 className="text-center text-3xl font-bold text-black">🔍 Vulnerability Scanner Dashboard</h1>

      <ScanForm onHosts={handleHostDiscovery} onScanResult={handleScanResult} />  
      {liveHosts.length > 0 && <HostList hosts={liveHosts} onScanResult={handleScanResult} />}
      {scanData.length > 0 && <ScanDashboard data={scanData} />}
      <ScanLog />
    </main>
  );
}
