'use client';

import { useState } from 'react';
import { discoverHosts, scanHost, clearLogs, addLog } from '@/lib/scan';

interface ScanFormProps {
  onHosts: (hosts: string[]) => void;
  onScanResult?: (result: any) => void;
}

export default function ScanForm({ onHosts, onScanResult }: ScanFormProps) {
  const [subnet, setSubnet] = useState('10.7.160.0/23');
  const [loading, setLoading] = useState(false);

  const handleDiscover = async () => {
    try {
      setLoading(true);
      clearLogs(); // clear logs before starting
      addLog(`🔍 Discovering hosts in ${subnet}...`);
      const hosts = await discoverHosts(subnet);
      addLog(`✅ Found ${hosts.length} live hosts.`);
      onHosts(hosts); // send to parent
    } catch (err) {
      addLog(`❌ Discovery error: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const handleScanSingle = async () => {
    try {
      setLoading(true);
      clearLogs(); // clear logs before scan
      addLog(`🚀 Starting scan for ${subnet}...`);
      const result = await scanHost(subnet); // uses shared log system
      if (onScanResult) onScanResult(result[0]); // send to parent
      addLog(`✅ Scan completed.`);
    } catch (err) {
      addLog(`❌ Scan error: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded shadow p-4 max-w-4xl mx-auto my-4">
      <h2 className="text-xl font-bold mb-4 text-black">🔧 Scan Setup</h2>
      <input
        type="text"
        placeholder="e.g. 192.168.1.0/24 or 10.7.160.113"
        className="w-full p-2 border rounded mb-4 text-black"
        value={subnet}
        onChange={(e) => setSubnet(e.target.value)}
      />
      <div className="space-x-2">
        <button
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
          onClick={handleDiscover}
          disabled={loading}
        >
          {loading ? 'Discovering...' : 'Discover Hosts'}
        </button>
        <button
          className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700"
          onClick={handleScanSingle}
          disabled={loading}
        >
          {loading ? 'Scanning...' : 'Scan Single Host'}
        </button>
      </div>
    </div>
  );
}
