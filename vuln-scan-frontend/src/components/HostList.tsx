'use client';
import { scanHost, clearLogs } from '@/lib/scan';
import { useState } from 'react';

export default function HostList({
  hosts,
  onScanResult,
}: {
  hosts: string[];
  onScanResult: (result: any) => void;
}) {
  const [scanning, setScanning] = useState<string | null>(null);

  const handleScan = async (host: string) => {
    clearLogs(); // Clear logs before scanning new host
    setScanning(host);
    try {
      const result = await scanHost(host);
      onScanResult({ host, result });
    } catch (e) {
      alert(`Scan failed for ${host}`);
    } finally {
      setScanning(null);
    }
  };

  return (
    <div className="p-4 max-w-2xl mx-auto">
      <h3 className="text-lg font-bold mb-2 text-black">Live Hosts</h3>
      <ul className="space-y-2">
        {hosts.map((host) => (
          <li key={host} className="flex justify-between items-center border p-2 rounded bg-white">
            <span className="text-black">{host}</span>
            <button
              className="bg-green-600 text-white px-3 py-1 rounded hover:bg-green-700"
              onClick={() => handleScan(host)}
              disabled={scanning === host}
            >
              {scanning === host ? 'Scanning...' : 'Scan Host'}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
