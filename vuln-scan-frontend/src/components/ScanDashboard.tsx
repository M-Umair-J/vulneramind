'use client';

import { useState } from 'react';

interface ScanDashboardProps {
  data: any[];
}

export default function ScanDashboard({ data }: ScanDashboardProps) {
  const [selectedHostData, setSelectedHostData] = useState<any | null>(null);

  const openDetails = (entry: any) => {
    const result = entry.result?.[0] || entry;
    setSelectedHostData(result);
  };

  const closeModal = () => {
    setSelectedHostData(null);
  };

  return (
    <div className="max-w-5xl mx-auto mt-6 bg-white rounded shadow p-4">
      <h2 className="text-xl font-bold mb-4 text-black">🧠 Scan Results</h2>

      {data.map((entry, index) => {
        const result = entry.result?.[0] || entry;
        return (
          <div key={index} className="border-b border-gray-300 py-2 flex justify-between items-center">
            <span className="text-lg text-black font-semibold">{result.host}</span>
            <button
              className="text-blue-600 hover:underline"
              onClick={() => openDetails(entry)}
            >
              Show Details
            </button>
          </div>
        );
      })}

      {/* 🔽 Modal Popup */}
      {selectedHostData && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white w-full max-w-2xl max-h-[80vh] overflow-y-auto p-6 rounded-lg shadow-lg relative">
            {/* Close Button */}
            <button
              onClick={closeModal}
              className="absolute top-3 right-4 text-gray-600 text-2xl hover:text-black"
              aria-label="Close"
            >
              &times;
            </button>

            <h3 className="text-2xl font-bold mb-4 text-black">
              🔍 Details for {selectedHostData.host}
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

            {/* Services + CVEs */}
            <div>
              <h4 className="font-semibold text-gray-800 mb-1">🛡️ Services & CVEs</h4>
              {selectedHostData.services?.length > 0 ? (
                <ul className="space-y-3 text-sm text-black">
                  {selectedHostData.services.map((srv: any, idx: number) => (
                    <li key={idx} className="bg-gray-100 border rounded p-3">
                      <p><strong>Port:</strong> {srv.port} ({srv.protocol})</p>
                      <p><strong>Service:</strong> {srv.service}</p>
                      <p><strong>Product:</strong> {srv.product}</p>
                      <p><strong>Version:</strong> {srv.version}</p>
                      <p><strong>CVEs:</strong> {srv.cve_ids?.join(', ') || 'None'}</p>

                      {/* Exploit placeholder */}
                      <div className="mt-2 text-gray-500 italic">
                        Exploit info will appear here...
                      </div>
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
    </div>
  );
}
