'use client';

import { useEffect, useRef, useState } from 'react';

export default function ScanLog() {
  const [logs, setLogs] = useState<string[]>([]);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const es = new EventSource('http://localhost:8000/log-stream');

    es.onmessage = (event) => {
      const line = event.data;
      setLogs((prev) => [...prev.slice(-100), line]);
    };

    es.onerror = (err) => {
      console.error('❌ Log stream error:', err);
      es.close();
    };

    return () => es.close();
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="p-4 max-w-5xl mx-auto mt-6 bg-black text-green-400 font-mono text-sm rounded shadow">
      <h3 className="mb-2 text-white">Scan Logs</h3>
      <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
        {logs.map((line, idx) => (
          <div key={idx}>{line}</div>
        ))}
        <div ref={logEndRef} />
      </div>
    </div>
  );
}
