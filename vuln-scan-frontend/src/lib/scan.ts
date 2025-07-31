let logCallback: (line: string) => void = () => {};

// Allows frontend component to register its log handler
export function setLogHandler(cb: (line: string) => void) {
  logCallback = cb;
}

// Send signal to clear logs in frontend
export function clearLogs() {
  if (!logCallback) return;
  logCallback('[Log cleared]');
  logCallback('__CLEAR__'); // Custom signal to wipe frontend log list
}

// Format frontend log messages with timestamp
export function addLog(message: string) {
  if (!logCallback) return;
  logCallback(`[${new Date().toLocaleTimeString()}] ${message}`);
}

// Direct backend logs passthrough (they're already formatted)
export function addBackendLog(message: string) {
  if (!logCallback) return;
  logCallback(message);
}

// Host discovery API call
export async function discoverHosts(subnet: string) {
  clearLogs(); // Clear before discovery (instant is fine here)
  addLog(`Discovering hosts in ${subnet}...`);

  const res = await fetch('http://localhost:8000/discover', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: subnet }),
  });

  if (!res.ok) throw new Error('Host discovery failed.');

  const data = await res.json();
  addLog(`Found ${data.length} live hosts.`);
  return data;
}

// Scan a specific host and collect results + backend logs
export async function scanHost(target: string) {
  // ✅ Delay log clearing slightly so ScanLog can mount and set logCallback
  setTimeout(() => clearLogs(), 100);

  addLog(`Starting scan for ${target}...`);

  const res = await fetch('http://localhost:8000/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  });

  if (!res.ok) {
    addLog(`Scan failed for ${target}`);
    throw new Error('Scan failed.');
  }

  const { results, logs } = await res.json();

console.log('🔥 Backend Logs Received:', logs); // Add this


  // ✅ Append backend logs
  if (logs && logs.length > 0) {
    logs.forEach((line: string) => addBackendLog(line));
  }

  addLog(
    `Scan complete for ${target}. Found ${
      results[0]?.open_ports?.length ?? 0
    } open ports.`
  );

  return results;
}
