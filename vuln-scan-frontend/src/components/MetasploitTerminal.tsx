'use client';

import { useEffect, useRef, useState } from 'react';

// Dynamic imports to avoid SSR issues
let Terminal: any = null;
let FitAddon: any = null;

interface MetasploitTerminalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function MetasploitTerminal({ isOpen, onClose }: MetasploitTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [terminal, setTerminal] = useState<any>(null);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isLoaded, setIsLoaded] = useState(false);
  const fitAddon = useRef<any>(null);

  // Load xterm dynamically
  useEffect(() => {
    if (typeof window !== 'undefined' && !Terminal) {
      import('@xterm/xterm').then((xtermModule) => {
        Terminal = xtermModule.Terminal;
        return import('@xterm/addon-fit');
      }).then((fitModule) => {
        FitAddon = fitModule.FitAddon;
        setIsLoaded(true);
      }).catch((error) => {
        console.error('Failed to load xterm:', error);
      });
    }
  }, []);

  useEffect(() => {
    if (isOpen && terminalRef.current && !terminal && isLoaded && Terminal && FitAddon) {
      // Create terminal
      const term = new Terminal({
        cursorBlink: true,
        theme: {
          background: '#000000',
          foreground: '#ffffff',
          cursor: '#ffffff',
          selection: '#ffffff40'
        },
        fontSize: 14,
        fontFamily: 'Monaco, Menlo, "Ubuntu Mono", monospace'
      });

      // Create fit addon
      const fit = new FitAddon();
      fitAddon.current = fit;
      term.loadAddon(fit);

      // Open terminal
      term.open(terminalRef.current);
      fit.fit();

      setTerminal(term);

      // Connect to backend
      connectToMetasploit(term);

      // Handle input
      term.onData((data: string) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ input: data }));
        }
      });
    }

    return () => {
      if (terminal) {
        terminal.dispose();
        setTerminal(null);
      }
      if (ws) {
        ws.close();
        setWs(null);
      }
    };
  }, [isOpen, isLoaded]);

  const connectToMetasploit = async (term: any) => {
    setIsConnecting(true);
    
    try {
      // First, ensure Metasploit RPC connection
      term.write('Connecting to Metasploit RPC...\r\n');
      
      const response = await fetch('http://localhost:8000/msf-connect', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        term.write('❌ Failed to connect to Metasploit RPC\r\n');
        setIsConnecting(false);
        return;
      }

      term.write('✅ Connected to Metasploit RPC\r\n');
      term.write('Opening terminal session...\r\n');

      // Connect WebSocket
      const websocket = new WebSocket('ws://localhost:8000/ws/metasploit');
      
      websocket.onopen = () => {
        term.write('✅ Terminal session established\r\n');
        setIsConnected(true);
        setIsConnecting(false);
        setWs(websocket);
      };

      websocket.onmessage = (event) => {
        term.write(event.data);
      };

      websocket.onclose = () => {
        term.write('\r\n❌ Connection to Metasploit lost\r\n');
        setIsConnected(false);
        setWs(null);
      };

      websocket.onerror = (error) => {
        term.write('❌ WebSocket error\r\n');
        setIsConnected(false);
        setIsConnecting(false);
      };

    } catch (error) {
      term.write(`❌ Error: ${error}\r\n`);
      setIsConnecting(false);
    }
  };

  const handleResize = () => {
    if (fitAddon.current) {
      fitAddon.current.fit();
    }
  };

  useEffect(() => {
    if (isOpen) {
      window.addEventListener('resize', handleResize);
      return () => window.removeEventListener('resize', handleResize);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  if (!isLoaded) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-black border border-gray-600 rounded-lg w-5/6 h-5/6 flex items-center justify-center">
          <div className="text-white">Loading Metasploit Terminal...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-black border border-gray-600 rounded-lg w-5/6 h-5/6 flex flex-col">
        {/* Header */}
        <div className="bg-gray-800 px-4 py-2 rounded-t-lg flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <div className="text-green-400 text-sm font-mono">◉</div>
            <span className="text-white font-medium">Metasploit Console</span>
            <div className={`text-xs px-2 py-1 rounded ${
              isConnected ? 'bg-green-600 text-white' : 
              isConnecting ? 'bg-yellow-600 text-white' : 
              'bg-red-600 text-white'
            }`}>
              {isConnected ? 'Connected' : isConnecting ? 'Connecting...' : 'Disconnected'}
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Terminal */}
        <div className="flex-1 p-2">
          <div
            ref={terminalRef}
            className="w-full h-full"
            style={{
              height: '100%',
              width: '100%'
            }}
          />
        </div>

        {/* Footer */}
        <div className="bg-gray-800 px-4 py-2 rounded-b-lg">
          <div className="text-xs text-gray-400">
            Press Ctrl+C to interrupt • Type 'help' for commands • 'exit' to close session
          </div>
        </div>
      </div>
    </div>
  );
}
