'use client';

import { useState, useEffect, useRef } from 'react';

interface SimpleTerminalProps {
  isOpen: boolean;
  onClose: () => void;
  exploitCommands?: any;
}

export default function SimpleTerminal({ isOpen, onClose, exploitCommands }: SimpleTerminalProps) {
  const [output, setOutput] = useState<string[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [wslStatus, setWslStatus] = useState<any>(null);
  const [currentCommand, setCurrentCommand] = useState('');
  const [isMetasploitReady, setIsMetasploitReady] = useState(false);
  const outputRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  useEffect(() => {
    if (isOpen) {
      checkWslStatus();
    }
  }, [isOpen]);

  useEffect(() => {
    if (isOpen && inputRef.current && isMetasploitReady) {
      inputRef.current.focus();
    }
  }, [isOpen, isMetasploitReady]);

  const addOutput = (text: string) => {
    setOutput(prev => [...prev, text]);
  };

  const checkWslStatus = async () => {
    try {
      const response = await fetch('http://localhost:8000/check-wsl-status');
      const status = await response.json();
      setWslStatus(status);
      
      if (!status.wsl_available) {
        addOutput(`❌ WSL Error: ${status.error}`);
      } else {
        addOutput('✅ WSL is available');
        if (!status.metasploit_directory_exists) {
          addOutput('⚠️ Metasploit directory not found at ~/metasploit-framework');
        } else {
          addOutput('✅ Metasploit directory found');
        }
        if (status.msfconsole_available) {
          addOutput(`✅ msfconsole available at: ${status.metasploit_path}`);
        } else {
          addOutput('⚠️ msfconsole not found in PATH');
        }
      }
    } catch (error) {
      addOutput(`❌ Failed to check WSL status: ${error}`);
    }
  };

  const executeCommand = async (command: string) => {
    if (!command.trim()) return;
    
    setIsExecuting(true);
    addOutput(`msf6 {'>'} ${command}`);
    
    try {
      const response = await fetch('http://localhost:8000/execute-wsl-command', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ command }),
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        addOutput(`❌ Error: ${errorData.detail || 'Command execution failed'}`);
      } else {
        const result = await response.json();
        if (result.output) {
          addOutput(result.output);
        }
        if (result.is_interactive) {
          addOutput('msf6 {'>'} ');
        }
      }
    } catch (error) {
      addOutput(`❌ Error: ${error}`);
    } finally {
      setIsExecuting(false);
      addOutput('msf6 {'>'} ');
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isExecuting) {
      executeCommand(currentCommand);
      setCurrentCommand('');
    }
  };

  const spawnMetasploit = async () => {
    addOutput('🚀 Spawning Metasploit Framework...');
    
    // Check if metasploit directory exists first
    await executeCommand('ls -la ~/metasploit-framework');
    
    // Try to change directory
    await executeCommand('cd ~/metasploit-framework');
    
    // Check if msfconsole exists
    await executeCommand('ls -la msfconsole');
    
    // Try to run msfconsole
    await executeCommand('./msfconsole');
    
    // Set metasploit as ready
    setIsMetasploitReady(true);
    addOutput('msf6 {'>'} ');
  };

  const executeExploitCommands = async () => {
    if (!exploitCommands?.commands) return;
    
    addOutput('🎯 Executing exploit commands...');
    for (const command of exploitCommands.commands) {
      await executeCommand(command);
      // Small delay between commands
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
      <div className="bg-black text-green-400 w-full max-w-4xl h-[80vh] rounded-lg shadow-2xl flex flex-col">
        {/* Header */}
        <div className="bg-gray-800 px-4 py-2 rounded-t-lg flex justify-between items-center">
          <span className="text-white font-mono">WSL Terminal - Metasploit</span>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-xl">×</button>
        </div>

        {/* Output Display */}
        <div className="flex-1 p-4 overflow-hidden">
          <div 
            ref={outputRef}
            className="h-full overflow-y-auto font-mono text-sm space-y-1 bg-black"
          >
            {output.map((line, index) => (
              <div key={index} className="whitespace-pre-wrap">
                {line}
              </div>
            ))}
            
            {/* Command Input Line */}
            <div className="flex items-center">
              <span className="text-green-400 mr-2">msf6 {'>'} </span>
              <input
                ref={inputRef}
                type="text"
                value={currentCommand}
                onChange={(e) => setCurrentCommand(e.target.value)}
                onKeyPress={handleKeyPress}
                className="flex-1 bg-transparent text-green-400 outline-none border-none font-mono"
                placeholder={isExecuting ? 'Executing...' : 'Type Metasploit command here...'}
                disabled={isExecuting || !isMetasploitReady}
              />
            </div>
            
            {isExecuting && (
              <div className="text-yellow-400">Executing...</div>
            )}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="bg-gray-800 px-4 py-2 rounded-b-lg flex gap-2">
          <button
            onClick={checkWslStatus}
            disabled={isExecuting}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 font-mono text-sm disabled:opacity-50"
          >
            🔍 Check WSL
          </button>
          
          <button
            onClick={spawnMetasploit}
            disabled={isExecuting}
            className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 font-mono text-sm disabled:opacity-50"
          >
            🚀 Spawn Metasploit
          </button>
          
          {exploitCommands && (
            <button
              onClick={executeExploitCommands}
              disabled={isExecuting}
              className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 font-mono text-sm disabled:opacity-50"
            >
              🎯 Execute Exploit
            </button>
          )}
          
          <button
            onClick={() => setOutput([])}
            className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700 font-mono text-sm"
          >
            Clear
          </button>
        </div>
      </div>
    </div>
  );
}
