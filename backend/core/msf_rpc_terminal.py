#!/usr/bin/env python3
"""
Metasploit RPC Terminal - Backend Only Version
Tests the Metasploit RPC connection without frontend complications
"""

import sys
import os
import msgpack
import requests
import urllib3
import json
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Metasploit RPC configuration
MSF_RPC_URL = "https://127.0.0.1:55552/api/"
MSF_HEADERS = {'Content-Type': 'binary/message-pack'}
MSF_USERNAME = "msf"
MSF_PASSWORD = "abc123"

class MetasploitRPCClient:
    def __init__(self):
        self.token = None
        self.console_id = None
        self.connected = False
        self.current_session = None  # Track if we're in a session
    
    def connect(self):
        """Connect to Metasploit RPC API"""
        print("🔌 Connecting to Metasploit RPC...")
        try:
            auth_data = ['auth.login', MSF_USERNAME, MSF_PASSWORD]
            resp = requests.post(
                MSF_RPC_URL,
                data=msgpack.packb(auth_data),
                headers=MSF_HEADERS,
                verify=False,
                timeout=10
            )
            
            unpacker = msgpack.Unpacker()
            unpacker.feed(resp.content)
            for obj in unpacker:
                print(f"DEBUG: Response object: {obj}")
                
                # Handle dictionary response format
                if isinstance(obj, dict):
                    if b'result' in obj and obj[b'result'] == b'success':
                        self.token = obj[b'token'].decode() if isinstance(obj[b'token'], bytes) else obj[b'token']
                        print(f"✅ Connected! Token: {self.token[:10]}...")
                        self.connected = True
                        return self.create_console()
                    elif 'result' in obj and obj['result'] == 'success':
                        self.token = obj['token'].decode() if isinstance(obj['token'], bytes) else obj['token']
                        print(f"✅ Connected! Token: {self.token[:10]}...")
                        self.connected = True
                        return self.create_console()
                    else:
                        print(f"❌ Authentication failed: {obj}")
                        return False
                
                # Handle list response format (legacy)
                elif isinstance(obj, list) and len(obj) >= 2:
                    if obj[0] == b'success' or obj[0] == 'success':
                        self.token = obj[1].decode() if isinstance(obj[1], bytes) else obj[1]
                        print(f"✅ Connected! Token: {self.token[:10]}...")
                        self.connected = True
                        return self.create_console()
                    else:
                        print(f"❌ Authentication failed: {obj}")
                        return False
                else:
                    print(f"❌ Unexpected response format: {obj}")
                    return False
        except Exception as e:
            print(f"❌ Connection error: {str(e)}")
            return False
    
    def create_console(self):
        """Create a new console session"""
        print("🖥️ Creating console session...")
        try:
            console_data = ['console.create', self.token]
            resp = requests.post(
                MSF_RPC_URL,
                data=msgpack.packb(console_data),
                headers=MSF_HEADERS,
                verify=False,
                timeout=10
            )
            
            unpacker = msgpack.Unpacker()
            unpacker.feed(resp.content)
            for obj in unpacker:
                print(f"DEBUG: Console response: {obj}")
                
                if isinstance(obj, dict):
                    # Handle byte keys
                    if b'id' in obj:
                        self.console_id = obj[b'id']
                        print(f"✅ Console created! ID: {self.console_id}")
                        return True
                    # Handle string keys  
                    elif 'id' in obj:
                        self.console_id = obj['id']
                        print(f"✅ Console created! ID: {self.console_id}")
                        return True
                    else:
                        print(f"❌ No console ID in response: {obj}")
                        return False
                else:
                    print(f"❌ Unexpected console response format: {obj}")
                    return False
        except Exception as e:
            print(f"❌ Console creation error: {str(e)}")
            return False
    
    def write_command(self, command):
        """Send command to Metasploit console or session"""
        if not self.connected:
            print("❌ Not connected to Metasploit")
            return False
        
        try:
            # If we're in a session, write to session instead of console
            if self.current_session:
                write_data = ['session.shell_write', self.token, self.current_session, command + '\n']
            else:
                if not self.console_id:
                    print("❌ No console ID")
                    return False
                write_data = ['console.write', self.token, self.console_id, command + '\n']
                
            resp = requests.post(
                MSF_RPC_URL,
                data=msgpack.packb(write_data),
                headers=MSF_HEADERS,
                verify=False,
                timeout=10
            )
            return True
        except Exception as e:
            print(f"❌ Command write error: {str(e)}")
            return False
    
    def read_output(self):
        """Read output from Metasploit console or session"""
        if not self.connected:
            return ""
        
        try:
            # If we're in a session, read from session instead of console
            if self.current_session:
                read_data = ['session.shell_read', self.token, self.current_session]
            else:
                read_data = ['console.read', self.token, self.console_id]
                
            resp = requests.post(
                MSF_RPC_URL,
                data=msgpack.packb(read_data),
                headers=MSF_HEADERS,
                verify=False,
                timeout=10
            )
            
            unpacker = msgpack.Unpacker()
            unpacker.feed(resp.content)
            for obj in unpacker:
                if isinstance(obj, dict):
                    if b'data' in obj:
                        data = obj[b'data']
                        if isinstance(data, bytes):
                            return data.decode('utf-8', errors='ignore')
                        return str(data)
                    elif 'data' in obj:
                        data = obj['data']
                        if isinstance(data, bytes):
                            return data.decode('utf-8', errors='ignore')
                        return str(data)
            return ""
        except Exception as e:
            print(f"❌ Read error: {str(e)}")
            return ""
    
    def list_sessions(self):
        """List active sessions"""
        try:
            session_data = ['session.list', self.token]
            resp = requests.post(
                MSF_RPC_URL,
                data=msgpack.packb(session_data),
                headers=MSF_HEADERS,
                verify=False,
                timeout=10
            )
            
            unpacker = msgpack.Unpacker()
            unpacker.feed(resp.content)
            for obj in unpacker:
                return obj
        except Exception as e:
            print(f"❌ Session list error: {str(e)}")
            return {}
    
    def interact_session(self, session_id):
        """Interact with a session"""
        print(f"🎯 Interacting with session {session_id}")
        print("Type 'exit_session' to return to console")
        
        while True:
            try:
                command = input(f"session {session_id} > ").strip()
                
                if command.lower() == 'exit_session':
                    print("👋 Exiting session interaction")
                    break
                
                if not command:
                    continue
                
                # Send command to session
                session_data = ['session.shell_write', self.token, session_id, command + '\n']
                resp = requests.post(
                    MSF_RPC_URL,
                    data=msgpack.packb(session_data),
                    headers=MSF_HEADERS,
                    verify=False,
                    timeout=10
                )
                
                # Wait and read output
                time.sleep(1)
                read_data = ['session.shell_read', self.token, session_id]
                resp = requests.post(
                    MSF_RPC_URL,
                    data=msgpack.packb(read_data),
                    headers=MSF_HEADERS,
                    verify=False,
                    timeout=10
                )
                
                unpacker = msgpack.Unpacker()
                unpacker.feed(resp.content)
                for obj in unpacker:
                    if isinstance(obj, dict):
                        if b'data' in obj:
                            data = obj[b'data']
                            if isinstance(data, bytes):
                                output = data.decode('utf-8', errors='ignore')
                                if output.strip():
                                    print(output, end='')
                        elif 'data' in obj:
                            data = obj['data']
                            if isinstance(data, bytes):
                                output = data.decode('utf-8', errors='ignore')
                                if output.strip():
                                    print(output, end='')
                
            except KeyboardInterrupt:
                print("\n👋 Exiting session interaction")
                break
            except Exception as e:
                print(f"❌ Session error: {str(e)}")

    def test_connection(self):
        """Test basic RPC functionality"""
        print("\n🧪 Testing RPC functionality...")
        
        # Test version command
        print("📝 Testing 'version' command...")
        if self.write_command("version"):
            time.sleep(1)
            output = self.read_output()
            if output:
                print(f"✅ Version output: {output.strip()}")
            else:
                print("❌ No output received")
        
        # Test help command
        print("\n📝 Testing 'help' command...")
        if self.write_command("help"):
            time.sleep(1)
            output = self.read_output()
            if output:
                print(f"✅ Help output (first 200 chars): {output[:200]}...")
            else:
                print("❌ No output received")
        """Test basic RPC functionality"""
        print("\n🧪 Testing RPC functionality...")
        
        # Test version command
        print("📝 Testing 'version' command...")
        if self.write_command("version"):
            time.sleep(1)
            output = self.read_output()
            if output:
                print(f"✅ Version output: {output.strip()}")
            else:
                print("❌ No output received")
        
        # Test help command
        print("\n📝 Testing 'help' command...")
        if self.write_command("help"):
            time.sleep(1)
            output = self.read_output()
            if output:
                print(f"✅ Help output (first 200 chars): {output[:200]}...")
            else:
                print("❌ No output received")

def main():
    print("=" * 60)
    print("🚀 METASPLOIT RPC TERMINAL - Backend Only Version")
    print("=" * 60)
    
    # Check if Metasploit RPC server is needed
    print("\n📋 Prerequisites:")
    print("1. Start msfconsole: cd ~/metasploit-framework && ./msfconsole")
    print("2. Load RPC: load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=abc123 SSL=true")
    print("3. Keep that terminal open")
    print("\nPress Enter when ready to test connection...")
    input()
    
    # Create RPC client
    client = MetasploitRPCClient()
    
    # Test connection
    if not client.connect():
        print("\n❌ Failed to connect to Metasploit RPC")
        print("Make sure:")
        print("1. msfconsole is running")
        print("2. RPC server is loaded with correct settings")
        print("3. Port 55552 is accessible")
        return False
    
    # Test basic functionality
    client.test_connection()
    
    # Interactive mode
    print("\n" + "=" * 60)
    print("🎯 INTERACTIVE METASPLOIT RPC TERMINAL")
    print("=" * 60)
    print("Type commands (or 'quit' to exit):")
    
    while True:
        try:
            command = input("\nmsf6 > ").strip()
            
            if command.lower() in ['quit', 'exit', 'q']:
                print("👋 Goodbye!")
                break
            
            # Check for session commands
            if command.lower() == 'sessions':
                sessions = client.list_sessions()
                print("Active sessions:")
                if sessions:
                    for session_id, session_info in sessions.items():
                        print(f"  {session_id}: {session_info}")
                else:
                    print("  No active sessions")
                continue
            
            if command.lower().startswith('sessions ') and not command.lower().startswith('sessions -i'):
                # Handle "sessions 2" - set current session
                try:
                    session_id = command.split()[-1]
                    client.current_session = session_id
                    print(f"✅ Now interacting with session {session_id}")
                    continue
                except:
                    print("❌ Invalid session ID")
                    continue
            
            if command.lower().startswith('sessions -i '):
                try:
                    session_id = command.split()[-1]
                    client.interact_session(session_id)
                    continue
                except:
                    print("❌ Invalid session ID")
                    continue
            
            if not command:
                continue
            
            # Send command
            print(f"DEBUG: Sending command: {command}")
            if client.write_command(command):
                # Wait for output - some commands need more time
                time.sleep(1)
                output = client.read_output()
                print(f"DEBUG: Raw output: '{output}'")
                print(f"DEBUG: Output length: {len(output)}")
                
                # Try reading multiple times if no output
                if not output.strip():
                    print("DEBUG: No output, trying to read again...")
                    for i in range(3):
                        time.sleep(1)
                        output = client.read_output()
                        print(f"DEBUG: Attempt {i+1}: '{output}'")
                        if output.strip():
                            break
                
                if output.strip():
                    print(output, end='')
                else:
                    # For silent commands like 'use', check if they worked by getting prompt
                    if command.startswith('use '):
                        print("DEBUG: Detected 'use' command, trying 'info'...")
                        # Send a command that shows current module
                        if client.write_command('info'):
                            time.sleep(2)
                            info_output = client.read_output()
                            print(f"DEBUG: Info output: '{info_output}'")
                            if info_output.strip():
                                print(f"✅ Module loaded successfully:")
                                print(info_output, end='')
                            else:
                                print(f"❌ No info output - module may not have loaded")
                        else:
                            print(f"❌ Failed to send info command")
                    else:
                        print(f"❌ Command executed but no output received")
            else:
                print(f"❌ Failed to send command: {command}")
                
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")

if __name__ == "__main__":
    main()
