#!/usr/bin/env python3
"""
Local AI System using Ollama
Replaces unreliable cloud APIs with local models for exploit analysis and report generation
"""

import ollama
import json
from typing import Dict, Any, List
from datetime import datetime
import re


class LocalAISystem:
    """Local AI system using Ollama for cybersecurity analysis"""
    
    def __init__(self):
        self.exploit_model = "codellama:7b-instruct"
        self.report_model = "mistral:7b-instruct"
        self.base_url = "http://127.0.0.1:11434"
        
    def test_connection(self) -> bool:
        """Test if Ollama is running and models are available"""
        try:
            # First test if Ollama is running
            models_response = ollama.list()
            print(f"🔧 Raw response: {models_response}")
            
            # Handle the actual response format from ollama
            available_models = []
            
            # The response has a 'models' attribute with a list of Model objects
            if hasattr(models_response, 'models'):
                models_list = models_response.models
            elif isinstance(models_response, dict) and 'models' in models_response:
                models_list = models_response['models']
            else:
                models_list = []
            
            # Extract model names from Model objects
            for model in models_list:
                if hasattr(model, 'model'):  # Model object with .model attribute
                    model_name = model.model
                elif isinstance(model, dict):
                    model_name = model.get('name', model.get('model', str(model)))
                else:
                    model_name = str(model)
                available_models.append(model_name)
            
            has_exploit_model = any(self.exploit_model in model for model in available_models)
            has_report_model = any(self.report_model in model for model in available_models)
            
            print(f"🤖 Available models: {available_models}")
            print(f"✅ Exploit model ({self.exploit_model}): {has_exploit_model}")
            print(f"✅ Report model ({self.report_model}): {has_report_model}")
            
            return has_exploit_model and has_report_model
        except Exception as e:
            print(f"❌ Ollama connection failed: {e}")
            print(f"❌ Error type: {type(e)}")
            return False

    def generate_metasploit_exploit(self, service_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Metasploit exploit recommendations using CodeLlama"""
        
        service = service_data.get('service', 'unknown')
        product = service_data.get('product', 'unknown')
        version = service_data.get('version', 'unknown')
        port = service_data.get('port', 'unknown')
        host = service_data.get('host', 'unknown')
        
        prompt = f"""You are a cybersecurity expert. Analyze this network service and determine if there are known Metasploit modules for it.

TARGET SERVICE:
Service: {service}
Product: {product} 
Version: {version}
Port: {port}

ANALYSIS STEPS:
1. What type of service is this? (FTP, HTTP, SSH, SMB, etc.)
2. Are there known vulnerabilities for this specific product/version?
3. What would be the appropriate Metasploit module category?

METASPLOIT MODULE CATEGORIES:
- exploit/: Remote code execution vulnerabilities
- auxiliary/scanner/: Information gathering and enumeration  
- auxiliary/dos/: Denial of service attacks
- post/: Post-exploitation modules

CRITICAL THINKING:
- For well-known exploits (like vsftpd 2.3.4 backdoor), suggest the actual exploit module
- If you don't know of a specific exploit, suggest scanner modules for enumeration
- If the service is completely unknown, return MODULE_NOT_AVAILABLE
- Don't make up module names - be conservative but don't be overly cautious about famous exploits

WELL-KNOWN EXPLOITS (these are safe to suggest):
- vsftpd 2.3.4 backdoor → exploit/unix/ftp/vsftpd_234_backdoor
- SSH enumeration → auxiliary/scanner/ssh/ssh_version  
- HTTP enumeration → auxiliary/scanner/http/http_version
- FTP enumeration → auxiliary/scanner/ftp/ftp_version

EXAMPLE ANALYSIS:
Service: ssh, Product: openssh, Version: 8.0
→ This is SSH service. No known RCE exploits for this version.
→ Appropriate response: auxiliary/scanner/ssh/ssh_version for enumeration

Service: ftp, Product: vsftpd, Version: 2.3.4  
→ This is FTP service. vsftpd 2.3.4 has a FAMOUS backdoor vulnerability.
→ Appropriate response: exploit/unix/ftp/vsftpd_234_backdoor (this exploit definitely exists)

Service: unknown-service, Product: unknown, Version: 1.0
→ This is an unknown service with no vulnerability information.
→ Appropriate response: MODULE_NOT_AVAILABLE

Now analyze the target service above and respond with JSON:
{{
    "exploit_module": "specific_module_path_or_MODULE_NOT_AVAILABLE",
    "payload": "appropriate_payload_or_NO_PAYLOAD",
    "vulnerability_type": "RCE|DOS|INFO_DISCLOSURE|AUTH_BYPASS|OTHER",
    "confidence": "high|medium|low", 
    "reasoning": "step_by_step_analysis_of_your_decision",
    "target_info": {{
        "RHOSTS": "{host}",
        "RPORT": {port}
    }}
}}"""

        try:
            print(f"🤖 Analyzing {service} {product} {version} with local AI...")
            
            response = ollama.chat(
                model=self.exploit_model,
                messages=[{
                    'role': 'user', 
                    'content': prompt
                }],
                options={
                    'temperature': 0.1,  # Low temperature for consistent results
                    'top_p': 0.9,
                    'num_predict': 400   # Slightly longer for better reasoning
                }
            )
            
            content = response['message']['content'].strip()
            
            # Clean up response if it has markdown formatting
            if content.startswith('```json'):
                content = content.replace('```json', '').replace('```', '').strip()
            if content.startswith('```'):
                content = content.replace('```', '').strip()
            
            # Parse JSON response
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                else:
                    raise ValueError("No valid JSON found in response")
            
            # Validate the response
            exploit_module = result.get('exploit_module', 'MODULE_NOT_AVAILABLE')
            payload = result.get('payload', 'NOT_APPLICABLE')
            vuln_type = result.get('vulnerability_type', 'OTHER')
            
            # Basic validation - reject obviously invalid responses
            if "exact_metasploit_module_path_or_MODULE_NOT_AVAILABLE" in exploit_module or "module_name_here" in exploit_module or "specific_module_path_or_MODULE_NOT_AVAILABLE" in exploit_module:
                print(f"⚠️ AI responded with template text: {exploit_module}")
                print(f"🔄 Overriding to MODULE_NOT_AVAILABLE")
                exploit_module = 'MODULE_NOT_AVAILABLE'
                vuln_type = 'OTHER'
                result['reasoning'] = f"AI provided template response instead of actual module"
            
            # Validate module path format
            elif exploit_module != 'MODULE_NOT_AVAILABLE' and not (
                exploit_module.startswith('exploit/') or 
                exploit_module.startswith('auxiliary/') or 
                exploit_module.startswith('post/')
            ):
                print(f"⚠️ AI suggested invalid module format: {exploit_module}")
                print(f"🔄 Overriding to MODULE_NOT_AVAILABLE")
                exploit_module = 'MODULE_NOT_AVAILABLE'
                vuln_type = 'OTHER'
                result['reasoning'] = f"Invalid module path format: {exploit_module}"
            
            # Validate that service type matches suggested module (basic sanity check)
            elif exploit_module != 'MODULE_NOT_AVAILABLE':
                service_lower = service.lower()
                
                # Check for obvious mismatches
                if 'ftp' in exploit_module and service_lower not in ['ftp']:
                    print(f"⚠️ AI suggested FTP module for non-FTP service: {service}")
                    print(f"🔄 Overriding to MODULE_NOT_AVAILABLE")
                    exploit_module = 'MODULE_NOT_AVAILABLE'
                    vuln_type = 'OTHER'
                    result['reasoning'] = f"FTP module suggested for {service} service - mismatch"
                
                elif 'ssh' in exploit_module and service_lower not in ['ssh']:
                    print(f"⚠️ AI suggested SSH module for non-SSH service: {service}")
                    print(f"🔄 Overriding to MODULE_NOT_AVAILABLE")
                    exploit_module = 'MODULE_NOT_AVAILABLE'
                    vuln_type = 'OTHER'
                    result['reasoning'] = f"SSH module suggested for {service} service - mismatch"
                
                elif 'http' in exploit_module and service_lower not in ['http', 'https', 'web']:
                    print(f"⚠️ AI suggested HTTP module for non-HTTP service: {service}")
                    print(f"🔄 Overriding to MODULE_NOT_AVAILABLE")
                    exploit_module = 'MODULE_NOT_AVAILABLE'
                    vuln_type = 'OTHER'
                    result['reasoning'] = f"HTTP module suggested for {service} service - mismatch"
            
            # Handle case where no module is available
            if exploit_module == 'MODULE_NOT_AVAILABLE':
                print(f"⚠️ No specific Metasploit module available for this vulnerability")
                return {
                    "exploit_module": "MODULE_NOT_AVAILABLE",
                    "payload": "NOT_APPLICABLE",
                    "vulnerability_type": vuln_type,
                    "confidence": "high",
                    "reasoning": "No specific Metasploit module exists for this vulnerability type/version combination",
                    "target_info": {
                        "RHOSTS": host,
                        "RPORT": port
                    },
                    "commands": [
                        "# No Metasploit module available for this vulnerability",
                        "# Consider manual exploitation or alternative tools",
                        f"# Target: {host}:{port} ({service} {product} {version})"
                    ],
                    "ai_source": 'local_ollama',
                    "model_used": self.exploit_model
                }
            
            # Build appropriate command sequence based on module type
            commands = []
            
            if exploit_module.startswith('auxiliary/'):
                # Auxiliary modules (DOS, scanners, etc.)
                commands = [
                    f"use {exploit_module}",
                    f"set RHOSTS {host}",
                    f"set RPORT {port}",
                    "run"
                ]
                # Auxiliary modules shouldn't have payloads, but don't warn for expected values
                if payload and payload not in ["NO_PAYLOAD", "NOT_APPLICABLE", "N/A", "", "payload/platform/type OR NO_PAYLOAD OR NOT_APPLICABLE"]:
                    print(f"⚠️ Warning: Auxiliary module shouldn't have payload, but AI suggested: {payload}")
                    
            elif exploit_module.startswith('exploit/'):
                # Exploit modules (RCE, etc.)
                commands = [
                    f"use {exploit_module}",
                    f"set RHOSTS {host}",
                    f"set RPORT {port}"
                ]
                
                if payload and payload != "NO_PAYLOAD" and payload != "NOT_APPLICABLE":
                    commands.append(f"set payload {payload}")
                    commands.extend([
                        "set LHOST YOUR_IP",
                        "set LPORT 4444"
                    ])
                
                commands.extend([
                    "check",
                    "exploit"
                ])
            else:
                # Unknown module type
                commands = [
                    f"use {exploit_module}",
                    f"set RHOSTS {host}",
                    f"set RPORT {port}",
                    "run"
                ]
            
            result['commands'] = commands
            result['ai_source'] = 'local_ollama'
            result['model_used'] = self.exploit_model
            
            # Log the result with vulnerability type
            vuln_type_emoji = {
                'RCE': '💥',
                'DOS': '💣', 
                'INFO_DISCLOSURE': '🔍',
                'AUTH_BYPASS': '🔓',
                'PRIVILEGE_ESCALATION': '⬆️',
                'OTHER': '❓'
            }.get(vuln_type, '❓')
            
            print(f"✅ AI result: {exploit_module} {vuln_type_emoji} ({vuln_type})")
            return result
            
        except Exception as e:
            print(f"❌ Local AI Error: {e}")
            return {
                "exploit_module": "ERROR_OCCURRED",
                "payload": "NOT_APPLICABLE",
                "vulnerability_type": "ERROR",
                "confidence": "low",
                "reasoning": f"Local AI error: {str(e)}",
                "target_info": {
                    "RHOSTS": host,
                    "RPORT": port
                },
                "commands": [
                    "# AI analysis failed",
                    f"# Target: {host}:{port} ({service} {product} {version})",
                    "# Manual analysis required"
                ],
                "ai_source": "error",
                "error": str(e)
            }

    def generate_report_section(self, section_type: str, data: Dict[str, Any]) -> str:
        """Generate professional report sections using Mistral"""
        
        prompts = {
            'executive_summary': f"""Write a professional executive summary for a cybersecurity vulnerability assessment report.

Target Information:
- Host: {data.get('target_host', 'Unknown')}
- Services Found: {len(data.get('services', []))}
- Total CVEs: {data.get('total_cves', 0)}
- High/Critical CVEs: {data.get('critical_cves', 0)}
- Risk Level: {data.get('risk_level', 'Unknown')}

Write 2-3 paragraphs in professional business language suitable for C-level executives. Focus on business impact and risk. Do not use stars or amateur formatting.""",

            'technical_findings': f"""Write a technical findings section for a vulnerability assessment report.

Vulnerability Data:
- Total vulnerabilities: {data.get('total_cves', 0)}
- Critical: {data.get('severity_breakdown', {}).get('CRITICAL', 0)}
- High: {data.get('severity_breakdown', {}).get('HIGH', 0)}
- Medium: {data.get('severity_breakdown', {}).get('MEDIUM', 0)}
- Low: {data.get('severity_breakdown', {}).get('LOW', 0)}

Services: {', '.join([s.get('service', 'unknown') for s in data.get('services', [])])}

Write detailed technical analysis in professional cybersecurity language. Use proper markdown headers.""",

            'remediation_strategy': f"""Write a comprehensive remediation strategy section for a cybersecurity report.

Current Risk Profile:
- Risk Level: {data.get('risk_level', 'Unknown')}
- Priority Services: {', '.join([s.get('service', 'unknown') for s in data.get('services', [])[:3]])}
- Immediate Threats: {data.get('critical_cves', 0)} critical vulnerabilities

Write actionable remediation steps organized by priority (Immediate, Short-term, Long-term). Use professional language."""
        }
        
        if section_type not in prompts:
            return f"## {section_type.replace('_', ' ').title()}\n\nSection content will be generated here.\n\n"
            
        try:
            response = ollama.chat(
                model=self.report_model,
                messages=[{
                    'role': 'system', 
                    'content': 'You are a professional cybersecurity consultant writing formal assessment reports. Write in clear, professional business language without amateur formatting like stars.'
                }, {
                    'role': 'user', 
                    'content': prompts[section_type]
                }],
                options={
                    'temperature': 0.3,  # Slightly higher for creative writing
                    'top_p': 0.9,
                    'num_predict': 800   # Longer responses for reports
                }
            )
            
            content = response['message']['content'].strip()
            return content
            
        except Exception as e:
            print(f"❌ Report AI Error: {e}")
            return f"## {section_type.replace('_', ' ').title()}\n\nContent generation failed: {str(e)}\n\n"

    def enhance_vulnerability_analysis(self, vulnerability_data: Dict[str, Any]) -> str:
        """Use AI to enhance vulnerability analysis with professional insights"""
        
        prompt = f"""Analyze these vulnerability findings and provide professional cybersecurity insights:

Vulnerability Summary:
- Total Vulnerabilities: {vulnerability_data.get('total_vulnerabilities', 0)}
- Critical Severity: {vulnerability_data.get('critical_count', 0)}
- High Severity: {vulnerability_data.get('high_count', 0)}
- Services Affected: {vulnerability_data.get('affected_services', 0)}
- Average CVSS Score: {vulnerability_data.get('avg_cvss', 0)}

Top Vulnerabilities:
{vulnerability_data.get('top_vulnerabilities', 'None listed')}

Provide a professional analysis focusing on:
1. Overall security posture assessment
2. Business risk implications  
3. Attack surface analysis
4. Prioritization recommendations

Write in professional cybersecurity consultant language."""

        try:
            response = ollama.chat(
                model=self.report_model,
                messages=[{
                    'role': 'system',
                    'content': 'You are a senior cybersecurity consultant providing expert analysis for enterprise clients.'
                }, {
                    'role': 'user',
                    'content': prompt
                }],
                options={
                    'temperature': 0.4,
                    'top_p': 0.9,
                    'num_predict': 600
                }
            )
            
            return response['message']['content'].strip()
            
        except Exception as e:
            print(f"❌ Analysis AI Error: {e}")
            return "Professional vulnerability analysis could not be generated due to AI service error."


# Global instance for easy import
local_ai = LocalAISystem()


# Test function
def test_local_ai():
    """Test the local AI system"""
    print("🔧 Testing Local AI System...")
    
    # Test connection
    if not local_ai.test_connection():
        print("❌ Local AI not ready")
        return False
    
    # Test exploit generation
    test_service = {
        'service': 'ftp',
        'product': 'vsftpd',
        'version': '2.3.4',
        'port': 21,
        'host': '192.168.1.100'
    }
    
    print("\n🎯 Testing exploit generation...")
    result = local_ai.generate_metasploit_exploit(test_service)
    print(f"Result: {result}")
    
    # Test report generation
    test_data = {
        'target_host': '192.168.1.100',
        'services': [{'service': 'ftp', 'product': 'vsftpd'}],
        'total_cves': 5,
        'critical_cves': 2,
        'risk_level': 'HIGH'
    }
    
    print("\n📄 Testing report generation...")
    summary = local_ai.generate_report_section('executive_summary', test_data)
    print(f"Summary: {summary[:200]}...")
    
    print("\n✅ Local AI system test complete!")
    return True


if __name__ == "__main__":
    test_local_ai()
