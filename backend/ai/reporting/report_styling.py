#!/usr/bin/env python3
"""
Professional Report Styling and Branding System
Creates professional-looking reports with proper styling, logos, and layouts
"""

import base64
import os
from typing import Dict, Any

class ReportStyler:
    """Professional report styling system"""
    
    def __init__(self):
        self.brand_colors = {
            'primary': '#1e40af',      # Deep blue
            'secondary': '#0f172a',    # Dark slate
            'accent': '#dc2626',       # Red for critical
            'warning': '#ea580c',      # Orange for high
            'info': '#0891b2',         # Cyan for medium
            'success': '#16a34a',      # Green for low
            'background': '#f8fafc',   # Light gray
            'text': '#1e293b',         # Dark text
            'border': '#e2e8f0'        # Light border
        }
        
        # Create a simple SVG logo
        self.logo_svg = self._create_logo_svg()
        self.logo_base64 = self._svg_to_base64(self.logo_svg)
    
    def _create_logo_svg(self) -> str:
        """Create a professional SVG logo"""
        return '''<svg width="200" height="60" viewBox="0 0 200 60" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="logoGradient" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#1e40af;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#0891b2;stop-opacity:1" />
    </linearGradient>
  </defs>
  
  <!-- Shield icon -->
  <path d="M20 12l8-4 8 4v16c0 6-4 10-8 14-4-4-8-8-8-14V12z" 
        fill="url(#logoGradient)" stroke="#1e40af" stroke-width="2"/>
  
  <!-- Checkmark -->
  <path d="M24 22l3 3 6-6" stroke="white" stroke-width="2" fill="none" stroke-linecap="round"/>
  
  <!-- Company name -->
  <text x="50" y="25" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#1e40af">
    VulneraMind
  </text>
  
  <!-- Tagline -->
  <text x="50" y="40" font-family="Arial, sans-serif" font-size="12" fill="#64748b">
    AI-Powered Security Assessment
  </text>
</svg>'''
    
    def _svg_to_base64(self, svg_content: str) -> str:
        """Convert SVG to base64 for embedding"""
        return base64.b64encode(svg_content.encode('utf-8')).decode('utf-8')
    
    def get_html_header(self, title: str = "Security Assessment Report") -> str:
        """Generate professional HTML header with logo"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: {self.brand_colors['text']};
            background: {self.brand_colors['background']};
        }}
        
        .container {{
            max-width: 8.5in;
            margin: 0 auto;
            background: white;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, {self.brand_colors['primary']}, {self.brand_colors['info']});
            color: white;
            padding: 2rem;
            text-align: center;
        }}
        
        .logo {{
            margin-bottom: 1rem;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        
        .header .subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 2rem;
        }}
        
        .section {{
            margin-bottom: 3rem;
            page-break-inside: avoid;
        }}
        
        .section h2 {{
            color: {self.brand_colors['primary']};
            font-size: 1.8rem;
            font-weight: 600;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid {self.brand_colors['border']};
        }}
        
        .section h3 {{
            color: {self.brand_colors['secondary']};
            font-size: 1.4rem;
            font-weight: 600;
            margin: 1.5rem 0 1rem 0;
        }}
        
        .section h4 {{
            color: {self.brand_colors['text']};
            font-size: 1.2rem;
            font-weight: 500;
            margin: 1rem 0 0.5rem 0;
        }}
        
        .risk-level {{
            display: inline-block;
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.875rem;
        }}
        
        .risk-critical {{
            background: {self.brand_colors['accent']};
            color: white;
        }}
        
        .risk-high {{
            background: {self.brand_colors['warning']};
            color: white;
        }}
        
        .risk-medium {{
            background: #d97706;
            color: white;
        }}
        
        .risk-low {{
            background: {self.brand_colors['success']};
            color: white;
        }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}
        
        .metric-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid {self.brand_colors['border']};
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}
        
        .metric-value {{
            font-size: 2rem;
            font-weight: 700;
            color: {self.brand_colors['primary']};
        }}
        
        .metric-label {{
            font-size: 0.875rem;
            color: #64748b;
            margin-top: 0.25rem;
        }}
        
        .vulnerability-card {{
            background: white;
            border: 1px solid {self.brand_colors['border']};
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid {self.brand_colors['accent']};
        }}
        
        .vulnerability-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}
        
        .cve-id {{
            font-weight: 600;
            color: {self.brand_colors['primary']};
        }}
        
        .cvss-score {{
            background: {self.brand_colors['accent']};
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.875rem;
        }}
        
        .service-info {{
            background: #f1f5f9;
            padding: 1rem;
            border-radius: 6px;
            margin: 1rem 0;
        }}
        
        .table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}
        
        .table th,
        .table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid {self.brand_colors['border']};
        }}
        
        .table th {{
            background: {self.brand_colors['background']};
            font-weight: 600;
            color: {self.brand_colors['secondary']};
        }}
        
        .footer {{
            background: {self.brand_colors['secondary']};
            color: white;
            padding: 2rem;
            text-align: center;
            margin-top: 3rem;
        }}
        
        .footer-logo {{
            opacity: 0.7;
            margin-bottom: 1rem;
        }}
        
        .classification {{
            background: {self.brand_colors['accent']};
            color: white;
            text-align: center;
            padding: 0.5rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        @media print {{
            .container {{
                box-shadow: none;
                max-width: none;
            }}
            
            .section {{
                page-break-inside: avoid;
            }}
            
            .header {{
                page-break-after: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="classification">CONFIDENTIAL - SECURITY ASSESSMENT</div>
    <div class="container">
        <div class="header">
            <div class="logo">
                <img src="data:image/svg+xml;base64,{self.logo_base64}" alt="VulneraMind Logo" width="200" height="60">
            </div>
            <h1>{title}</h1>
            <div class="subtitle">Professional Cybersecurity Assessment</div>
        </div>
        <div class="content">'''
    
    def get_html_footer(self) -> str:
        """Generate professional HTML footer"""
        return f'''
        </div>
        <div class="footer">
            <div class="footer-logo">
                <img src="data:image/svg+xml;base64,{self.logo_base64}" alt="VulneraMind Logo" width="150" height="45" style="opacity: 0.7;">
            </div>
            <p>This report was generated by VulneraMind AI Security Scanner</p>
            <p style="font-size: 0.875rem; opacity: 0.8; margin-top: 0.5rem;">
                Professional Cybersecurity Assessment | Confidential Information
            </p>
        </div>
    </div>
</body>
</html>'''
    
    def get_css_styles(self) -> str:
        """Get CSS styles for markdown-to-HTML conversion"""
        return f"""
        <style>
            /* Professional Report Styling */
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: {self.brand_colors['text']};
                max-width: 8.5in;
                margin: 0 auto;
                background: white;
                padding: 0;
            }}
            
            .header-section {{
                background: linear-gradient(135deg, {self.brand_colors['primary']}, {self.brand_colors['info']});
                color: white;
                padding: 2rem;
                text-align: center;
                margin-bottom: 2rem;
            }}
            
            h1 {{
                color: {self.brand_colors['primary']};
                font-size: 2.5rem;
                margin-bottom: 1rem;
                font-weight: 700;
            }}
            
            h2 {{
                color: {self.brand_colors['primary']};
                font-size: 1.8rem;
                margin: 2rem 0 1rem 0;
                padding-bottom: 0.5rem;
                border-bottom: 2px solid {self.brand_colors['border']};
            }}
            
            h3 {{
                color: {self.brand_colors['secondary']};
                font-size: 1.4rem;
                margin: 1.5rem 0 1rem 0;
            }}
            
            .risk-critical {{
                background: {self.brand_colors['accent']};
                color: white;
                padding: 0.5rem 1rem;
                border-radius: 9999px;
                font-weight: 600;
                text-transform: uppercase;
                font-size: 0.875rem;
            }}
            
            .cve-card {{
                border: 1px solid {self.brand_colors['border']};
                border-left: 4px solid {self.brand_colors['accent']};
                padding: 1rem;
                margin: 1rem 0;
                background: #f8fafc;
                border-radius: 4px;
            }}
            
            code {{
                background: #f1f5f9;
                padding: 0.2rem 0.4rem;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
            }}
            
            pre {{
                background: #f1f5f9;
                padding: 1rem;
                border-radius: 6px;
                overflow-x: auto;
                border-left: 4px solid {self.brand_colors['primary']};
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 1rem 0;
            }}
            
            th, td {{
                padding: 0.75rem;
                text-align: left;
                border-bottom: 1px solid {self.brand_colors['border']};
            }}
            
            th {{
                background: {self.brand_colors['background']};
                font-weight: 600;
                color: {self.brand_colors['secondary']};
            }}
            
            .footer {{
                text-align: center;
                padding: 2rem;
                background: {self.brand_colors['secondary']};
                color: white;
                margin-top: 3rem;
            }}
        </style>
        """
    
    def create_executive_summary_card(self, risk_level: str, total_vulns: int, critical_count: int, host: str) -> str:
        """Create a professional executive summary card"""
        risk_class = f"risk-{risk_level.lower()}"
        
        return f'''
        <div class="section">
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value">{total_vulns}</div>
                    <div class="metric-label">Total Vulnerabilities</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{critical_count}</div>
                    <div class="metric-label">Critical/High Risk</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">
                        <span class="risk-level {risk_class}">{risk_level}</span>
                    </div>
                    <div class="metric-label">Overall Risk Level</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{host}</div>
                    <div class="metric-label">Target Host</div>
                </div>
            </div>
        </div>'''
    
    def create_vulnerability_card(self, cve_id: str, severity: str, score: float, description: str, service: str = "") -> str:
        """Create a professional vulnerability card"""
        severity_class = f"risk-{severity.lower()}"
        
        return f'''
        <div class="vulnerability-card">
            <div class="vulnerability-header">
                <span class="cve-id">{cve_id}</span>
                <span class="cvss-score">{score}</span>
            </div>
            <div class="risk-level {severity_class}">{severity}</div>
            {f'<div class="service-info"><strong>Affected Service:</strong> {service}</div>' if service else ''}
            <p style="margin-top: 0.5rem;">{description}</p>
        </div>'''

# Global instance for easy access
report_styler = ReportStyler()
