#!/usr/bin/env python3
"""
Vulnerability Scanner Report Generator
Copyright (c) 2025 RHAZOUANE SALAH-EDDINE
All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

PROPRIETARY NOTICE:
This software is the confidential and proprietary information of
RHAZOUANE SALAH-EDDINE. You shall not disclose such confidential
information and shall use it only in accordance with the terms
of the license agreement you entered into with RHAZOUANE SALAH-EDDINE.

Author: RHAZOUANE SALAH-EDDINE
Repository: https://github.com/THE-RZ1-x/Ai_Vuln_Scanner
Profile: https://github.com/THE-RZ1-x
Version: 2.0
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
import traceback
import socket

logger = logging.getLogger(__name__)

# Global variables
JINJA_AVAILABLE = False
PLOTLY_AVAILABLE = False
MATPLOTLIB_AVAILABLE = False
NETWORKX_AVAILABLE = False

# Define basic template class
class BasicTemplate:
    def __init__(self, template_str):
        self.template_str = template_str
    def render(self, **kwargs):
        return self.template_str

# Initialize template system
Template = BasicTemplate  # Default to basic template

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape, Template as JinjaTemplate, StrictUndefined
    Template = JinjaTemplate  # Use Jinja2 Template if available
    JINJA_AVAILABLE = True
    logger.info("Jinja2 available for templating")
except ImportError:
    logger.warning("Jinja2 not installed. Using basic string templates.")

# Try importing visualization libraries
try:
    import plotly.graph_objects as go
    import plotly.express as px
    import plotly.io as pio
    try:
        import kaleido
        logger.info("Kaleido available for static export of interactive charts")
    except ImportError:
        logger.warning("Kaleido not installed. Static export of interactive charts disabled.")
    PLOTLY_AVAILABLE = True
    logger.info("Plotly available for interactive charts")
except ImportError:
    logger.warning("Plotly not installed. Interactive charts disabled.")
    
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
    logger.info("Matplotlib available for static charts")
except ImportError:
    logger.warning("Matplotlib not installed. Static charts disabled.")

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
    logger.info("NetworkX available for network visualization")
except ImportError:
    logger.warning("NetworkX not installed. Network visualization disabled.")

@dataclass
class ReportData:
    target: str
    scan_type: str
    timestamp: str
    vulnerabilities: List[Dict]
    system_info: Dict
    web_vulnerabilities: List[Dict]
    network_services: List[Dict]
    risk_score: float
    scan_duration: float
    generated_exploits: List[Dict] = None

class ReportGenerator:
    # Template level constants
    TEMPLATE_ADVANCED = "advanced"
    TEMPLATE_STANDARD = "standard"
    TEMPLATE_BASIC = "basic"
    TEMPLATE_MINIMAL = "minimal"
    
    def __init__(self):
        self.template_env = None
        self.template_level = None
        self.capabilities = {}
        self.jinja_available = JINJA_AVAILABLE
        self.plotly_available = PLOTLY_AVAILABLE
        self.matplotlib_available = MATPLOTLIB_AVAILABLE
        self.networkx_available = NETWORKX_AVAILABLE
        self.setup_templates()

    def setup_templates(self):
        """Set up the Jinja2 template environment with robust fallbacks."""
        # Detect capabilities
        self._detect_capabilities()
        
        if self.jinja_available:
            try:
                template_dir = os.path.join(os.path.dirname(__file__), 'templates')
                self.template_env = Environment(
                    loader=FileSystemLoader(template_dir),
                    autoescape=select_autoescape(['html', 'xml']),
                    # Security hardening
                    auto_reload=False,
                    cache_size=100,
                    undefined=StrictUndefined  # Fail on undefined variables
                )
                if self.template_level:
                    logger.info(f"Using template level: {self.template_level}")
            except Exception as e:
                logger.warning(f"Error setting up Jinja2 template environment: {str(e)}")
                # Fallback to simpler environment without strict settings
                try:
                    self.template_env = Environment(
                        loader=FileSystemLoader(template_dir),
                        autoescape=True
                    )
                except Exception as e:
                    logger.warning(f"Fallback template setup failed: {str(e)}")
                    self.jinja_available = False
                    
        if not self.jinja_available:
            logger.warning("Jinja2 not available. Using secure basic HTML templates.")
    
    def _detect_capabilities(self):
        """Detect available capabilities and select the most appropriate template level."""
        # Check internet connection
        internet_available = False
        try:
            # Try connecting to Google's DNS
            socket.create_connection(("8.8.8.8", 53), 1)
            internet_available = True
        except (OSError, NameError):
            pass
            
        # Check CDN access
        cdn_available = False
        if internet_available:
            try:
                import urllib.request
                import urllib.error
                # Try to access common CDNs used in our templates
                urllib.request.urlopen("https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css", timeout=1)
                cdn_available = True
            except (urllib.error.URLError, socket.timeout, ImportError, NameError):
                pass
                
        # Store capabilities
        self.capabilities = {
            'jinja': self.jinja_available,
            'interactive_charts': self.plotly_available,
            'static_charts': self.matplotlib_available,
            'internet': internet_available,
            'cdn_access': cdn_available
        }
        
        # Template selection logic based on capabilities
        if all([self.capabilities['jinja'], self.capabilities['interactive_charts'], self.capabilities['cdn_access']]):
            self.template_level = self.TEMPLATE_ADVANCED
        elif all([self.capabilities['jinja'], self.capabilities['cdn_access']]):
            self.template_level = self.TEMPLATE_STANDARD
        elif self.capabilities['jinja']:
            self.template_level = self.TEMPLATE_BASIC
        else:
            self.template_level = self.TEMPLATE_MINIMAL

    def get_appropriate_template(self, scan_results: dict) -> Optional[Template]:
        """Select the most appropriate template based on system capabilities."""
        if not self.jinja_available or not self.template_env:
            return None
            
        template_file = None
        
        # Try to load template file based on capability level
        if self.template_level == self.TEMPLATE_ADVANCED:
            try:
                template_file = 'advanced_report.html'
                return self.template_env.get_template(template_file)
            except Exception as e:
                logger.warning(f"Failed to load advanced template: {str(e)}")
                
        if self.template_level in [self.TEMPLATE_ADVANCED, self.TEMPLATE_STANDARD]:
            try:
                template_file = 'standard_report.html'
                return self.template_env.get_template(template_file)
            except Exception as e:
                logger.warning(f"Failed to load standard template: {str(e)}")
                
        if self.template_level in [self.TEMPLATE_ADVANCED, self.TEMPLATE_STANDARD, self.TEMPLATE_BASIC]:
            try:
                template_file = 'basic_report.html'
                return self.template_env.get_template(template_file)
            except Exception as e:
                logger.warning(f"Failed to load basic template: {str(e)}")
        
        # Try minimal template as last resort  
        try:
            template_file = 'minimal_report.html'
            return self.template_env.get_template(template_file)
        except Exception as e:
            logger.warning(f"Failed to load minimal template: {str(e)}")
            
        # Fall back to embedded templates
        if self.template_level in [self.TEMPLATE_ADVANCED, self.TEMPLATE_STANDARD]:
            return self._get_enhanced_report_template()
        else:
            return self._get_report_template()

    def get_appropriate_template_path(self, scan_results: dict) -> Optional[str]:
        """Select the path to the most appropriate template based on system capabilities."""
        if not self.jinja_available:
            return None
            
        # Define template directory
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
            
        # Try to find template file based on capability level
        if self.template_level == self.TEMPLATE_ADVANCED:
            try:
                template_path = os.path.join(template_dir, 'advanced_report.html')
                if os.path.exists(template_path):
                    return template_path
            except Exception as e:
                logger.warning(f"Failed to find advanced template: {str(e)}")
                
        if self.template_level in [self.TEMPLATE_ADVANCED, self.TEMPLATE_STANDARD]:
            try:
                template_path = os.path.join(template_dir, 'standard_report.html')
                if os.path.exists(template_path):
                    return template_path
            except Exception as e:
                logger.warning(f"Failed to find standard template: {str(e)}")
                
        if self.template_level in [self.TEMPLATE_ADVANCED, self.TEMPLATE_STANDARD, self.TEMPLATE_BASIC]:
            try:
                template_path = os.path.join(template_dir, 'basic_report.html')
                if os.path.exists(template_path):
                    return template_path
            except Exception as e:
                logger.warning(f"Failed to find basic template: {str(e)}")
        
        # Try minimal template as last resort  
        try:
            template_path = os.path.join(template_dir, 'minimal_report.html')
            if os.path.exists(template_path):
                return template_path
        except Exception as e:
            logger.warning(f"Failed to find minimal template: {str(e)}")
            
        return None

    def generate_report(self, scan_results: dict, output_dir: str) -> str:
        """Generate HTML report from scan results."""
        try:
            logger.info("Starting report generation")
            
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Initialize chart paths (will be empty if charts can't be generated)
            chart_paths = {}
            
            # Try to generate charts only if visualization libraries are available
            charts_dir = os.path.join(output_dir, 'charts')
            
            try:
                # Create charts directory if it doesn't exist and if charts will be generated
                if self.plotly_available or self.matplotlib_available:
                    os.makedirs(charts_dir, exist_ok=True)
                    logger.info(f"Creating charts in directory: {charts_dir}")
                    
                    # Generate charts if visualization libraries are available
                    if self.plotly_available:
                        self._generate_charts_plotly(scan_results, charts_dir, chart_paths, output_dir)
                    elif self.matplotlib_available:
                        self._generate_charts_matplotlib(scan_results, charts_dir, chart_paths, output_dir)
            except Exception as chart_error:
                logger.error(f"Error generating charts: {str(chart_error)}")
                logger.debug(f"Chart error traceback: {traceback.format_exc()}")
            
            # Prepare data for template
            template_data = self._prepare_template_data(scan_results, chart_paths)

            # Generate HTML report
            if self.jinja_available:
                # Get appropriate template
                template_path = self.get_appropriate_template_path(scan_results)
                if template_path:
                    try:
                        html_content = self._render_template(template_path, template_data)
                    except Exception as template_error:
                        logger.error(f"Error rendering template: {str(template_error)}")
                        html_content = self._generate_basic_html_report(scan_results, chart_paths)
                else:
                    # Use simple string formatting if no template available
                    html_content = self._generate_basic_html_report(scan_results, chart_paths)
            else:
                # Use simple string formatting if Jinja is not available
                html_content = self._generate_basic_html_report(scan_results, chart_paths)

            # Save report
            report_path = os.path.join(output_dir, 'report.html')
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"HTML report generated successfully at {report_path}")
            return report_path

        except Exception as render_error:
            logger.error(f"Error rendering template: {str(render_error)}")
            logger.debug(f"Template error traceback: {traceback.format_exc()}")
            raise
                
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            
            # Last resort - fall back to super simple HTML
            try:
                simple_html = self._generate_minimal_html_report(scan_results)
                
                # Save simple report
                report_path = os.path.join(output_dir, 'report.html')
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(simple_html)
                
                logger.info(f"Simple HTML report generated successfully at {report_path}")
                return report_path
            
            except Exception as simple_error:
                logger.error(f"Error generating simple HTML report: {str(simple_error)}")
                return None

    def _prepare_template_data(self, scan_results: dict, chart_paths: dict) -> dict:
        """Prepare standardized data structure for templates."""
        try:
            # Extract risk level counts
            count_by_risk = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Unknown': 0
            }
            
            # Process services directly from scan_results to include analysis data
            services_with_ai = {}
            
            # Ensure services is a dictionary before processing
            services = scan_results.get('services', {})
            if not isinstance(services, dict):
                logger.warning(f"Expected services to be a dictionary, got {type(services)}")
                services = {}
            
            for port_key, service_info in services.items():
                # Ensure port_key is a string
                port_key_str = str(port_key)
                
                # Create an enhanced service info
                if '/' in port_key_str:
                    port, protocol = port_key_str.split('/')
                else:
                    port = port_key_str
                    protocol = service_info.get('transport', 'tcp')
                
                # Initialize service with basic info
                services_with_ai[port_key_str] = {
                    'protocol': protocol,
                    'port': port,
                    'service': service_info.get('service', 'unknown'),
                    'product': service_info.get('product', ''),
                    'version': service_info.get('version', ''),
                    'identification_failed': service_info.get('identification_failed', False),
                    'risk_level': 'Unknown',
                    'analyses': []  # Initialize empty list for analyses
                }
                
                # Get analyses from service_info if present
                if 'analysis' in service_info:
                    if isinstance(service_info['analysis'], list):
                        services_with_ai[port_key_str]['analyses'] = service_info['analysis']
                    else:
                        logger.warning(f"Expected analysis to be a list, got {type(service_info['analysis'])}")
                
                # Process analysis to determine risk level
                ai_analysis_found = False
                risk_level = 'Unknown'
                
                for item in services_with_ai[port_key_str]['analyses']:
                    source = item.get('source', '')
                    analysis_text = item.get('analysis', '')
                    
                    # Check if AI analysis exists
                    if source in ['Enhanced Analysis', 'Gemini AI', 'OpenAI', 'AI Analysis']:
                        ai_analysis_found = True
                    
                    # Determine risk level from analysis text
                    if "Critical" in analysis_text or "CRITICAL" in analysis_text:
                        risk_level = "Critical"
                        break
                    elif ("High" in analysis_text or "HIGH" in analysis_text) and risk_level != "Critical":
                        risk_level = "High"
                    elif ("Medium" in analysis_text or "MEDIUM" in analysis_text) and risk_level not in ["Critical", "High"]:
                        risk_level = "Medium"
                    elif ("Low" in analysis_text or "LOW" in analysis_text) and risk_level not in ["Critical", "High", "Medium"]:
                        risk_level = "Low"
                
                # Record AI analysis status and risk level
                services_with_ai[port_key_str]['has_ai_analysis'] = ai_analysis_found
                services_with_ai[port_key_str]['risk_level'] = risk_level
                
                # Update risk level counts
                count_by_risk[risk_level] = count_by_risk.get(risk_level, 0) + 1
            
            # Determine overall risk level
            overall_risk = 'Low'
            if count_by_risk['Critical'] > 0:
                overall_risk = 'Critical'
            elif count_by_risk['High'] > 0:
                overall_risk = 'High'
            elif count_by_risk['Medium'] > 0:
                overall_risk = 'Medium'
            
            # Organize template data
            template_data = {
                'data': {
                    'target': scan_results.get('target', 'Unknown'),
                    'scan_type': scan_results.get('scan_type', 'Unknown'),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'risk_level': overall_risk,
                    'services': services_with_ai,
                    'services_original': scan_results.get('services', {}),  # Include original services too
                    'system_info': scan_results.get('system_info', {}),
                    'count_by_risk': count_by_risk,
                    'summary': scan_results.get('summary', None)
                },
                'charts': chart_paths,
                'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'current_year': datetime.now().year,
                'scan_duration': scan_results.get('scan_duration', 0),
                'has_interactive_charts': self.plotly_available and bool(chart_paths),
                'has_ai_analysis': any(svc.get('has_ai_analysis', False) for svc in services_with_ai.values()),
                'count_by_risk': count_by_risk  # Add count_by_risk to the root level too
            }
                
            return template_data
                
        except Exception as e:
            logger.error(f"Error preparing template data: {str(e)}")
            logger.error(f"Error details: {traceback.format_exc()}")
            # Fallback with minimal template data
            return {
                'data': {
                    'target': scan_results.get('target', 'Unknown'),
                    'scan_type': scan_results.get('scan_type', 'basic'),
                    'services': {},
                    'services_original': scan_results.get('services', {}),
                    'risk_level': 'Unknown',
                    'count_by_risk': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
                },
                'charts': chart_paths,
                'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration': 0,
                'count_by_risk': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
            }

    def _generate_minimal_html_report(self, scan_results: dict) -> str:
        """Generate a minimal HTML report when all else fails."""
        simple_html = f"""
        <html>
        <head><title>Scan Report for {scan_results.get('target')}</title>
        <style>
            body {{ font-family: sans-serif; margin: 20px; }}
            h1, h2 {{ color: #333; }}
            pre {{ background-color: #f8f9fc; padding: 15px; border-radius: 5px; }}
        </style>
        </head>
        <body>
            <h1>Scan Report for {scan_results.get('target')}</h1>
            <h2>Risk Level: {scan_results.get('risk_level', 'Unknown')}</h2>
            <pre>{json.dumps(scan_results, indent=2)}</pre>
            <p><small>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
        </body>
        </html>
        """
        return simple_html

    def _generate_basic_html_report(self, scan_results: dict, chart_paths: dict) -> str:
        """Generate basic HTML report without using Jinja2."""
        try:
            # Prepare template data
            template_data = self._prepare_template_data(scan_results, chart_paths)
            
            target = template_data['data']['target']
            risk_level = template_data['data']['risk_level']
            timestamp = template_data['current_time']
            scan_duration = template_data['scan_duration']
            services = template_data['data']['services']
            
            html = f"""
            <!DOCTYPE html>
            <html lang="en" dir="ltr">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Security Scan Report - {target}</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
                <style>
                    :root {{
                        --critical: #dc3545;
                        --high: #fd7e14;
                        --medium: #ffc107;
                        --low: #28a745;
                        --unknown: #6c757d;
                    }}
                    body {{ 
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background-color: #f8f9fa;
                    }}
                    .card {{
                        border: none;
                        border-radius: 10px;
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        margin-bottom: 1.5rem;
                        overflow: hidden;
                    }}
                    .card-header {{
                        background-color: #f8f9fa;
                        border-bottom: 1px solid rgba(0,0,0,0.125);
                        padding: 1rem;
                    }}
                    .dashboard-card {{
                        height: 100%;
                        transition: transform 0.3s;
                    }}
                    .dashboard-card:hover {{
                        transform: translateY(-5px);
                    }}
                    .risk-critical {{ border-right: 5px solid var(--critical); }}
                    .risk-high {{ border-right: 5px solid var(--high); }}
                    .risk-medium {{ border-right: 5px solid var(--medium); }}
                    .risk-low {{ border-right: 5px solid var(--low); }}
                    .risk-unknown {{ border-right: 5px solid var(--unknown); }}
                    
                    .badge-critical {{ background-color: var(--critical); color: white; }}
                    .badge-high {{ background-color: var(--high); color: white; }}
                    .badge-medium {{ background-color: var(--medium); color: black; }}
                    .badge-low {{ background-color: var(--low); color: white; }}
                    .badge-unknown {{ background-color: var(--unknown); color: white; }}
                    
                    .chart-container {{
                        position: relative;
                        height: 300px;
                        width: 100%;
                    }}
                    .analysis-section {{
                        background-color: #f8f9fa;
                        border-radius: 8px;
                        padding: 15px;
                        margin-bottom: 15px;
                    }}
                    .ai-analysis {{
                        border-right: 4px solid #4e73df;
                    }}
                    .source-tag {{
                        display: inline-block;
                        padding: 3px 10px;
                        border-radius: 25px;
                        font-size: 0.75rem;
                        font-weight: 600;
                        background-color: #e2e8f0;
                        color: #1a202c;
                        margin-bottom: 8px;
                    }}
                    .tag-gemini {{
                        background-color: #4285f4;
                        color: white;
                    }}
                    .tag-openai {{
                        background-color: #10a37f;
                        color: white;
                    }}
                    .analysis-content {{
                        white-space: pre-wrap;
                        font-size: 0.9rem;
                        line-height: 1.6;
                        color: #333;
                        background-color: #f8f9fa;  /* إضافة خلفية للنص لضمان الوضوح */
                        padding: 10px;  /* إضافة تباعد داخلي */
                        border-radius: 5px;  /* تنعيم الزوايا */
                    }}
                    .stat-card {{
                        border-radius: 10px;
                        padding: 20px;
                        text-align: center;
                        margin-bottom: 20px;
                        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                    }}
                    .stat-card.critical {{ background-color: rgba(220, 53, 69, 0.1); }}
                    .stat-card.high {{ background-color: rgba(253, 126, 20, 0.1); }}
                    .stat-card.medium {{ background-color: rgba(255, 193, 7, 0.1); }}
                    .stat-card.low {{ background-color: rgba(40, 167, 69, 0.1); }}
                    .headline {{
                        position: relative;
                        padding-bottom: 10px;
                        margin-bottom: 20px;
                    }}
                    .headline:after {{
                        content: '';
                        position: absolute;
                        bottom: 0;
                        right: 0;
                        height: 3px;
                        width: 70px;
                        background-color: #4e73df;
                    }}
                    .footer {{
                        background-color: #343a40;
                        color: #f8f9fa;
                        padding: 30px 0;
                        border-radius: 10px 10px 0 0;
                        margin-top: 30px;
                    }}
                </style>
            </head>
            <body>
                <div class="container py-5">
                    <header class="p-4 mb-5 bg-white rounded shadow">
                        <div class="row align-items-center">
                            <div class="col-md-8">
                                <h1 class="display-5 fw-bold text-primary">Security Scan Report</h1>
                                <div class="mt-3">
                                    <div class="row">
                                        <div class="col-md-6">
                                            <p><i class="fas fa-server me-2"></i><strong>Target:</strong> {target}</p>
                                            <p><i class="fas fa-search me-2"></i><strong>Scan Type:</strong> {template_data['data']['scan_type']}</p>
                                        </div>
                                        <div class="col-md-6">
                                            <p><i class="fas fa-calendar-alt me-2"></i><strong>Date:</strong> {timestamp}</p>
                                            <p><i class="fas fa-shield-alt me-2"></i><strong>Risk Level:</strong> 
                                                <span class="badge badge-{risk_level.lower()}">{risk_level}</span>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4 text-center">
                                <div class="p-3 rounded-circle mx-auto d-flex align-items-center justify-content-center" style="background-color: #f8f9fa; width: 150px; height: 150px;">
                                    <i class="fas fa-shield-alt text-primary" style="font-size: 5rem;"></i>
                                </div>
                            </div>
                        </div>
                    </header>

                    <!-- Dashboard -->
                    <div class="row mb-5">
                        <div class="col">
                            <h2 class="headline fw-bold mb-4">Dashboard</h2>
                        </div>
                    </div>

                    <!-- Risk Stats -->
                    <div class="row mb-5">
                        <div class="col-md-3">
                            <div class="stat-card critical">
                                <span>Critical</span>
                                <h3>{template_data['count_by_risk']['Critical']}</h3>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-card high">
                                <span>High</span>
                                <h3>{template_data['count_by_risk']['High']}</h3>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-card medium">
                                <span>Medium</span>
                                <h3>{template_data['count_by_risk']['Medium']}</h3>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stat-card low">
                                <span>Low</span>
                                <h3>{template_data['count_by_risk']['Low']}</h3>
                            </div>
                        </div>
                    </div>

                    <!-- Charts -->
                    <div class="row mb-5">
            """
            
            # Add charts if available
            if chart_paths:
                if 'severity_chart' in chart_paths:
                    html += f"""
                        <div class="col-md-6 mb-4">
                            <div class="card dashboard-card h-100">
                                <div class="card-header">
                                    <h5 class="card-title mb-0"><i class="fas fa-chart-pie me-2"></i>Severity Distribution</h5>
                                </div>
                                <div class="card-body">
                                    <div class="text-center">
                                        <img src="{chart_paths['severity_chart']}" alt="Severity Distribution" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                    </div>
                    """
                
                if 'service_chart' in chart_paths:
                    html += f"""
                        <div class="col-md-6 mb-4">
                            <div class="card dashboard-card h-100">
                                <div class="card-header">
                                    <h5 class="card-title mb-0"><i class="fas fa-chart-bar me-2"></i>Service Distribution</h5>
                                </div>
                                <div class="card-body">
                                    <div class="text-center">
                                        <img src="{chart_paths['service_chart']}" alt="Service Distribution" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                    </div>
                    """
                
                if 'risk_gauge_img' in chart_paths:
                    html += f"""
                        <div class="col-md-6 mb-4">
                            <div class="card dashboard-card h-100">
                                <div class="card-header">
                                    <h5 class="card-title mb-0"><i class="fas fa-tachometer-alt me-2"></i>Risk Assessment</h5>
                                </div>
                                <div class="card-body">
                                    <div class="text-center">
                                        <img src="{chart_paths['risk_gauge_img']}" alt="Risk Assessment" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                        </div>
                    """

                if 'network_map' in chart_paths:
                    html += f"""
                        <div class="col-md-6 mb-4">
                            <div class="card dashboard-card h-100">
                                <div class="card-header">
                                    <h5 class="card-title mb-0"><i class="fas fa-network-wired me-2"></i>Network Map</h5>
                                </div>
                                <div class="card-body">
                                    <div class="text-center">
                                        <img src="{chart_paths['network_map']}" alt="Network Map" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                        </div>
                    """
            
            html += """
                    </div>

                    <!-- Findings -->
                    <div class="row mb-4">
                        <div class="col">
                            <h2 class="headline fw-bold mb-4">Key Findings</h2>
                        </div>
                    </div>
            """
            
            # Add service rows
            for port_key, service_info in services.items():
                port = service_info.get('port', 'Unknown')
                protocol = service_info.get('protocol', 'tcp')
                service_name = service_info.get('service', 'Unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                risk_level = service_info.get('risk_level', 'Unknown')
                analyses = service_info.get('analyses', [])
                
                # Add row for this service
                risk_class = f"risk-{risk_level.lower()}"
                
                product_version = f"{product} {version}".strip()
                html += f"""
                <div class="card mb-4 {risk_class}">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0"><i class="fas fa-plug me-2"></i>{port}/{protocol} - {service_name}</h5>
                        <span class="badge badge-{risk_level.lower()}">{risk_level}</span>
                    </div>
                    <div class="card-body">
                """
                
                if product_version:
                    html += f"""
                        <p><i class="fas fa-info-circle me-2"></i><strong>Product:</strong> {product_version}</p>
                """
                
                # Add recommendations from analysis items
                if analyses:
                    html += """
                        <h6 class="mt-4 mb-3"><i class="fas fa-search me-2"></i>Service Analysis:</h6>
                    """
                    
                for analysis_item in analyses:
                    source = analysis_item.get('source', 'Unknown')
                    analysis_text = analysis_item.get('analysis', '')
                    
                    # Determine CSS class based on the source
                    css_class = "analysis-section"
                    tag_class = ""
                    source_icon = "fas fa-search"
                    
                    if source == "Gemini AI":
                        css_class += " ai-analysis"
                        tag_class = "tag-gemini"
                        source_icon = "fab fa-google"
                    elif source == "OpenAI":
                        css_class += " ai-analysis"
                        tag_class = "tag-openai"
                        source_icon = "fas fa-robot"
                    else:
                        source_icon = "fas fa-search"
                    
                    # Add each analysis item with its source
                    html += f"""
                    <div class="{css_class}">
                            <span class="source-tag {tag_class}"><i class="{source_icon} me-1"></i> {source}</span>
                            <div class="analysis-content mt-2">{analysis_text}</div>
                    </div>
                    """
                
                html += """
                    </div>
                </div>
                """
            
            # Add system info section if available
            if template_data['data']['system_info']:
                html += """
                <div class="row mb-4">
                    <div class="col">
                        <h2 class="headline fw-bold mb-4">System Information</h2>
                    </div>
                </div>
                <div class="card mb-5">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-server me-2"></i>System Details</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Variable</th>
                                        <th>Value</th>
                    </tr>
                                </thead>
                                <tbody>
            """
            
            for key, value in template_data['data']['system_info'].items():
                html += f"""
                <tr>
                        <td><strong>{key}</strong></td>
                    <td>{value}</td>
                </tr>
                """
            
                html += """
                                </tbody>
                </table>
                        </div>
                    </div>
                </div>
                """
            
            # Executive summary section
            html += f"""
                <!-- Executive Summary -->
                <div class="row mb-4">
                    <div class="col">
                        <h2 class="headline fw-bold mb-4">Executive Summary</h2>
                    </div>
                </div>
                <div class="card mb-5">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-clipboard-list me-2"></i>Overview</h5>
                    </div>
                    <div class="card-body">
                        <p>This security scan identified a total of <strong>{len(services)}</strong> services running on the target system.</p>
                        
                        <div class="alert alert-primary mt-3">
                            <ul class="mb-0">
                                <li>Found <strong>{template_data['count_by_risk']['Critical']}</strong> issues with Critical risk level</li>
                                <li>Found <strong>{template_data['count_by_risk']['High']}</strong> issues with High risk level</li>
                                <li>Found <strong>{template_data['count_by_risk']['Medium']}</strong> issues with Medium risk level</li>
                                <li>Found <strong>{template_data['count_by_risk']['Low']}</strong> issues with Low risk level</li>
                            </ul>
                        </div>
                        
                        <p class="mt-3">The overall risk level has been calculated as <strong>{risk_level}</strong>.</p>
            """
            
            # Add AI summary if available
            if template_data['data'].get('summary'):
                html += f"""
                        <div class="alert alert-info p-4 mt-4">
                            <h5><i class="fas fa-robot me-2"></i>AI Analysis Summary</h5>
                            <p class="mt-2">{template_data['data']['summary']}</p>
                        </div>
                """
            
            html += f"""
                    </div>
                </div>

                <footer class="text-center mt-5 mb-4">
                    <p>Report generated by AI Vulnerability Scanner - &copy; {template_data['current_year']} RHAZOUANE SALAH-EDDINE</p>
                    <p>Scan duration: {scan_duration:.2f} seconds | Generated on {timestamp}</p>
                </footer>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
            <!-- JavaScript for interactive effects removed to avoid syntax errors -->
            </body>
            </html>
            """
            
            return html
        
        except Exception as e:
            logger.error(f"Error generating basic HTML report: {str(e)}")
            logger.error(f"Error details: {traceback.format_exc()}")
            
            # Return a very minimal HTML report on error
            return f"""
            <!DOCTYPE html>
            <html>
            <head><title>Scan Report</title></head>
            <body>
                <h1>Scan Report</h1>
                <p>An error occurred while generating the report: {str(e)}</p>
                <pre>{json.dumps(scan_results, indent=2)}</pre>
            </body>
            </html>
            """

    def _generate_charts_plotly(self, scan_results: dict, charts_dir: str, chart_paths: dict, output_dir: str):
        """Generate all charts using Plotly if available."""
        if not self.plotly_available:
            return
            
        try:
            # 1. Severity distribution chart
            severity_data = self._get_severity_distribution(scan_results)
            severity_chart_path = os.path.join(charts_dir, 'severity_distribution.png')
            relative_path = os.path.relpath(severity_chart_path, output_dir)
            chart_paths['severity_chart'] = relative_path
            
            try:
                severity_html_path = self._generate_severity_chart(severity_data, severity_chart_path)
                if severity_html_path:
                    chart_paths['severity_html'] = os.path.relpath(severity_html_path, output_dir)
            except Exception as e:
                logger.error(f"Error generating severity chart: {str(e)}")
            
            # 2. Service distribution chart
            service_data = self._get_service_distribution(scan_results)
            service_chart_path = os.path.join(charts_dir, 'service_distribution.png')
            relative_path = os.path.relpath(service_chart_path, output_dir)
            chart_paths['service_chart'] = relative_path
            
            try:
                service_html_path = self._generate_service_chart(service_data, service_chart_path)
                if service_html_path:
                    chart_paths['service_html'] = os.path.relpath(service_html_path, output_dir)
            except Exception as e:
                logger.error(f"Error generating service chart: {str(e)}")
            
            # 3. Risk score gauge
            risk_gauge_path = os.path.join(charts_dir, 'risk_gauge.png')
            relative_path = os.path.relpath(risk_gauge_path, output_dir)
            
            try:
                risk_html_path = self._generate_risk_score_gauge(scan_results.get('risk_level', 'Unknown'), risk_gauge_path)
                if risk_html_path:
                    chart_paths['risk_gauge'] = os.path.relpath(risk_html_path, output_dir)
                    if os.path.exists(risk_gauge_path):
                        chart_paths['risk_gauge_img'] = relative_path
                else:
                    chart_paths['risk_gauge'] = None
            except Exception as e:
                logger.error(f"Error generating risk gauge chart: {str(e)}")
                chart_paths['risk_gauge'] = None
            
            # 4. Network map
            network_map_path = os.path.join(charts_dir, 'network_map.png')
            relative_path = os.path.relpath(network_map_path, output_dir)
            chart_paths['network_map'] = relative_path
            
            try:
                network_html_path = self._generate_network_map(scan_results.get('services', {}), network_map_path)
                if network_html_path:
                    chart_paths['network_html'] = os.path.relpath(network_html_path, output_dir)
            except Exception as e:
                logger.error(f"Error generating network map: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in _generate_charts_plotly: {str(e)}")
            
    def _generate_charts_matplotlib(self, scan_results: dict, charts_dir: str, chart_paths: dict, output_dir: str):
        """Generate all charts using Matplotlib if available."""
        if not self.matplotlib_available:
            return
            
        try:
            # 1. Severity distribution chart
            severity_data = self._get_severity_distribution(scan_results)
            severity_chart_path = os.path.join(charts_dir, 'severity_distribution.png')
            relative_path = os.path.relpath(severity_chart_path, output_dir)
            
            try:
                self._generate_severity_chart_matplotlib(severity_data, severity_chart_path)
                chart_paths['severity_chart'] = relative_path
            except Exception as e:
                logger.error(f"Error generating severity chart with matplotlib: {str(e)}")
            
            # 2. Service distribution chart
            service_data = self._get_service_distribution(scan_results)
            service_chart_path = os.path.join(charts_dir, 'service_distribution.png')
            relative_path = os.path.relpath(service_chart_path, output_dir)
            
            try:
                self._generate_service_chart_matplotlib(service_data, service_chart_path)
                chart_paths['service_chart'] = relative_path
            except Exception as e:
                logger.error(f"Error generating service chart with matplotlib: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in _generate_charts_matplotlib: {str(e)}")
            
    def _get_severity_distribution(self, scan_results: dict) -> dict:
        """Get distribution of vulnerabilities by severity."""
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Unknown': 0
        }

        for analysis in scan_results.get('analysis', []):
            if isinstance(analysis, dict):
                findings = analysis.get('analysis', [])
                if isinstance(findings, list):
                    for finding in findings:
                        if isinstance(finding, dict):
                            severity = finding.get('severity', 'Unknown')
                            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return severity_counts
        
    def _get_service_distribution(self, scan_results: dict) -> dict:
        """Get distribution of discovered services."""
        service_counts = {}
        
        for service in scan_results.get('services', {}).values():
            service_name = service.get('service', 'Unknown')
            service_counts[service_name] = service_counts.get(service_name, 0) + 1

        return service_counts
        
    def _generate_severity_chart(self, severity_data: dict, output_path: str):
        """Generate interactive pie chart for severity distribution using Plotly."""
        if self.plotly_available:
            try:
                # Prepare data
                labels = list(severity_data.keys())
                values = list(severity_data.values())
                
                # Generate colors for each severity
                colors = {
                    'Critical': '#dc3545',  # Red
                    'High': '#fd7e14',      # Orange
                    'Medium': '#ffc107',    # Yellow
                    'Low': '#28a745',       # Green
                    'Unknown': '#6c757d'    # Gray
                }
                
                pie_colors = [colors.get(label, '#6c757d') for label in labels]
                
                # Create interactive pie chart
                fig = go.Figure(data=[go.Pie(
                    labels=labels,
                    values=values,
                    hole=0.4,
                    marker_colors=pie_colors,
                    textinfo='label+percent',
                    hoverinfo='label+value',
                    textposition='inside'
                )])
                
                fig.update_layout(
                    title='Vulnerability Severity Distribution',
                    title_font_size=20,
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=-0.2,
                        xanchor="center",
                        x=0.5
                    ),
                    margin=dict(t=60, b=60, l=20, r=20),
                    height=500,
                    width=600,
                    hovermode='closest',
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)'
                )
                
                # Save the chart as HTML file for interactivity
                html_path = output_path.replace('.png', '.html')
                fig.write_html(html_path)
                
                # Save as image for fallback
                pio.write_image(fig, output_path, format='png')
                
                return html_path
                
            except Exception as e:
                logger.error(f"Error generating severity chart with plotly: {str(e)}")
                return self._generate_severity_chart_matplotlib(severity_data, output_path)
        else:
            return self._generate_severity_chart_matplotlib(severity_data, output_path)
    
    def _generate_severity_chart_matplotlib(self, severity_data: dict, output_path: str):
        """Fallback to matplotlib for generating severity chart."""
        try:
            import matplotlib.pyplot as plt

            # Prepare data
            labels = list(severity_data.keys())
            sizes = list(severity_data.values())
            
            # Color mapping
            colors = {
                'Critical': '#dc3545',
                'High': '#fd7e14',
                'Medium': '#ffc107',
                'Low': '#28a745',
                'Unknown': '#6c757d'
            }
            
            colors_list = [colors.get(label, '#6c757d') for label in labels]

            # Create pie chart
            plt.figure(figsize=(8, 8))
            plt.pie(sizes, labels=labels, colors=colors_list, autopct='%1.1f%%', startangle=90, shadow=True)
            plt.axis('equal')
            plt.title('Vulnerability Severity Distribution', fontsize=16)

            # Save chart
            plt.savefig(output_path, dpi=100, bbox_inches='tight', transparent=True)
            plt.close()

            return output_path
            
        except ImportError:
            logger.warning("Matplotlib not installed. Skipping chart generation.")
            return None
        except Exception as e:
            logger.error(f"Error generating severity chart: {str(e)}")
            return None

    def _generate_service_chart(self, service_data: dict, output_path: str):
        """Generate interactive bar chart for service distribution using Plotly."""
        if self.plotly_available:
            try:
                # Prepare data
                services = list(service_data.keys())
                counts = list(service_data.values())
                
                # Create bar chart
                fig = go.Figure()
                
                fig.add_trace(go.Bar(
                    x=services,
                    y=counts,
                    text=counts,
                    textposition='auto',
                    marker_color='#4e73df',
                    hoverinfo='x+y',
                ))
                
                fig.update_layout(
                    title='Network Service Distribution',
                    title_font_size=20,
                    xaxis=dict(
                        title='Service',
                        tickangle=-45,
                        tickfont=dict(size=12),
                    ),
                    yaxis=dict(
                        title='Count',
                        gridcolor='#e5e5e5',
                    ),
                    margin=dict(t=60, b=100, l=60, r=20),
                    height=500,
                    width=800,
                    hovermode='closest',
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)'
                )
                
                # Save interactive HTML version
                html_path = output_path.replace('.png', '.html')
                fig.write_html(html_path)
                
                # Save static image for fallback
                pio.write_image(fig, output_path, format='png')
                
                return html_path
                
            except Exception as e:
                logger.error(f"Error generating service chart with plotly: {str(e)}")
                return self._generate_service_chart_matplotlib(service_data, output_path)
        else:
            return self._generate_service_chart_matplotlib(service_data, output_path)
            
    def _generate_service_chart_matplotlib(self, service_data: dict, output_path: str):
        """Fallback to matplotlib for generating service chart."""
        try:
            import matplotlib.pyplot as plt

            # Prepare data
            services = list(service_data.keys())
            counts = list(service_data.values())

            # Create bar chart
            plt.figure(figsize=(10, 6))
            bars = plt.bar(services, counts, color='#4e73df')
            
            # Add count labels on top of the bars
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                         f'{height:.0f}', ha='center', va='bottom')
            
            plt.title('Network Service Distribution', fontsize=16)
            plt.xlabel('Service')
            plt.ylabel('Count')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()

            # Save chart
            plt.savefig(output_path, dpi=100, bbox_inches='tight', transparent=True)
            plt.close()

            return output_path
            
        except ImportError:
            logger.warning("Matplotlib not installed. Skipping chart generation.")
            return None
        except Exception as e:
            logger.error(f"Error generating service chart: {str(e)}")
            return None

    def _generate_risk_score_gauge(self, risk_level: str, output_path: str):
        """Generate risk score gauge chart."""
        if self.plotly_available:
            try:
                # Map risk level to a score
                risk_scores = {
                    'Critical': 90,
                    'High': 70,
                    'Medium': 50,
                    'Low': 30,
                    'Unknown': 0
                }
                score = risk_scores.get(risk_level, 0)
                
                # Determine color based on risk level
                colors = {
                    'Critical': '#dc3545',
                    'High': '#fd7e14',
                    'Medium': '#ffc107',
                    'Low': '#28a745',
                    'Unknown': '#6c757d'
                }
                color = colors.get(risk_level, '#6c757d')
                
                # Create gauge chart
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = score,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Risk Score", 'font': {'size': 24}},
                    gauge = {
                        'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                        'bar': {'color': color},
                        'bgcolor': "white",
                        'borderwidth': 2,
                        'bordercolor': "gray",
                        'steps': [
                            {'range': [0, 30], 'color': 'rgba(40, 167, 69, 0.3)'},
                            {'range': [30, 50], 'color': 'rgba(255, 193, 7, 0.3)'},
                            {'range': [50, 70], 'color': 'rgba(253, 126, 20, 0.3)'},
                            {'range': [70, 100], 'color': 'rgba(220, 53, 69, 0.3)'}
                        ],
                    }
                ))
                
                fig.update_layout(
                    font = {'color': "darkblue", 'family': "Arial"},
                    height=400,
                    width=500,
                    margin=dict(l=20, r=20, t=50, b=20),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)'
                )
                
                # Save interactive HTML version
                html_path = output_path.replace('.png', '.html')
                fig.write_html(html_path)
                
                # Save static image for fallback
                pio.write_image(fig, output_path, format='png')
                
                return html_path
                
            except Exception as e:
                logger.error(f"Error generating risk gauge with plotly: {str(e)}")
                return self._generate_risk_score_gauge_matplotlib(risk_level, output_path)
        else:
            return self._generate_risk_score_gauge_matplotlib(risk_level, output_path)
            
    def _generate_risk_score_gauge_matplotlib(self, risk_level: str, output_path: str):
        """Fallback to matplotlib for generating risk gauge."""
        try:
            import matplotlib.pyplot as plt
            import numpy as np
            from matplotlib.patches import Circle, Rectangle, Arc
            
            # Map risk level to a score
            risk_scores = {
                'Critical': 90,
                'High': 70,
                'Medium': 50,
                'Low': 30,
                'Unknown': 0
            }
            score = risk_scores.get(risk_level, 0)
            
            # Determine color based on risk level
            colors = {
                'Critical': '#dc3545',
                'High': '#fd7e14',
                'Medium': '#ffc107',
                'Low': '#28a745',
                'Unknown': '#6c757d'
            }
            color = colors.get(risk_level, '#6c757d')
            
            # Create matplotlib figure
            fig, ax = plt.subplots(figsize=(6, 4))
            
            # Draw background arcs for risk levels
            ax.add_patch(Arc((0.5, 0.2), 0.8, 0.8, theta1=180, theta2=0, 
                            facecolor='none', edgecolor='#e5e5e5', lw=15, alpha=0.3))
            
            # Draw color-coded arcs for each risk segment
            ax.add_patch(Arc((0.5, 0.2), 0.8, 0.8, theta1=180, theta2=135, 
                            facecolor='none', edgecolor='#28a745', lw=15, alpha=0.7))
            ax.add_patch(Arc((0.5, 0.2), 0.8, 0.8, theta1=135, theta2=90, 
                            facecolor='none', edgecolor='#ffc107', lw=15, alpha=0.7))
            ax.add_patch(Arc((0.5, 0.2), 0.8, 0.8, theta1=90, theta2=45, 
                            facecolor='none', edgecolor='#fd7e14', lw=15, alpha=0.7))
            ax.add_patch(Arc((0.5, 0.2), 0.8, 0.8, theta1=45, theta2=0, 
                            facecolor='none', edgecolor='#dc3545', lw=15, alpha=0.7))
            
            # Draw the needle
            angle = 180 - score * 1.8  # Scale score to angle (0-100 -> 180-0)
            needle_len = 0.4
            x = 0.5 + needle_len * np.cos(np.radians(angle))
            y = 0.2 + needle_len * np.sin(np.radians(angle))
            ax.plot([0.5, x], [0.2, y], color='black', lw=2)
            ax.add_patch(Circle((0.5, 0.2), 0.02, facecolor='black'))
            
            # Add risk level text
            ax.text(0.5, 0.7, f"Risk Level: {risk_level}", ha='center', va='center', 
                    fontsize=14, fontweight='bold', color=color)
            ax.text(0.5, 0.6, f"Score: {score}/100", ha='center', va='center', 
                    fontsize=12, color='#333333')
            
            # Add risk level labels
            ax.text(0.2, 0.15, "Low", ha='center', va='center', fontsize=10)
            ax.text(0.35, 0.05, "Medium", ha='center', va='center', fontsize=10)
            ax.text(0.65, 0.05, "High", ha='center', va='center', fontsize=10)
            ax.text(0.8, 0.15, "Critical", ha='center', va='center', fontsize=10)
            
            # Final chart formatting
            ax.set_xlim(0, 1)
            ax.set_ylim(0, 1)
            ax.axis('off')
            plt.title('Risk Score Gauge', fontsize=16, pad=20)
            plt.tight_layout()
            
            # Save chart
            plt.savefig(output_path, dpi=100, bbox_inches='tight', transparent=True)
            plt.close()
            
            return output_path
            
        except ImportError:
            logger.warning("Matplotlib not installed. Skipping risk gauge generation.")
            return None
        except Exception as e:
            logger.error(f"Error generating risk gauge: {str(e)}")
            return None
    
    def _generate_network_map(self, services: dict, output_path: str):
        """Generate network map visualization."""
        if self.plotly_available:
            try:
                import networkx as nx
                
                # Create graph
                G = nx.Graph()
                
                # Add nodes
                G.add_node("Target", type="target")
                
                # Group services by port
                for port_service in services.items():
                    port = port_service[0]
                    service_info = port_service[1]
                    service_name = service_info.get('service', 'unknown')
                    G.add_node(f"{port}/{service_name}", type="service")
                    G.add_edge("Target", f"{port}/{service_name}")
                
                # Get positions for all nodes
                pos = nx.spring_layout(G, k=0.5, iterations=50)
                
                # Separate nodes by type
                target_nodes = [n for n, d in G.nodes(data=True) if d.get('type') == "target"]
                service_nodes = [n for n, d in G.nodes(data=True) if d.get('type') == "service"]
                
                # Create edge trace
                edge_x = []
                edge_y = []
                for edge in G.edges():
                    x0, y0 = pos[edge[0]]
                    x1, y1 = pos[edge[1]]
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])
                
                edge_trace = go.Scatter(
                    x=edge_x, y=edge_y,
                    line=dict(width=1, color='#888'),
                    hoverinfo='none',
                    mode='lines')
                
                # Create node traces
                node_trace_target = go.Scatter(
                    x=[pos[node][0] for node in target_nodes],
                    y=[pos[node][1] for node in target_nodes],
                    mode='markers',
                    hoverinfo='text',
                    marker=dict(
                        color='#e74a3b',
                        size=25,
                        line=dict(width=2)
                    ),
                    text=target_nodes
                )
                
                node_trace_service = go.Scatter(
                    x=[pos[node][0] for node in service_nodes],
                    y=[pos[node][1] for node in service_nodes],
                    mode='markers+text',
                    hoverinfo='text',
                    marker=dict(
                        color='#4e73df',
                        size=15,
                        line=dict(width=1.5)
                    ),
                    text=service_nodes,
                    textposition="top center"
                )
                
                # Create figure
                fig = go.Figure(data=[edge_trace, node_trace_target, node_trace_service],
                                layout=go.Layout(
                                    title={
                                        'text': 'Network Service Map',
                                        'font': {'size': 16}
                                    },
                                    showlegend=False,
                                    hovermode='closest',
                                    margin=dict(b=20, l=5, r=5, t=40),
                                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                    width=800,
                                    height=600,
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    plot_bgcolor='rgba(0,0,0,0)'
                                ))
                
                # Save interactive HTML version
                html_path = output_path.replace('.png', '.html')
                fig.write_html(html_path)
                
                # Save static image for fallback
                pio.write_image(fig, output_path, format='png')
                
                return html_path
                
            except Exception as e:
                logger.error(f"Error generating network map with plotly: {str(e)}")
                return self._generate_network_map_matplotlib(services, output_path)
        else:
            return self._generate_network_map_matplotlib(services, output_path)
            
    def _generate_network_map_matplotlib(self, services: dict, output_path: str):
        """Fallback to matplotlib for generating network map."""
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
            # Create graph
            G = nx.Graph()
            
            # Add nodes
            G.add_node("Target", type="target")
            
            # Group services by port
            for port_service in services.items():
                port = port_service[0]
                service_info = port_service[1]
                service_name = service_info.get('service', 'unknown')
                G.add_node(f"{port}/{service_name}", type="service")
                G.add_edge("Target", f"{port}/{service_name}")
            
            # Set up the plot
            plt.figure(figsize=(10, 8))
            pos = nx.spring_layout(G)
            
            # Draw nodes with different colors and sizes
            target_nodes = [n for n, d in G.nodes(data=True) if d.get('type') == "target"]
            service_nodes = [n for n, d in G.nodes(data=True) if d.get('type') == "service"]
            
            nx.draw_networkx_nodes(G, pos, nodelist=target_nodes, node_color='#e74a3b', node_size=500)
            nx.draw_networkx_nodes(G, pos, nodelist=service_nodes, node_color='#4e73df', node_size=300)
            
            # Draw edges
            nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.5)
            
            # Draw labels
            nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')
            
            plt.title('Network Service Map')
            plt.axis('off')
            plt.tight_layout()
            
            # Save chart
            plt.savefig(output_path, dpi=100, bbox_inches='tight', transparent=True)
            plt.close()
            
            return output_path
            
        except ImportError:
            logger.warning("NetworkX or Matplotlib not installed. Skipping network map generation.")
            return None
        except Exception as e:
            logger.error(f"Error generating network map: {str(e)}")
            return None

    def _get_report_template(self):
        """Get basic HTML report template."""
        try:
            # Try to use Jinja2 template first
            if self.template_env:
                return self.template_env.get_template('report.html')
        except Exception as e:
            logger.warning(f"Error loading template from file: {str(e)}")
            logger.info("Using embedded basic template")
        
        # Fall back to embedded template
        from jinja2 import Template
        
        template_str = """
<!DOCTYPE html>
        <html>
<head>
    <title>Scan Report for {{ scan_results.target }}</title>
            <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1, h2, h3 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .risk-critical {{ background-color: #ffcccc; }}
        .risk-high {{ background-color: #ffdacc; }}
        .risk-medium {{ background-color: #fff5cc; }}
        .risk-low {{ background-color: #e6ffcc; }}
        .chart {{ max-width: 500px; margin: 20px 0; }}
        .analysis-section {{ margin-top: 15px; padding: 10px; background-color: #f9f9f9; border-left: 4px solid #4e73df; }}
        .source-tag {{ display: inline-block; padding: 3px 6px; background-color: #e2e8f0; border-radius: 4px; font-size: 12px; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; background-color: #f8f9fc; padding: 12px; overflow-x: auto; }}
            </style>
</head>
        <body>
    <h1>Scan Report for {{ scan_results.target }}</h1>
    <h2>Risk Level: {{ scan_results.risk_level }}</h2>
    
    {% if severity_chart or service_chart %}
    <div class="charts">
        {% if severity_chart %}
        <div>
                    <h3>Severity Distribution</h3>
            <img src="{{ severity_chart }}" class="chart" alt="Severity Distribution">
            </div>
        {% endif %}
        
        {% if service_chart %}
        <div>
                    <h3>Service Distribution</h3>
            <img src="{{ service_chart }}" class="chart" alt="Service Distribution">
            </div>
        {% endif %}
        </div>
    {% endif %}

    <h2>Findings</h2>
                <table>
                    <tr>
            <th>Port/Protocol</th>
                        <th>Service</th>
            <th>Risk Level</th>
            <th>Recommendations</th>
                        </tr>
                    {% for port, service in scan_results.services.items() %}
        <tr class="risk-{{ service.risk_level|lower if service.risk_level else 'unknown' }}">
            <td>{{ port }}/{{ service.transport }}</td>
                        <td>{{ service.service }}</td>
            <td>{{ service.risk_level }}</td>
            <td>
                {% if service.recommendations %}
                <ul>
                    {% for rec in service.recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                
                {% if service.identification_failed %}
                <p><em>Service identification failed. Manual investigation recommended.</em></p>
                {% endif %}
            </td>
                        </tr>
                        {% endfor %}
                </table>
    
    <p>Scan completed on {{ timestamp }} (Duration: {{ "%.2f"|format(scan_duration) }} seconds)</p>
</body>
</html>
        """
        
        return Template(template_str)

    def _get_enhanced_report_template(self):
        """Get enhanced HTML report template with interactive elements."""
        try:
            # Try to use Jinja2 template first
            if self.template_env:
                return self.template_env.get_template('enhanced_report.html')
        except Exception as e:
            logger.warning(f"Error loading enhanced template from file: {str(e)}")
            logger.info("Using embedded enhanced template")
        
        # Fall back to embedded template
        from jinja2 import Template
        
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {{ data.target }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <header class="bg-white shadow rounded-lg p-6 mb-8">
            <h1 class="text-3xl font-bold text-gray-900">Security Scan Report</h1>
            <div class="mt-4 text-gray-600">
                <p><strong>Target:</strong> {{ data.target }}</p>
                <p><strong>Scan Type:</strong> {{ data.scan_type }}</p>
                <p><strong>Timestamp:</strong> {{ current_time }}</p>
                <p>
                    <strong>Risk Level:</strong> 
                    <span class="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full
                    {% if data.risk_level == 'Critical' %}bg-red-100 text-red-800{% elif data.risk_level == 'High' %}bg-orange-100 text-orange-800{% elif data.risk_level == 'Medium' %}bg-yellow-100 text-yellow-800{% elif data.risk_level == 'Low' %}bg-green-100 text-green-800{% else %}bg-gray-100 text-gray-800{% endif %}
                    ">
                    {{ data.risk_level }}
                    </span>
                </p>
            </div>
        </header>

        <!-- Charts Dashboard -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
            {% if charts and charts.severity_chart %}
            <div class="bg-white shadow rounded-lg p-6">
                <h2 class="text-xl font-semibold mb-4">Severity Distribution</h2>
                <div class="h-64">
                    {% if charts.severity_html and has_interactive_charts %}
                    <iframe src="{{ charts.severity_html }}" frameborder="0" width="100%" height="100%"></iframe>
                    {% else %}
                    <img src="{{ charts.severity_chart }}" alt="Severity Distribution" class="max-w-full h-auto">
                    {% endif %}
                </div>
            </div>
            {% endif %}
            
            {% if charts and charts.service_chart %}
            <div class="bg-white shadow rounded-lg p-6">
                <h2 class="text-xl font-semibold mb-4">Service Distribution</h2>
                <div class="h-64">
                    {% if charts.service_html and has_interactive_charts %}
                    <iframe src="{{ charts.service_html }}" frameborder="0" width="100%" height="100%"></iframe>
                    {% else %}
                    <img src="{{ charts.service_chart }}" alt="Service Distribution" class="max-w-full h-auto">
                    {% endif %}
                </div>
            </div>
            {% endif %}
        </div>
        
        <!-- Additional Charts -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
            {% if charts and charts.risk_gauge %}
            <div class="bg-white shadow rounded-lg p-6">
                <h2 class="text-xl font-semibold mb-4">Risk Assessment</h2>
                <div class="h-64">
                    {% if charts.risk_html and has_interactive_charts %}
                    <iframe src="{{ charts.risk_html }}" frameborder="0" width="100%" height="100%"></iframe>
                    {% else %}
                    <img src="{{ charts.risk_gauge }}" alt="Risk Assessment" class="max-w-full h-auto">
                    {% endif %}
                </div>
            </div>
            {% endif %}
            
            {% if charts and charts.network_map %}
            <div class="bg-white shadow rounded-lg p-6">
                <h2 class="text-xl font-semibold mb-4">Network Map</h2>
                <div class="h-64">
                    {% if charts.network_html and has_interactive_charts %}
                    <iframe src="{{ charts.network_html }}" frameborder="0" width="100%" height="100%"></iframe>
                    {% else %}
                    <img src="{{ charts.network_map }}" alt="Network Map" class="max-w-full h-auto">
                    {% endif %}
                </div>
            </div>
            {% endif %}
        </div>

        <!-- Key Findings -->
        <div class="bg-white shadow rounded-lg p-6 mb-8">
            <h2 class="text-2xl font-bold mb-4">Key Findings</h2>
            <div class="space-y-4">
                {% for port, service in data.services.items() %}
                    {% set risk_class = 'border-gray-500' %}
                    {% if service.risk_level == 'Critical' %}
                        {% set risk_class = 'border-red-500' %}
                    {% elif service.risk_level == 'High' %}
                        {% set risk_class = 'border-orange-500' %}
                    {% elif service.risk_level == 'Medium' %}
                        {% set risk_class = 'border-yellow-500' %}
                    {% elif service.risk_level == 'Low' %}
                        {% set risk_class = 'border-green-500' %}
                    {% endif %}
                    
                    <div class="border-l-4 pl-4 py-2 {{ risk_class }}">
                        <div class="flex justify-between items-start">
                            <h3 class="text-lg font-medium text-gray-900">{{ port }}/{{ service.protocol }} - {{ service.service }}</h3>
                            <span class="px-2 py-1 text-xs font-semibold rounded-full
                                {% if service.risk_level == 'Critical' %}bg-red-100 text-red-800{% elif service.risk_level == 'High' %}bg-orange-100 text-orange-800{% elif service.risk_level == 'Medium' %}bg-yellow-100 text-yellow-800{% elif service.risk_level == 'Low' %}bg-green-100 text-green-800{% else %}bg-gray-100 text-gray-800{% endif %}">
                                {{ service.risk_level }}
                            </span>
                        </div>
                        
                        {% if service.product %}
                        <p class="mt-2 text-sm text-gray-600">
                            <span class="font-medium">Product:</span> {{ service.product }} {{ service.version }}
                        </p>
                        {% endif %}
                        
                        {% if service.analyses %}
                        <div class="mt-4">
                            <h4 class="font-semibold text-gray-700 mb-2">Analysis:</h4>
                            {% for analysis_item in service.analyses %}
                            <div class="bg-gray-50 p-3 mb-2 rounded border-l-4 
                                {% if analysis_item.source == 'Gemini AI' or analysis_item.source == 'OpenAI' %}border-blue-500
                                {% elif analysis_item.source == 'Enhanced Analysis' %}border-purple-500
                                {% else %}border-gray-300{% endif %}">
                                <div class="flex justify-between mb-1">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                                        {% if analysis_item.source == 'Gemini AI' or analysis_item.source == 'OpenAI' %}bg-blue-100 text-blue-800
                                        {% elif analysis_item.source == 'Enhanced Analysis' %}bg-purple-100 text-purple-800
                                        {% else %}bg-gray-100 text-gray-800{% endif %}">
                                        {{ analysis_item.source }}
                                    </span>
                                    <span class="text-xs text-gray-500">Confidence: {{ analysis_item.confidence }}</span>
                                </div>
                                <div class="text-sm whitespace-pre-wrap">{{ analysis_item.analysis }}</div>
                            </div>
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
            </div>

        {% if data.system_info %}
        <!-- System Information -->
        <div class="bg-white shadow rounded-lg p-6 mb-8">
            <h2 class="text-2xl font-bold mb-4">System Information</h2>
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Key</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Value</th>
                        </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    {% for key, value in data.system_info.items() %}
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ key }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ value }}</td>
                        </tr>
                        {% endfor %}
                </tbody>
                </table>
        </div>
        {% endif %}

        <!-- Executive Summary -->
        <div class="bg-white shadow rounded-lg p-6 mb-8">
            <h2 class="text-2xl font-bold mb-4">Executive Summary</h2>
            <p class="mb-4">This security scan identified a total of <strong>{{ data.services|length }}</strong> service(s) running on the target system.</p>
            
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div class="bg-red-50 p-4 rounded-lg border border-red-200">
                    <span class="text-red-700 font-medium">Critical</span>
                    <p class="text-2xl font-bold text-red-700">{{ data.count_by_risk.Critical }}</p>
                </div>
                <div class="bg-orange-50 p-4 rounded-lg border border-orange-200">
                    <span class="text-orange-700 font-medium">High</span>
                    <p class="text-2xl font-bold text-orange-700">{{ data.count_by_risk.High }}</p>
                </div>
                <div class="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
                    <span class="text-yellow-700 font-medium">Medium</span>
                    <p class="text-2xl font-bold text-yellow-700">{{ data.count_by_risk.Medium }}</p>
                </div>
                <div class="bg-green-50 p-4 rounded-lg border border-green-200">
                    <span class="text-green-700 font-medium">Low</span>
                    <p class="text-2xl font-bold text-green-700">{{ data.count_by_risk.Low }}</p>
                </div>
            </div>
            
            <p>Overall risk level is determined to be <strong>{{ data.risk_level }}</strong>.</p>
            
            {% if data.summary %}
            <div class="bg-blue-50 p-4 rounded-lg border border-blue-200 mt-4">
                <h3 class="text-lg font-medium text-blue-800 mb-2">AI Analysis Summary</h3>
                <p class="text-blue-800">{{ data.summary }}</p>
            </div>
            {% endif %}
        </div>

        <footer class="text-center text-gray-500 text-sm mt-8">
            <p>Generated on {{ current_time }} by AI-Powered Vulnerability Scanner</p>
            <p>&copy; {{ current_year }} RHAZOUANE SALAH-EDDINE. All rights reserved.</p>
        </footer>
    </div>
</body>
</html>
"""
        
        return Template(template_str)

    def _render_template(self, template_path: str, context: dict):
        """Render the template with the given context."""
        try:
            if self.jinja_available:
                with open(template_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                
                # Create Jinja2 template from the content
                template = Template(template_content)
                
                # Ensure charts is a dict to prevent attribute errors
                if 'charts' in context and context['charts'] is None:
                    context['charts'] = {}
                
                # Render the template with the provided context
                return template.render(**context)
            else:
                # Fallback to basic string template if Jinja2 is not available
                with open(template_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                return self._basic_template_render(template_content, context)
        except Exception as e:
            logger.error(f"Error rendering template: {str(e)}")
            raise
