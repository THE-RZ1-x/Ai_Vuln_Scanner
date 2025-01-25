#!/usr/bin/env python3
"""
Interactive HTML Report Generator
Part of AI-Powered Vulnerability Scanner
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader
from dataclasses import dataclass
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

logger = logging.getLogger(__name__)

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

class ReportGenerator:
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = template_dir
        self._ensure_template_dir()
        self.env = Environment(loader=FileSystemLoader(template_dir))
        
    def generate_report(self, data: ReportData, output_dir: str) -> str:
        """Generate an interactive HTML report."""
        try:
            # Create visualizations
            charts = self._create_visualizations(data)
            
            # Render the template
            template = self.env.get_template("report_template.html")
            report_html = template.render(
                data=data,
                charts=charts,
                current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            # Save the report
            os.makedirs(output_dir, exist_ok=True)
            report_path = os.path.join(output_dir, f"security_report_{data.timestamp}.html")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_html)
                
            logger.info(f"Report generated successfully: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise
            
    def _create_visualizations(self, data: ReportData) -> Dict[str, str]:
        """Create interactive visualizations using plotly."""
        charts = {}
        
        # Vulnerability severity distribution
        severity_counts = self._count_severity(data.vulnerabilities)
        fig = go.Figure(data=[
            go.Pie(labels=list(severity_counts.keys()),
                  values=list(severity_counts.values()),
                  hole=.3)
        ])
        fig.update_layout(title="Vulnerability Severity Distribution")
        charts['severity_dist'] = fig.to_html(full_html=False)
        
        # Vulnerability types breakdown
        vuln_types = self._count_vulnerability_types(data.vulnerabilities)
        fig = px.bar(
            x=list(vuln_types.keys()),
            y=list(vuln_types.values()),
            title="Vulnerability Types"
        )
        charts['vuln_types'] = fig.to_html(full_html=False)
        
        # Risk score timeline
        if hasattr(data, 'risk_timeline'):
            df = pd.DataFrame(data.risk_timeline)
            fig = px.line(df, x='timestamp', y='risk_score',
                         title="Risk Score Timeline")
            charts['risk_timeline'] = fig.to_html(full_html=False)
            
        # Network services distribution
        service_types = self._count_service_types(data.network_services)
        fig = px.treemap(
            names=list(service_types.keys()),
            parents=[""] * len(service_types),
            values=list(service_types.values()),
            title="Network Services Distribution"
        )
        charts['service_dist'] = fig.to_html(full_html=False)
        
        return charts
        
    def _count_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
        
    def _count_vulnerability_types(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        return type_counts
        
    def _count_service_types(self, services: List[Dict]) -> Dict[str, int]:
        """Count network services by type."""
        service_counts = {}
        for service in services:
            service_type = service.get("name", "Unknown")
            service_counts[service_type] = service_counts.get(service_type, 0) + 1
        return service_counts
        
    def _ensure_template_dir(self):
        """Ensure template directory exists and create default template if needed."""
        os.makedirs(self.template_dir, exist_ok=True)
        template_path = os.path.join(self.template_dir, "report_template.html")
        
        if not os.path.exists(template_path):
            with open(template_path, "w", encoding="utf-8") as f:
                f.write(self._get_default_template())
                
    def _get_default_template(self) -> str:
        """Return default HTML template with modern design."""
        return """
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
                <p><strong>Timestamp:</strong> {{ data.timestamp }}</p>
                <p><strong>Risk Score:</strong> {{ "%.2f"|format(data.risk_score) }}/10</p>
            </div>
        </header>

        <!-- Dashboard -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
            <div class="bg-white shadow rounded-lg p-6">
                <h2 class="text-xl font-semibold mb-4">Severity Distribution</h2>
                {{ charts.severity_dist | safe }}
            </div>
            <div class="bg-white shadow rounded-lg p-6">
                <h2 class="text-xl font-semibold mb-4">Vulnerability Types</h2>
                {{ charts.vuln_types | safe }}
            </div>
        </div>

        <!-- Vulnerabilities -->
        <div class="bg-white shadow rounded-lg p-6 mb-8">
            <h2 class="text-2xl font-bold mb-4">Vulnerabilities</h2>
            <div class="overflow-x-auto">
                <table class="min-w-full table-auto">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Remediation</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        {% for vuln in data.vulnerabilities %}
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ vuln.type }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                                    {% if vuln.severity == 'Critical' %}bg-red-100 text-red-800
                                    {% elif vuln.severity == 'High' %}bg-orange-100 text-orange-800
                                    {% elif vuln.severity == 'Medium' %}bg-yellow-100 text-yellow-800
                                    {% else %}bg-green-100 text-green-800{% endif %}">
                                    {{ vuln.severity }}
                                </span>
                            </td>
                            <td class="px-6 py-4 text-sm text-gray-500">{{ vuln.description }}</td>
                            <td class="px-6 py-4 text-sm text-gray-500">{{ vuln.remediation }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Network Services -->
        <div class="bg-white shadow rounded-lg p-6 mb-8">
            <h2 class="text-2xl font-bold mb-4">Network Services</h2>
            {{ charts.service_dist | safe }}
            <div class="mt-4 overflow-x-auto">
                <table class="min-w-full table-auto">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Port</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Version</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        {% for service in data.network_services %}
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ service.name }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ service.port }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ service.version }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ service.status }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Web Vulnerabilities -->
        {% if data.web_vulnerabilities %}
        <div class="bg-white shadow rounded-lg p-6 mb-8">
            <h2 class="text-2xl font-bold mb-4">Web Vulnerabilities</h2>
            <div class="overflow-x-auto">
                <table class="min-w-full table-auto">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Parameter</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        {% for vuln in data.web_vulnerabilities %}
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ vuln.type }}</td>
                            <td class="px-6 py-4 text-sm text-gray-500">{{ vuln.url }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ vuln.parameter }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                                    {% if vuln.severity == 'Critical' %}bg-red-100 text-red-800
                                    {% elif vuln.severity == 'High' %}bg-orange-100 text-orange-800
                                    {% elif vuln.severity == 'Medium' %}bg-yellow-100 text-yellow-800
                                    {% else %}bg-green-100 text-green-800{% endif %}">
                                    {{ vuln.severity }}
                                </span>
                            </td>
                            <td class="px-6 py-4 text-sm text-gray-500">{{ vuln.description }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <footer class="text-center text-gray-500 text-sm mt-8">
            <p>Generated on {{ current_time }} by AI-Powered Vulnerability Scanner</p>
        </footer>
    </div>
</body>
</html>
"""
