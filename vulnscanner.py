#!/usr/bin/env python3
"""
Copyright (c) 2025 [RHAZOUANE SALAH-EDDINE]
All rights reserved.

This code is licensed under the [Specify License, e.g., MIT License]. You may not use this code without permission.
"""
"""
AI-Powered Vulnerability Scanner
Developed by RZ1 (https://github.com/THE-RZ1-x)
Repository: https://github.com/THE-RZ1-x/Ai_Vuln_Scanner

A sophisticated vulnerability scanner that uses AI to analyze and detect security vulnerabilities
in network services and systems.
"""
# -*- coding: utf-8 -*-
# Author: cbk914

import os
import re
import sys
import json
import time
import socket
import logging
import argparse
import ipaddress
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
import nmap
import shodan
import vulners
import requests
import aiohttp
import asyncio
from tqdm import tqdm
import google.generativeai as genai
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from requests.exceptions import RequestException
import vulners
import shodan
from web_scanner import WebScanner, WebVulnerability
from report_generator import ReportGenerator, ReportData
from container_scanner import ContainerScanner, ContainerScanResult, ContainerVulnerability
from cloud_scanner import CloudScanner, CloudScanResult

class CloudVulnerability:
    """Class representing a vulnerability found through cloud security scanning."""
    def __init__(self, name: str, description: str, severity: str, recommendations: List[str]):
        self.name = name
        self.description = description
        self.severity = severity
        self.recommendations = recommendations

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'recommendations': self.recommendations
        }

def analyze_service_offline(service_info: dict) -> list:
    """Analyze a service without requiring external APIs."""
    recommendations = []
    
    # Basic service checks
    if not service_info.get('product'):
        recommendations.append("Service identification failed - manual investigation recommended")
        return recommendations
    
    # Version checks
    if service_info.get('version'):
        recommendations.append(f"Update {service_info.get('product')} to the latest version")
    
    # Port-specific recommendations
    port = service_info.get('port', 0)
    if port < 1024:
        recommendations.append(f"Service running on privileged port {port}. Consider running as non-root if possible.")
    
    # Protocol recommendations
    if service_info.get('protocol') == 'tcp':
        recommendations.append("Ensure firewall rules restrict access to necessary IPs only")
    
    # SSL/TLS checks
    if 'http' in service_info.get('name', '').lower() or 'https' in service_info.get('name', '').lower():
        recommendations.extend([
            "Verify SSL/TLS configuration and certificate validity",
            "Enable HTTP Strict Transport Security (HSTS)",
            "Implement proper Content Security Policy (CSP)"
        ])
    
    # Database recommendations
    if any(db in service_info.get('name', '').lower() for db in ['mysql', 'postgresql', 'mongodb', 'redis']):
        recommendations.extend([
            "Ensure strong authentication is enabled",
            "Regularly backup database content",
            "Monitor for unusual access patterns"
        ])
    
    # Remote access recommendations
    if any(remote in service_info.get('name', '').lower() for remote in ['ssh', 'rdp', 'vnc']):
        recommendations.extend([
            "Use strong authentication methods",
            "Implement fail2ban or similar brute-force protection",
            "Restrict access to specific IP ranges"
        ])
    
    return recommendations

# Parse command line arguments
parser = argparse.ArgumentParser(description='AI-powered vulnerability scanner')
parser.add_argument('-t', '--target', required=True, help='Target IP address, hostname, container image, or cloud provider')
parser.add_argument('-s', '--scan-type', choices=['basic', 'comprehensive', 'container', 'cloud'], default='basic',
                  help='Type of scan to perform')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('-o', '--output', help='Output file name (without extension)')
parser.add_argument('--container', action='store_true', help='Treat target as a container image')
parser.add_argument('--cloud-providers', nargs='+', choices=['aws', 'azure', 'gcp'],
                  help='Cloud providers to scan when using cloud scan type')
args = parser.parse_args()

# Configure logging based on verbosity
if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize global scanner
scanner = None
ai_analyzer = None

def init_scanner():
    """Initialize the vulnerability scanner with all components."""
    try:
        # Initialize scanner components
        scanner = VulnerabilityScanner()
        
        # Initialize APIs
        scanner.initialize_apis()
        
        # Initialize analyzers
        scanner.ai_analyzer = AISecurityAnalyzer()
        
        # Initialize scanners
        scanner.web_scanner = WebScanner()
        scanner.container_scanner = ContainerScanner()
        scanner.cloud_scanner = CloudScanner()
        
        # Initialize report generator
        scanner.report_generator = ReportGenerator()
        
        return scanner
    except Exception as e:
        logger.error(f"Error initializing scanner: {str(e)}")
        # Still return a partially initialized scanner to continue with limited functionality
        return VulnerabilityScanner()

class VulnerabilityScanner:
    def __init__(self):
        self.nmap_scanner = None
        self.security_apis = None
        self.ai_analyzer = AISecurityAnalyzer()
        self.report_generator = None
        self._partial_results = {}
        self.openai_api = None
        self.gemini_api = None
        self.vulners_api = None
        self.shodan_api = None
        self.initialize_apis()
        
    async def scan(self, target: str, scan_type: str = 'basic') -> dict:
        """
        Perform a vulnerability scan on the specified target.
        
        Args:
            target (str): Target IP or hostname
            scan_type (str): Type of scan ('basic', 'full', 'stealth')
            
        Returns:
            dict: Scan results including vulnerabilities and recommendations
        """
        try:
            # Initialize scan results
            scan_results = {
                'target': target,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'services': [],
                'vulnerabilities': [],
                'recommendations': []
            }
            
            # Resolve target if hostname
            target_ip = await self._resolve_target(target)
            if not target_ip:
                raise ValueError(f"Could not resolve target: {target}")
            
            # Configure scan options based on type
            scan_options = self._get_scan_options(scan_type)
            
            # Initialize nmap scanner
            nm = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap',))
            
            # Run the scan
            logging.info(f"Starting {scan_type} scan on {target}")
            nm.scan(target_ip, arguments=scan_options)
            
            # Process scan results
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = list(nm[host][proto].keys())
                    for port in ports:
                        service_info = nm[host][proto][port]
                        service_info['port'] = port
                        service_info['protocol'] = proto
                        
                        # Analyze service for vulnerabilities
                        vulns = await self.analyze_service(service_info)
                        if vulns:
                            scan_results['vulnerabilities'].extend(vulns)
                        
                        # Add service info to results
                        scan_results['services'].append({
                            'port': port,
                            'protocol': proto,
                            'state': service_info.get('state', ''),
                            'name': service_info.get('name', ''),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extrainfo': service_info.get('extrainfo', '')
                        })
            
            # Generate recommendations based on findings
            scan_results['recommendations'] = self._generate_recommendations(scan_results['vulnerabilities'])
            
            # Add overall risk assessment
            scan_results['risk_level'] = self._assess_risk(scan_results['vulnerabilities'])
            
            return scan_results
            
        except Exception as e:
            logging.error(f"Error during scan: {str(e)}")
            raise

    def _get_scan_options(self, scan_type: str) -> str:
        """Get nmap scan options based on scan type."""
        options = {
            'basic': '-sV -sC -O --version-intensity 5',
            'full': '-sV -sC -O -p- -A --version-intensity 7',
            'stealth': '-sS -sV -O -T2 --version-intensity 3'
        }
        return options.get(scan_type, options['basic'])

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate security recommendations based on vulnerabilities."""
        recommendations = []
        
        # Group vulnerabilities by severity
        severity_groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for vuln in vulnerabilities:
            severity = self._determine_severity(vuln)
            if severity in severity_groups:
                severity_groups[severity].append(vuln)
        
        # Generate recommendations for each severity group
        for severity, vulns in severity_groups.items():
            if vulns:
                recommendations.append({
                    'severity': severity,
                    'count': len(vulns),
                    'summary': f"Found {len(vulns)} {severity} severity issues",
                    'actions': self._get_actions_for_severity(severity, vulns)
                })
        
        return recommendations

    def _determine_severity(self, vuln) -> str:
        """Determine the severity of a vulnerability."""
        try:
            # Handle dictionary input
            if isinstance(vuln, dict):
                if 'cvss' in vuln:
                    score = float(vuln['cvss'])
                elif 'severity' in vuln:
                    score = float(vuln['severity'])
                else:
                    return 'unknown'
            # Handle numeric input
            elif isinstance(vuln, (int, float)):
                score = float(vuln)
            # Handle string input
            elif isinstance(vuln, str):
                # Default for strings
                return 'medium'
            else:
                return 'unknown'
                
            # Determine severity based on score
            if score >= 9.0:
                return 'critical'
            elif score >= 7.0:
                return 'high'
            elif score >= 4.0:
                return 'medium'
            else:
                return 'low'
        except Exception as e:
            logger.debug(f"Error determining severity: {str(e)}")
            return 'unknown'

    def _get_actions_for_severity(self, severity: str, vulns: List[Dict]) -> List[str]:
        """Get recommended actions based on severity and vulnerabilities."""
        actions = []
        
        if severity == 'critical':
            actions.append("Immediate patching required")
            actions.append("Consider taking affected systems offline until patched")
            actions.append("Review and update security controls")
        elif severity == 'high':
            actions.append("Schedule urgent patching")
            actions.append("Implement additional security controls")
            actions.append("Monitor affected systems closely")
        elif severity == 'medium':
            actions.append("Plan for patching in next maintenance window")
            actions.append("Review security configurations")
        else:
            actions.append("Address during regular maintenance")
            actions.append("Update documentation and monitoring")
        
        # Add specific actions based on vulnerability types
        for vuln in vulns:
            if 'recommendations' in vuln:
                actions.extend(vuln['recommendations'])
        
        return list(set(actions))  # Remove duplicates

    async def analyze_service(self, service_info: Dict) -> List[Dict]:
        """Analyze a service using available AI models and APIs."""
        vulnerabilities = []
        
        try:
            # Try AI analysis if available
            if self.ai_analyzer:
                try:
                    ai_results = await self.ai_analyzer.analyze_service(service_info)
                    if ai_results and isinstance(ai_results, list):
                        vulnerabilities.extend(ai_results)
                    elif ai_results:
                        vulnerabilities.append(ai_results)
                except Exception as e:
                    logging.error(f"Error in AI analysis: {str(e)}")
                    logging.debug(f"AI analysis exception details: {traceback.format_exc()}")
            
            # If AI analysis failed or no AI services available, use offline analysis
            if not vulnerabilities:
                try:
                    offline_results = analyze_service_offline(service_info)
                    if isinstance(offline_results, list):
                        vulnerabilities.extend(offline_results)
                    elif offline_results:
                        vulnerabilities.append({
                            'source': 'Offline Analysis',
                            'analysis': str(offline_results),
                            'confidence': 'low'
                        })
                except Exception as e:
                    logging.error(f"Error in offline analysis: {str(e)}")
                    logging.debug(f"Offline analysis exception details: {traceback.format_exc()}")
                    # Provide a minimal set of recommendations as fallback
                    vulnerabilities.append({
                        'source': 'Basic Analysis',
                        'analysis': f"Service {service_info.get('name', 'unknown')} on port {service_info.get('port', 'unknown')} should be reviewed manually.",
                        'confidence': 'very low'
                    })
            
            # Add Vulners data if available
            if self.vulners_api:
                try:
                    software = f"{service_info.get('name', '')} {service_info.get('version', '')}".strip()
                    if software:
                        vulners_results = self.vulners_api.softwareVulnerabilities(software)
                        for vuln_type, vulns in vulners_results.items():
                            if vuln_type not in ['info', 'blog', 'bugbounty']:
                                for vuln in vulns:
                                    vulnerabilities.append({
                                        'source': 'Vulners',
                                        'id': vuln.get('id', 'unknown'),
                                        'title': vuln.get('title', 'Unknown vulnerability'),
                                        'description': vuln.get('description', ''),
                                        'type': vuln_type,
                                        'cvss': vuln.get('cvss', {}).get('score', 0),
                                        'published': vuln.get('published', ''),
                                        'references': vuln.get('references', [])
                                    })
                except Exception as e:
                    logging.error(f"Error searching Vulners: {str(e)}")
                    logging.debug(f"Vulners exception details: {traceback.format_exc()}")
            
            return vulnerabilities
            
        except Exception as e:
            logging.error(f"Error analyzing service: {str(e)}")
            logging.debug(f"Service analysis exception details: {traceback.format_exc()}")
            # Return at least some basic information even in case of complete failure
            return [{
                'source': 'Error Recovery',
                'analysis': f"Analysis failed for {service_info.get('name', 'unknown service')} on port {service_info.get('port', 'unknown')}. Manual review recommended.",
                'confidence': 'none',
                'error': str(e)
            }]
            
    async def _scan_network(self, target: str, scan_type: str = 'basic') -> dict:
        """
        Perform a network vulnerability scan.
        """
        self._partial_results = {
            'target': target,
            'scan_type': scan_type,
            'status': 'in_progress',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Validate and resolve target
            if not self._validate_target(target):
                return {
                    'error': f"Invalid target: {target}",
                    'status': 'failed'
                }
                
            ip = await self._resolve_target(target)
            if not ip:
                return {
                    'error': f"Could not resolve target: {target}",
                    'status': 'failed'
                }
                
            # Get target information
            hostnames = await self._get_hostnames(ip)
            self._partial_results['hostnames'] = hostnames
            
            # Scan ports
            print(f"Scanning ports on {ip}...")
            ports = await self._scan_ports(ip)
            if not ports:
                print("No open ports found")
                ports = {}
                
            # Analyze services
            services = {}
            for port, protocol in ports.items():
                service = await self._analyze_service(ip, port, protocol)
                if service:
                    services[f"{port}/{protocol}"] = service
                    
            self._partial_results['services'] = services
            
            # Get external information
            external_info = await self._get_external_info(ip)
            
            # Calculate risk level
            risk_level = self._calculate_risk(services)
            
            # Compile results
            results = {
                'target': target,
                'ip': ip,
                'hostnames': hostnames,
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'services': services,
                'external_info': external_info,
                'risk_level': risk_level,
                'status': 'completed'
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}")
            return {
                'error': str(e),
                'status': 'failed',
                'partial_results': self._partial_results
            }
            
    def _validate_target(self, target: str) -> bool:
        """Validate target format."""
        if not target:
            return False
        # Add more validation as needed
        return True
        
    async def _resolve_target(self, target: str) -> Optional[str]:
        """Resolve hostname to IP."""
        try:
            if is_ip_address(target):
                return target
            ip = socket.gethostbyname(target)
            print(f"Resolved {target} to {ip}")
            return ip
        except Exception as e:
            logger.error(f"Could not resolve target: {str(e)}")
            return None
            
    async def _get_hostnames(self, ip: str) -> List[str]:
        """Get hostnames for IP."""
        try:
            hostnames = []
            info = socket.gethostbyaddr(ip)
            if info and info[0]:
                hostnames.append(info[0])
            return hostnames
        except Exception:
            return []
            
    async def _scan_ports(self, ip: str) -> Dict[int, str]:
        """Scan ports on target."""
        try:
            self.nmap_scanner.scan(ip, arguments='-sV -sC -p-')
            
            ports = {}
            for host in self.nmap_scanner.all_hosts():
                for proto in self.nmap_scanner[host].all_protocols():
                    lport = self.nmap_scanner[host][proto].keys()
                    for port in lport:
                        service = self.nmap_scanner[host][proto][port]
                        if service['state'] == 'open':
                            ports[port] = proto
            
            return ports
            
        except Exception as e:
            logger.error(f"Error during port scan: {str(e)}")
            return {}
            
    async def _analyze_service(self, ip: str, port: int, protocol: str) -> Optional[Dict]:
        """Analyze a specific service."""
        try:
            service = self.nmap_scanner[ip][protocol][port]
            
            service_info = {
                'name': service.get('name', 'unknown'),
                'product': service.get('product', ''),
                'version': service.get('version', ''),
                'port': port,
                'protocol': protocol,
                'state': service.get('state', ''),
                'vulnerabilities': [],
                'recommendations': []
            }
            
            # Get AI analysis
            if self.ai_analyzer:
                analysis = await self.ai_analyzer.analyze_service(service_info)
                if analysis:
                    service_info.update(analysis)
            
            # Fallback to offline analysis if needed
            if not service_info.get('recommendations'):
                offline_recs = analyze_service_offline(service_info)
                service_info['recommendations'].extend(offline_recs)
            
            return service_info
            
        except Exception as e:
            logger.error(f"Error analyzing service: {str(e)}")
            return None
            
    async def _get_external_info(self, ip: str) -> Dict:
        """Get external information about the target."""
        try:
            if self.security_apis and self.security_apis.shodan_api:
                return await self.security_apis.shodan_lookup(ip)
        except Exception as e:
            logger.warning(f"Error getting external info: {str(e)}")
        return {}
        
    def _calculate_risk(self, services: Dict) -> float:
        """Calculate overall risk level."""
        if not services:
            return 0.0
            
        risk_scores = []
        for service in services.values():
            # Base risk for open port
            score = 2.0
            
            # Add risk for vulnerabilities
            vulns = service.get('vulnerabilities', [])
            vuln_weights = {'critical': 10.0, 'high': 8.0, 'medium': 5.0, 'low': 2.0}
            for vuln in vulns:
                score += vuln_weights.get(vuln.get('severity', 'low').lower(), 1.0)
            
            # Add risk for sensitive services
            name = service.get('name', '').lower()
            if any(s in name for s in ['sql', 'ftp', 'telnet', 'redis']):
                score += 3.0
            elif any(s in name for s in ['ssh', 'rdp', 'vnc']):
                score += 2.0
            
            risk_scores.append(score)
        
        # Calculate average and normalize to 0-10 range
        avg_risk = sum(risk_scores) / len(risk_scores)
        return min(avg_risk, 10.0)

    def _assess_risk(self, vulnerabilities: List[Dict]) -> str:
        """Assess overall risk level based on vulnerabilities."""
        risk_scores = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = self._determine_severity(vuln)
            total_score += risk_scores.get(severity, 0)
            
            # Increase score for certain high-risk conditions
            if any(high_risk in str(vuln).lower() for high_risk in 
                ['remote code execution', 'rce', 'arbitrary code', 'privilege escalation']):
                total_score += 5
            elif any(med_risk in str(vuln).lower() for med_risk in 
                ['sql injection', 'xss', 'command injection', 'buffer overflow']):
                total_score += 3
                
        # Determine risk level based on total score
        if total_score >= 30:
            return 'critical'
        elif total_score >= 15:
            return 'high'
        elif total_score >= 5:
            return 'medium'
        else:
            return 'low'

    async def _scan_container(self, target: str) -> dict:
        """Perform container security scan."""
        try:
            print(f"Starting container security scan for {target}...")
            
            # Scan container
            container_results = await self.container_scanner.scan_container(target)
            
            # Calculate risk score based on findings
            risk_score = self._calculate_container_risk_score(container_results)
            
            # Prepare report data
            report_data = ReportData(
                target=target,
                scan_type='container',
                timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
                vulnerabilities=self._convert_container_vulns(container_results.vulnerabilities),
                system_info={'type': 'container', 'image': target},
                web_vulnerabilities=[],
                network_services=[],
                risk_score=risk_score,
                scan_duration=time.time() - start_time
            )
            
            # Generate report
            report_path = self.report_generator.generate_report(
                report_data,
                output_dir="reports"
            )
            
            print(f"+ Container scan complete. Report generated: {report_path}")
            
            return {
                'container_results': container_results,
                'risk_score': risk_score,
                'report_path': report_path
            }
            
        except Exception as e:
            logger.error(f"Error scanning container: {str(e)}")
            raise
            
    def _calculate_container_risk_score(self, results: ContainerScanResult) -> float:
        """Calculate risk score for container scan results."""
        score = 0.0
        
        # Vulnerability severity weights
        severity_weights = {
            'Critical': 10.0,
            'High': 8.0,
            'Medium': 5.0,
            'Low': 2.0,
            'Unknown': 1.0
        }
        
        # Calculate vulnerability score
        vuln_count = len(results.vulnerabilities)
        if vuln_count > 0:
            severity_scores = [severity_weights.get(v.severity, 1.0) for v in results.vulnerabilities]
            score += sum(severity_scores) / vuln_count
            
        # Add points for misconfigurations
        score += len(results.misconfigurations) * 2.0
        
        # Add points for exposed secrets
        score += len(results.secrets) * 3.0
        
        # Add points for compliance issues
        score += len(results.compliance_issues) * 1.5
        
        # Normalize score to 0-10 range
        score = min(score, 10.0)
        
        return score
        
    def _convert_container_vulns(self, container_vulns: List[ContainerVulnerability]) -> List[Dict]:
        """Convert container vulnerabilities to standard format."""
        return [{
            'type': 'Container',
            'id': vuln.id,
            'severity': vuln.severity,
            'description': vuln.description,
            'package': vuln.package,
            'current_version': vuln.version,
            'fixed_version': vuln.fixed_version,
            'cve_id': vuln.cve_id,
            'remediation': vuln.remediation
        } for vuln in container_vulns]
        
    async def _scan_cloud(self, target: str) -> dict:
        """Perform cloud security scan."""
        try:
            print(f"Starting cloud security scan for {target}...")
            
            # Scan cloud infrastructure
            cloud_results = await self.cloud_scanner.scan_cloud_infrastructure(target)
            
            # Calculate risk score based on findings
            risk_score = self._calculate_cloud_risk_score(cloud_results)
            
            # Prepare report data
            report_data = ReportData(
                target=target,
                scan_type='cloud',
                timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
                vulnerabilities=self._convert_cloud_vulns(cloud_results.vulnerabilities),
                system_info={'type': 'cloud', 'provider': target},
                web_vulnerabilities=[],
                network_services=[],
                risk_score=risk_score,
                scan_duration=time.time() - start_time
            )
            
            # Generate report
            report_path = self.report_generator.generate_report(
                report_data,
                output_dir="reports"
            )
            
            print(f"+ Cloud scan complete. Report generated: {report_path}")
            
            return {
                'cloud_results': cloud_results,
                'risk_score': risk_score,
                'report_path': report_path
            }
            
        except Exception as e:
            logger.error(f"Error scanning cloud: {str(e)}")
            raise
            
    def _calculate_cloud_risk_score(self, results: CloudScanResult) -> float:
        """Calculate risk score for cloud scan results."""
        score = 0.0
        
        # Vulnerability severity weights
        severity_weights = {
            'Critical': 10.0,
            'High': 8.0,
            'Medium': 5.0,
            'Low': 2.0,
            'Unknown': 1.0
        }
        
        # Calculate vulnerability score
        vuln_count = len(results.vulnerabilities)
        if vuln_count > 0:
            severity_scores = [severity_weights.get(v.severity, 1.0) for v in results.vulnerabilities]
            score += sum(severity_scores) / vuln_count
            
        # Add points for misconfigurations
        score += len(results.misconfigurations) * 2.0
        
        # Add points for exposed secrets
        score += len(results.secrets) * 3.0
        
        # Add points for compliance issues
        score += len(results.compliance_issues) * 1.5
        
        # Normalize score to 0-10 range
        score = min(score, 10.0)
        
        return score
        
    def _convert_cloud_vulns(self, cloud_vulns: List[CloudVulnerability]) -> List[Dict]:
        """Convert cloud vulnerabilities to standard format."""
        return [{
            'type': 'Cloud',
            'id': vuln.id,
            'severity': vuln.severity,
            'description': vuln.description,
            'resource': vuln.resource,
            'current_version': vuln.version,
            'fixed_version': vuln.fixed_version,
            'cve_id': vuln.cve_id,
            'remediation': vuln.remediation
        } for vuln in cloud_vulns]
        
    def initialize_apis(self):
        """Initialize API clients based on available keys."""
        try:
            if os.getenv('OPENAI_API_KEY'):
                openai.api_key = os.getenv('OPENAI_API_KEY')
                self.openai_api = openai
                logging.info("OpenAI API initialized successfully")
            else:
                logging.warning("OpenAI API key not found")

            if os.getenv('GEMINI_API_KEY'):
                genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
                self.gemini_api = genai
                logging.info("Gemini API initialized successfully")
            else:
                logging.warning("Gemini API key not found")

            if os.getenv('VULNERS_API_KEY'):
                self.vulners_api = vulners.Vulners(api_key=os.getenv('VULNERS_API_KEY'))
                logging.info("Vulners API initialized successfully")
            else:
                logging.warning("Vulners API key not found")

            if os.getenv('SHODAN_API_KEY'):
                self.shodan_api = shodan.Shodan(os.getenv('SHODAN_API_KEY'))
                logging.info("Shodan API initialized successfully")
            else:
                logging.warning("Shodan API key not found")

        except Exception as e:
            logging.error(f"Error initializing APIs: {str(e)}")
            
class VulnerabilityDatabase:
    def __init__(self):
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_file = "vuln_cache.json"
        self.cache = self._load_cache()
        self.vulners_api = scanner.vulners_api
        self.shodan_api = scanner.shodan_api

    def _load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading vulnerability cache: {e}")
            return {}

    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Error saving vulnerability cache: {e}")

    def search_vulnerabilities(self, product: str, version: str = None) -> list:
        """Search for vulnerabilities using multiple sources."""
        cache_key = f"{product}:{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        vulns = []
        
        # Try Vulners API first
        if self.vulners_api:
            try:
                search_query = f"{product}"
                if version:
                    search_query += f" {version}"
                vulners_results = self.vulners_api.search(search_query, limit=100)
                
                for vuln in vulners_results:
                    vuln_info = {
                        'id': vuln.get('id'),
                        'title': vuln.get('title'),
                        'description': vuln.get('description'),
                        'severity': float(vuln.get('cvss', {}).get('score', 0)),
                        'published': vuln.get('published'),
                        'references': vuln.get('references', [])
                    }
                    vulns.append(vuln_info)
            except Exception as e:
                logger.error(f"Error searching Vulners: {str(e)}")

        # Try NVD API as backup
        try:
            params = {
                'keywordSearch': product,
                'resultsPerPage': 100
            }
            if version:
                params['versionStart'] = version
                params['versionStartType'] = 'including'

            headers = {'apiKey': self.nvd_api_key} if self.nvd_api_key else {}
            
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    vuln_info = {
                        'id': cve.get('id'),
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0),
                        'published': cve.get('published', ''),
                        'references': [ref.get('url') for ref in cve.get('references', [])]
                    }
                    vulns.append(vuln_info)
        except Exception as e:
            logger.error(f"Error searching NVD: {str(e)}")
        
        # Add Shodan data if available
        try:
            if self.shodan_api:
                api = self.shodan_api
                results = api.search(f"product:{product}")
                for result in results['matches'][:5]:
                    if 'vulns' in result:
                        for cve_id, vuln_info in result['vulns'].items():
                            vulns.append({
                                'id': cve_id,
                                'severity': float(vuln_info.get('cvss', 0)),
                                'description': vuln_info.get('summary', ''),
                                'source': 'shodan'
                            })
        except Exception as e:
            logger.error(f"Error searching Shodan: {str(e)}")

        # Remove duplicates based on ID
        unique_vulns = {v['id']: v for v in vulns if v['id']}.values()
        vulns = sorted(unique_vulns, key=lambda x: float(x.get('severity', 0)), reverse=True)
        
        self.cache[cache_key] = vulns
        self._save_cache()
        return vulns

class ExploitFinder:
    def __init__(self):
        self.exploit_db_url = "https://www.exploit-db.com/search?q="
        self.metasploit_url = "https://www.rapid7.com/db/?q="
        self.cache = {}

    def find_exploits(self, cve_id: str) -> dict:
        """Find available exploits for a CVE."""
        if cve_id in self.cache:
            return self.cache[cve_id]

        exploits = {
            'exploit_db': [],
            'metasploit': [],
            'github': []
        }

        try:
            # Search ExploitDB
            response = requests.get(f"{self.exploit_db_url}{cve_id}")
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    if '/exploits/' in link['href']:
                        exploits['exploit_db'].append({
                            'title': link.text.strip(),
                            'url': f"https://www.exploit-db.com{link['href']}"
                        })

            # Search GitHub
            gh_response = requests.get(
                f"https://api.github.com/search/repositories?q={cve_id}+in:readme+in:description"
            )
            if gh_response.status_code == 200:
                for repo in gh_response.json().get('items', [])[:5]:
                    exploits['github'].append({
                        'title': repo['full_name'],
                        'url': repo['html_url'],
                        'description': repo['description']
                    })

            self.cache[cve_id] = exploits
            return exploits

        except Exception as e:
            logger.error(f"Error finding exploits: {e}")
            return exploits

class AISecurityAnalyzer:
    """AI-powered security analysis for vulnerability assessment."""
    
    def __init__(self):
        """Initialize AI models for security analysis."""
        self.gemini_model = None
        self.openai_model = None
        self.local_model = None
        self.available_models = []
        self.vulners_api = None
        
        # Initialize AI models
        self._init_models()
        
        # Initialize Vulners API if available
        try:
            vulners_key = os.getenv('VULNERS_API_KEY')
            if vulners_key:
                import vulners
                self.vulners_api = vulners.Vulners(api_key=vulners_key)
                logger.info("Vulners API initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize Vulners API: {str(e)}")
            
    def _init_models(self):
        """Initialize available AI models."""
        try:
            # Try Gemini
            gemini_key = os.getenv('GEMINI_API_KEY')
            if gemini_key:
                import google.generativeai as genai
                genai.configure(api_key=gemini_key)
                self.gemini_model = genai.GenerativeModel('gemini-pro')
                self.available_models.append('gemini')
            else:
                logger.warning("Gemini API key not found. Gemini AI analysis will be disabled.")
                
            # Try OpenAI
            openai_key = os.getenv('OPENAI_API_KEY')
            if openai_key:
                import openai
                openai.api_key = openai_key
                self.openai_model = openai.OpenAI()
                self.available_models.append('openai')
            else:
                logger.warning("OpenAI API key not found. OpenAI analysis will be disabled.")
                
            # Try local ML model
            try:
                import tensorflow as tf
                import torch
                self.local_model = self._load_local_model()
                self.available_models.append('local')
            except ImportError:
                logger.warning("Required ML libraries not installed. Local ML analysis will be disabled.")
                
            if not self.available_models:
                logger.warning("No AI models available. Using offline analysis only.")
                
        except Exception as e:
            logger.error(f"Error initializing AI models: {str(e)}")
            
    def _load_local_model(self):
        """Load local ML model for analysis."""
        try:
            # Load model from disk
            model_path = "models/security_analyzer.h5"
            if os.path.exists(model_path):
                return tf.keras.models.load_model(model_path)
            return None
        except Exception as e:
            logger.warning(f"Error loading local model: {str(e)}")
            return None
            
    async def analyze_service(self, service_info: Dict) -> List[Dict]:
        """Analyze a service using available AI models and APIs."""
        vulnerabilities = []
        
        try:
            # Try AI analysis first
            if self.gemini_model:
                try:
                    model = self.gemini_model
                    prompt = f"""Analyze this network service for security vulnerabilities:
                    Service: {service_info.get('name', 'unknown')}
                    Port: {service_info.get('port', 'unknown')}
                    Version: {service_info.get('version', 'unknown')}
                    State: {service_info.get('state', 'unknown')}
                    
                    Provide:
                    1. Risk assessment
                    2. Potential vulnerabilities
                    3. Security recommendations
                    4. Compliance considerations"""
                    
                    response = model.generate_content(prompt)
                    if response:
                        vulnerabilities.append({
                            'source': 'Gemini AI',
                            'analysis': response.text,
                            'confidence': 'medium'
                        })
                except Exception as e:
                    logger.error(f"AI analysis failed: {str(e)}")
                    logger.debug(f"AI analysis exception details: {traceback.format_exc()}")
            
            if self.openai_model and not vulnerabilities:
                try:
                    response = await self.openai_model.ChatCompletion.acreate(
                        model="gpt-3.5-turbo",
                        messages=[{
                            "role": "system",
                            "content": "You are a cybersecurity expert analyzing network services for vulnerabilities."
                        }, {
                            "role": "user",
                            "content": f"""Analyze this network service for security vulnerabilities:
                            Service: {service_info.get('name', 'unknown')}
                            Port: {service_info.get('port', 'unknown')}
                            Version: {service_info.get('version', 'unknown')}
                            State: {service_info.get('state', 'unknown')}
                            
                            Provide:
                            1. Risk assessment
                            2. Potential vulnerabilities
                            3. Security recommendations
                            4. Compliance considerations"""
                        }]
                    )
                    if response:
                        vulnerabilities.append({
                            'source': 'OpenAI',
                            'analysis': response.choices[0].message.content,
                            'confidence': 'medium'
                        })
                except Exception as e:
                    logger.error(f"OpenAI analysis failed: {str(e)}")
                    logger.debug(f"OpenAI analysis exception details: {traceback.format_exc()}")
        
        except Exception as e:
            logger.error(f"Error during AI analysis: {str(e)}")
            logger.debug(f"AI analysis exception details: {traceback.format_exc()}")
        
        # If AI analysis failed or no AI services available, use offline analysis
        if not vulnerabilities:
            try:
                offline_analysis = analyze_service_offline(service_info)
                if isinstance(offline_analysis, list):
                    vulnerabilities.extend(offline_analysis)
                else:
                    vulnerabilities.append({
                        'source': 'Offline Analysis',
                        'analysis': offline_analysis,
                        'confidence': 'low'
                    })
            except Exception as e:
                logger.error(f"Error in offline analysis: {str(e)}")
                logger.debug(f"Offline analysis exception details: {traceback.format_exc()}")
                # Provide a minimal set of recommendations as fallback
                vulnerabilities.append({
                    'source': 'Basic Analysis',
                    'analysis': f"Service {service_info.get('name', 'unknown')} on port {service_info.get('port', 'unknown')} should be reviewed manually.",
                    'confidence': 'very low'
                })
        
        # Add Vulners data if available
        try:
            if self.vulners_api:
                software = f"{service_info.get('name', '')} {service_info.get('version', '')}".strip()
                if software:
                    vulners_results = self.vulners_api.softwareVulnerabilities(software)
                    for vuln_type, vulns in vulners_results.items():
                        if vuln_type not in ['info', 'blog', 'bugbounty']:
                            for vuln in vulns:
                                vulnerabilities.append({
                                    'source': 'Vulners',
                                    'id': vuln.get('id', 'unknown'),
                                    'title': vuln.get('title', 'Unknown vulnerability'),
                                    'description': vuln.get('description', ''),
                                    'type': vuln_type,
                                    'cvss': vuln.get('cvss', {}).get('score', 0),
                                    'published': vuln.get('published', ''),
                                    'references': vuln.get('references', [])
                                })
        except Exception as e:
            logger.error(f"Error searching Vulners: {str(e)}")
            logger.debug(f"Vulners exception details: {traceback.format_exc()}")
        
        return vulnerabilities

class NetworkMapper:
    def __init__(self):
        self.vuln_db = VulnerabilityDatabase()
        self.exploit_finder = ExploitFinder()
        self.scan_results = {}

    def analyze_service(self, service: dict) -> dict:
        """Analyze a single service for vulnerabilities."""
        product = service.get('product', '')
        version = service.get('version', '')
        
        vulnerabilities = self.vuln_db.search_vulnerabilities(product, version)
        high_risk_vulns = []
        
        for vuln in vulnerabilities:
            if vuln['severity'] >= 7.0:  # CVSS score >= 7.0 is high
                exploits = self.exploit_finder.find_exploits(vuln['id'])
                if any(exploits.values()):  # If any exploits found
                    vuln['exploits'] = exploits
                    high_risk_vulns.append(vuln)
        
        return {
            'service_info': service,
            'vulnerabilities': vulnerabilities,
            'high_risk': high_risk_vulns
        }

    def get_service_recommendations(self, service_analysis: dict) -> list:
        """Generate security recommendations based on service analysis."""
        recommendations = []
        service = service_analysis['service_info']
        
        # Basic service hardening
        if service.get('name') == 'ssh':
            recommendations.extend([
                "Disable root login via SSH",
                "Use key-based authentication instead of passwords",
                "Change default SSH port",
                "Implement fail2ban for brute force protection"
            ])
        elif service.get('name') == 'http' or service.get('name') == 'https':
            recommendations.extend([
                "Enable HTTPS and redirect HTTP to HTTPS",
                "Implement security headers (HSTS, CSP, etc.)",
                "Use WAF for additional protection",
                "Disable unnecessary HTTP methods",
                "Implement rate limiting"
            ])
        
        # Version-specific recommendations
        if service.get('version'):
            recommendations.append(f"Update {service.get('product')} to the latest version")
        
        # Port-specific recommendations
        port = service.get('port', 0)
        if port < 1024:
            recommendations.append(f"Service running on privileged port {port}. Consider running as non-root if possible.")
        
        # Protocol recommendations
        if service.get('protocol') == 'tcp':
            recommendations.append("Ensure firewall rules restrict access to necessary IPs only")
        
        # SSL/TLS checks
        if 'http' in service.get('name', '').lower() or 'https' in service.get('name', '').lower():
            recommendations.extend([
                "Verify SSL/TLS configuration and certificate validity",
                "Enable HTTP Strict Transport Security (HSTS)",
                "Implement proper Content Security Policy (CSP)"
            ])
        
        # Database recommendations
        if any(db in service.get('name', '').lower() for db in ['mysql', 'postgresql', 'mongodb', 'redis']):
            recommendations.extend([
                "Ensure strong authentication is enabled",
                "Regularly backup database content",
                "Monitor for unusual access patterns"
            ])
        
        # Remote access recommendations
        if any(remote in service.get('name', '').lower() for remote in ['ssh', 'rdp', 'vnc']):
            recommendations.extend([
                "Use strong authentication methods",
                "Implement fail2ban or similar brute-force protection",
                "Restrict access to specific IP ranges"
            ])
    
        return recommendations

async def analyze_vulnerabilities(scan_data: dict) -> str:
    """Analyze scan data for vulnerabilities."""
    try:
        analysis_results = []
        
        # Try AI-powered analysis first
        if gemini_model:
            try:
                # Format scan data for analysis
                scan_summary = []
                for proto in ['tcp', 'udp']:
                    if proto in scan_data:
                        for port, data in scan_data[proto].items():
                            service_info = f"Port {port}/{proto}: {data.get('name', 'unknown')}"
                            if data.get('product'):
                                service_info += f" - {data['product']}"
                                if data.get('version'):
                                    service_info += f" {data['version']}"
                            scan_summary.append(service_info)

                if scan_summary:
                    prompt = f"""Analyze these network services for security vulnerabilities:
{chr(10).join(scan_summary)}

Consider:
1. Known vulnerabilities for these services and versions
2. Common misconfigurations
3. Security best practices
4. Potential attack vectors
5. Specific remediation steps

Provide a detailed security analysis."""

                    response = gemini_model.generate_content(prompt)
                    analysis_results.append("AI Analysis:")
                    analysis_results.append(response.text)
            except Exception as e:
                logger.error(f"AI analysis failed: {str(e)}")
                logger.debug(f"AI analysis exception details: {traceback.format_exc()}")
        
        # Always perform offline analysis as backup
        analysis_results.append("\nOffline Analysis:")
        for proto in ['tcp', 'udp']:
            if proto in scan_data:
                for port, data in scan_data[proto].items():
                    service_name = data.get('name', 'unknown')
                    recommendations = analyze_service_offline(data)
                    if recommendations:
                        analysis_results.append(f"\nRecommendations for port {port}/{proto} ({service_name}):")
                        for rec in recommendations:
                            analysis_results.append(f"- {rec}")

        return "\n".join(analysis_results)
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {str(e)}")
        logger.debug(f"Vulnerability analysis exception details: {traceback.format_exc()}")
        return "Error performing vulnerability analysis. See logs for details."

async def scan(target: str, scan_type: str = 'basic'):
    """
    Perform network scan and vulnerability analysis.
    Args:
        target: IP address or hostname to scan
        scan_type: Type of scan to perform
    Returns:
        tuple: (analysis_results, raw_scan_data)
    """
    try:
        logger.info(f"Starting {scan_type} scan on {target}")
        
        # Input validation
        if not target or not isinstance(target, str):
            raise ValueError(f"Invalid target: Target must be a non-empty string, got {type(target)}")
            
        if scan_type not in ['basic', 'comprehensive']:
            raise ValueError(f"Invalid scan type: {scan_type}. Must be 'basic' or 'comprehensive'")
        
        # Initialize scanner
        scanner = init_scanner()
        
        # Validate target
        if not validate_target(target):
            raise ValueError(f"Invalid target format: {target}. Must be a valid IP address or hostname.")
            
        # Run nmap scan
        nm = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap',))
        scan_args = '-sV -sC' if scan_type == 'comprehensive' else '-sV'
        
        try:
            logger.info(f"Running nmap scan with arguments: {scan_args}")
            scan_results = await asyncio.to_thread(nm.scan, target, arguments=scan_args)
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {str(e)}")
            raise ValueError(f"Nmap scan failed: {str(e)}. Make sure nmap is installed and the target is reachable.")
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            logger.debug(f"Scan exception details: {traceback.format_exc()}")
            raise
            
        # Validate scan results
        if not scan_results or 'scan' not in scan_results:
            raise ValueError(f"Scan returned no results for target: {target}")
            
        # Extract service information
        services = {}
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    services[port] = {
                        'port': port,
                        'protocol': proto,
                        'state': service.get('state'),
                        'service': service.get('name'),
                        'product': service.get('product'),
                        'version': service.get('version'),
                        'extrainfo': service.get('extrainfo')
                    }
        
        logger.info(f"Found {len(services)} services on {target}")
                    
        # Analyze each service
        analysis_results = []
        for port, service in services.items():
            try:
                service_analysis = await scanner.analyze_service(service)
                analysis_results.append({
                    'service': service,
                    'analysis': service_analysis
                })
            except Exception as e:
                logger.error(f"Error analyzing service on port {port}: {str(e)}")
                logger.debug(f"Service analysis exception details: {traceback.format_exc()}")
                analysis_results.append({
                    'service': service,
                    'analysis': [{
                        'source': 'Error',
                        'analysis': f"Analysis failed: {str(e)}",
                        'confidence': 'none'
                    }]
                })
            
        # Get additional host information
        host_info = {}
        if scanner.shodan_api:
            try:
                host_info = await asyncio.to_thread(get_shodan_info, target)
            except Exception as e:
                logger.warning(f"Error getting Shodan info: {str(e)}")
                logger.debug(f"Shodan exception details: {traceback.format_exc()}")
                
        # Assess overall risk
        try:
            risk_level = scanner._assess_risk(services)
        except Exception as e:
            logger.error(f"Error assessing risk: {str(e)}")
            logger.debug(f"Risk assessment exception details: {traceback.format_exc()}")
            risk_level = "Unknown"
            
        # Compile final results
        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'services': services,
            'analysis': analysis_results,
            'host_info': host_info,
            'risk_level': risk_level,
            'status': 'completed'
        }
            
        return results
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        logger.debug(f"Scan exception details: {traceback.format_exc()}")
        # Return partial results if available
        return {
            'error': str(e),
            'status': 'failed',
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'partial_results': getattr(scanner, '_partial_results', {})
        }

def validate_target(target: str) -> bool:
    """
    Validate if the target is a valid IP address or hostname.
    Supports IPv4, IPv6, and hostnames according to RFC 1123.
    """
    if not target or len(target) > 255:
        return False

    # Try validating as IP address first
    try:
        # Handle IPv4
        if '.' in target:
            # Verify it looks like an IPv4 address
            octets = target.split('.')
            if len(octets) != 4:
                return False
            try:
                # Try converting each octet to int and validate range
                return all(
                    octet.isdigit() and 
                    0 <= int(octet) <= 255
                    for octet in octets
                )
            except ValueError:
                return False
        
        # Handle IPv6
        if ':' in target:
            ipaddress.IPv6Address(target)
            return True
            
        # If not an IP address, treat as hostname
        return validate_hostname(target)
            
    except ValueError:
        # If IP validation fails, try hostname validation
        return validate_hostname(target)

def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname according to RFC 1123 rules.
    """
    if not hostname or len(hostname) > 255:
        return False
        
    # Remove trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Hostname should not be empty after removing trailing dot
    if not hostname:
        return False
    
    # Split hostname into labels
    labels = hostname.split('.')
    
    # Check each label
    for label in labels:
        if not label:  # Empty label (consecutive dots)
            return False
        if len(label) > 63:  # Label too long
            return False
        if label.startswith('-') or label.endswith('-'):  # Hyphen at start/end
            return False
        # Check characters (alphanumeric and hyphen only)
        if not all(c.isalnum() or c == '-' for c in label):
            return False
        # Label can't be all numbers (at least for the last label/TLD)
        if label.isdigit():
            continue
    
    return True

def discover_network_targets(network: str) -> list:
    """
    Discover active hosts in the network using nmap ping scan.
    Args:
        network: Network range in CIDR notation (e.g., '192.168.1.0/24')
    Returns:
        List of active IP addresses
    """
    try:
        logger.info(f"Starting network discovery on {network}")
        nm = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap',))
        nm.scan(hosts=network, arguments='-sn')  # Ping scan
        
        active_hosts = []
        for host in nm.all_hosts():
            try:
                hostname = ''
                if 'hostnames' in nm[host] and nm[host]['hostnames']:
                    hostname = nm[host]['hostnames'][0]['name']
                
                status = nm[host].state()
                addresses = []
                if 'addresses' in nm[host]:
                    for addr_type, addr in nm[host]['addresses'].items():
                        addresses.append(f"{addr_type}:{addr}")
                
                if status == 'up':
                    active_hosts.append({
                        'ip': host,
                        'hostname': hostname,
                        'addresses': addresses,
                        'status': status
                    })
                    logger.info(f"Found active host: {host} ({hostname})")
            except Exception as e:
                logger.error(f"Error processing host {host}: {str(e)}")
                continue
                
        return active_hosts
    except Exception as e:
        logger.error(f"Error during network discovery: {str(e)}")
        return []

def validate_network_range(network: str) -> bool:
    """
    Validate if the given network range is in valid CIDR notation.
    Args:
        network: Network range (e.g., '192.168.1.0/24')
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        if '/' not in network:
            return False
        ip, mask = network.split('/')
        # Validate IP
        ipaddress.ip_address(ip)
        # Validate mask
        mask = int(mask)
        if not (0 <= mask <= 32):
            return False
        return True
    except ValueError:
        return False

def is_valid_ip(ip_str: str) -> bool:
    """Validate if a string is a valid IPv4 address."""
    try:
        # Split the IP address into octets
        octets = ip_str.split('.')
        
        # Check if we have exactly 4 octets
        if len(octets) != 4:
            return False
            
        # Check if each octet is a valid number between 0 and 255
        return all(0 <= int(octet) <= 255 for octet in octets)
    except (AttributeError, TypeError, ValueError):
        return False

def get_shodan_info(ip: str) -> dict:
    """Get information about an IP address from Shodan."""
    try:
        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"Invalid IP address format: {ip}")
            return {}

        # Skip private IP addresses
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            logger.warning(f"Skipping Shodan lookup for private IP: {ip}")
            return {}

        shodan_api = shodan.Shodan(os.getenv('SHODAN_API_KEY'))
        host = shodan_api.host(ip)
        
        return {
            'org': host.get('org', 'N/A'),
            'os': host.get('os', 'N/A'),
            'ports': host.get('ports', []),
            'vulns': host.get('vulns', [])
        }
    except shodan.APIError as e:
        if "No information available" in str(e):
            logger.warning(f"No Shodan information available for {ip}")
        else:
            logger.error(f"Shodan API error: {str(e)}")
        return {}
    except Exception as e:
        logger.error(f"Error getting Shodan info: {str(e)}")
        return {}

def init_vulners_api():
    """Initialize Vulners API with API key from environment."""
    try:
        api_key = os.getenv('VULNERS_API_KEY')
        if not api_key:
            logger.warning("No Vulners API key found in environment. Vulnerability database lookups will be limited.")
            return None
        
        # Basic validation of API key format
        if not isinstance(api_key, str) or len(api_key.strip()) < 20:
            logger.warning("Vulners API key appears to be invalid (too short or wrong format). Vulnerability database lookups will be limited.")
            return None
            
        try:
            # Initialize Vulners API with retry configuration
            vulners_api = vulners.Vulners(api_key=api_key)
            
            # Test API key with a simple query
            try:
                test_result = vulners_api.search("test", limit=1)
                if not test_result:
                    logger.warning("Vulners API key validation failed. Continuing without it.")
                    return None
                logger.info("Vulners API initialized successfully")
                return vulners_api
            except Exception as e:
                logger.warning(f"Vulners API key validation failed: {str(e)}. Continuing without it.")
                return None
        except ImportError:
            logger.warning("Vulners library not installed. Vulnerability database lookups will be limited.")
            return None
        except Exception as e:
            logger.warning(f"Error initializing Vulners API: {str(e)}. Continuing without it.")
            return None
    except Exception as e:
        logger.warning(f"Unexpected error initializing Vulners API: {str(e)}. Continuing without it.")
        return None

def init_shodan_api():
    """Initialize Shodan API with API key from environment."""
    try:
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            logger.warning("No Shodan API key found in environment. External reconnaissance will be limited.")
            return None
            
        # Basic validation of API key format
        if not isinstance(api_key, str) or len(api_key.strip()) < 20:
            logger.warning("Shodan API key appears to be invalid (too short or wrong format). External reconnaissance will be limited.")
            return None
        
        try:
            import shodan
            shodan_api = shodan.Shodan(api_key)
            
            # Test with a simple request to verify API key works
            try:
                info = shodan_api.info()
                if not info or not isinstance(info, dict):
                    logger.warning("Shodan API key validation failed. Continuing without it.")
                    return None
                    
                # Check API usage limits
                query_credits = info.get('query_credits', 0)
                scan_credits = info.get('scan_credits', 0)
                
                if query_credits <= 0:
                    logger.warning("Shodan API has no query credits remaining. Some functionality will be limited.")
                
                logger.info(f"Shodan API initialized successfully. Query credits: {query_credits}, Scan credits: {scan_credits}")
                return shodan_api
            except Exception as e:
                logger.warning(f"Shodan API key validation failed: {str(e)}. Continuing without it.")
                return None
        except ImportError:
            logger.warning("Shodan library not installed. External reconnaissance will be limited.")
            return None
        except Exception as e:
            logger.warning(f"Error initializing Shodan API: {str(e)}. Continuing without it.")
            return None
    except Exception as e:
        logger.warning(f"Unexpected error initializing Shodan API: {str(e)}. Continuing without it.")
        return None

async def main():
    """Main entry point for the vulnerability scanner."""
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='AI-powered vulnerability scanner')
        parser.add_argument('-t', '--target', required=True, help='Target IP address, hostname, container image, or cloud provider')
        parser.add_argument('-s', '--scan-type', choices=['basic', 'comprehensive', 'container', 'cloud'], default='basic', help='Type of scan to perform')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        parser.add_argument('-o', '--output', help='Output file name (without extension)')
        parser.add_argument('--container', action='store_true', help='Treat target as a container image')
        parser.add_argument('--cloud-providers', nargs='+', choices=['aws', 'azure', 'gcp'], help='Cloud providers to scan when using cloud scan type')
        
        args = parser.parse_args()
        
        # Configure logging based on verbosity
        log_level = logging.DEBUG if args.verbose else logging.INFO
        logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Validate arguments
        if not args.target:
            logger.error("Target is required")
            parser.print_help()
            return 1
            
        # Validate scan type and additional arguments
        if args.scan_type == 'cloud' and not args.cloud_providers:
            logger.error("Cloud providers must be specified for cloud scan type")
            parser.print_help()
            return 1
            
        if args.container and args.scan_type not in ['basic', 'container']:
            logger.error("Container scan requires scan type 'basic' or 'container'")
            parser.print_help()
            return 1
            
        # Set output file name
        output_prefix = args.output if args.output else f"{args.target.replace('.', '_')}_{int(time.time())}"
        
        # Perform scan based on scan type
        if args.container:
            # Import container scanner only when needed
            try:
                from container_scanner import scan_container
                results = await scan_container(args.target)
            except ImportError:
                logger.error("Container scanning module not available. Please install required dependencies.")
                return 1
            except Exception as e:
                logger.error(f"Container scan failed: {str(e)}")
                return 1
        elif args.scan_type == 'cloud':
            # Import cloud scanner only when needed
            try:
                from cloud_scanner import scan_cloud
                results = await scan_cloud(args.target, args.cloud_providers)
            except ImportError:
                logger.error("Cloud scanning module not available. Please install required dependencies.")
                return 1
            except Exception as e:
                logger.error(f"Cloud scan failed: {str(e)}")
                return 1
        else:
            # Network scan
            try:
                results = await scan(args.target, args.scan_type)
            except Exception as e:
                logger.error(f"Network scan failed: {str(e)}")
                return 1
                
        # Check if scan completed successfully
        if results.get('status') == 'failed':
            logger.error(f"Scan failed: {results.get('error', 'Unknown error')}")
            if results.get('partial_results'):
                logger.info("Partial results are available")
            else:
                return 1
                
        # Save results
        try:
            output_dir = save_results(results, output_prefix)
            if output_dir:
                logger.info(f"Results saved to {output_dir}")
                
                # Generate HTML report
                try:
                    report_generator = ReportGenerator()
                    report_path = report_generator.generate_report(results, output_dir)
                    logger.info(f"HTML report generated: {report_path}")
                except Exception as e:
                    logger.error(f"Error generating HTML report: {str(e)}")
            else:
                logger.error("Failed to save results")
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
            
        return 0
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.debug(f"Exception details: {traceback.format_exc()}")
        return 1

def save_results(results, output_prefix):
    """Save scan results to files."""
    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.getcwd(), 'scans')
        os.makedirs(output_dir, exist_ok=True)
        
        # Save JSON results
        json_path = os.path.join(output_dir, f"{output_prefix}.json")
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        # Save text report
        txt_path = os.path.join(output_dir, f"{output_prefix}.txt")
        with open(txt_path, 'w') as f:
            f.write(format_text_report(results))
                
        return output_dir
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")
        logger.debug(f"Save results exception details: {traceback.format_exc()}")
        return None

def format_text_report(results):
    """Format scan results as text."""
    output = []
    
    try:
        # Format header
        output.append(f"Findings for {results.get('target', 'unknown')}:")
        if results.get('hostname'):
            if isinstance(results['hostname'], list):
                output.append(f"Hostname: {', '.join(results['hostname'])}")
            else:
                output.append(f"Hostname: {results['hostname']}")
        output.append(f"Risk Level: {results.get('risk_level', 'Unknown')}\n")
        
        # Format service analysis
        output.append("Service Analysis:\n")
        for service_analysis in results.get('analysis', []):
            if not isinstance(service_analysis, dict):
                continue
                
            service = service_analysis.get('service', {})
            analysis = service_analysis.get('analysis', [])
            
            if not service or not analysis:
                continue
                
            output.append(f"\n{service.get('port', 'unknown')}/{service.get('protocol', 'tcp')} - {service.get('service', 'unknown')} ({service.get('product', '')} {service.get('version', '')})")
            
            # Handle analysis which could be a list or a single item
            if not isinstance(analysis, list):
                analysis = [analysis]
                
            for finding in analysis:
                # Handle finding which could be a dict or a string
                if isinstance(finding, dict):
                    source = finding.get('source', 'Unknown')
                    finding_text = finding.get('analysis', '')
                    confidence = finding.get('confidence', 'unknown')
                    
                    output.append(f"\nSource: {source} (Confidence: {confidence})")
                    output.append(f"{finding_text}\n")
                elif isinstance(finding, str):
                    output.append(f"\nAnalysis: {finding}\n")
        
        # Format Shodan info if available
        if results.get('host_info'):
            output.append("\nShodan Information:")
            for key, value in results['host_info'].items():
                if isinstance(value, dict):
                    output.append(f"{key}:")
                    for subkey, subvalue in value.items():
                        output.append(f"  {subkey}: {subvalue}")
                else:
                    output.append(f"{key}: {value}")
    except Exception as e:
        logger.error(f"Error formatting report: {str(e)}")
        logger.debug(f"Report formatting exception details: {traceback.format_exc()}")
        output.append(f"\nError generating full report: {str(e)}")
        
    return "\n".join(str(line) for line in output)

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
