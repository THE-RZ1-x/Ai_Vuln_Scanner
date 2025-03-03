#!/usr/bin/env python3
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
import sys
import nmap
import json
import time
import socket
import shodan
import logging
import vulners
import argparse
import requests
import ipaddress
import traceback
from tqdm import tqdm
import google.generativeai as genai
from datetime import datetime
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from typing import Dict, List, Union
from requests.exceptions import RequestException
import re
import vulners
import shodan
import aiohttp
import asyncio
from web_scanner import WebScanner, WebVulnerability
from report_generator import ReportGenerator, ReportData
from container_scanner import ContainerScanner, ContainerScanResult, ContainerVulnerability
from cloud_scanner import CloudScanner, CloudScanResult

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
        """Initialize the scanner with necessary APIs."""
        self.vulners_api = None
        self.shodan_api = None
        self.web_scanner = WebScanner()
        self.container_scanner = ContainerScanner()
        self.cloud_scanner = CloudScanner()
        self.report_generator = ReportGenerator()
        self.initialize_apis()

    def initialize_apis(self):
        """Initialize various security APIs."""
        try:
            # Initialize Vulners API
            self.vulners_api = init_vulners_api()
            if self.vulners_api:
                print("+ Vulners API initialized")
            else:
                print("! Vulners API not available - using offline vulnerability database")
            
            # Initialize Shodan API if needed
            self.shodan_api = init_shodan_api()
            if self.shodan_api:
                print("+ Shodan API initialized")
            else:
                print("! Shodan API not available - external reconnaissance will be limited")
                    
        except Exception as e:
            print(f"x Error initializing APIs: {str(e)}")

    async def analyze_service(self, service_info: dict) -> dict:
        """Analyze a service and its vulnerabilities."""
        try:
            # Get AI analysis if available
            ai_analysis = None
            analyzer = init_ai_analyzer()
            if analyzer:
                try:
                    ai_analysis = await analyzer.analyze_service(service_info)
                except Exception as e:
                    print(f"x Error analyzing service: {str(e)}")
            
            # Get vulnerability information if Vulners API is available
            vulns = []
            if self.vulners_api and service_info.get('product') and service_info.get('version'):
                try:
                    vulns_result = self.vulners_api.softwareVulnerabilities(
                        service_info['product'],
                        service_info['version']
                    )
                    
                    if vulns_result:
                        for vuln_type in vulns_result:
                            if vuln_type != 'info' and vulns_result[vuln_type]:
                                vulns.extend(vulns_result[vuln_type])
                except Exception as e:
                    print(f"x Error getting vulnerabilities: {str(e)}")
            
            # Get service recommendations using offline analysis
            recommendations = analyze_service_offline(service_info)
            
            return {
                'ai_analysis': ai_analysis,
                'vulnerabilities': vulns,
                'recommendations': recommendations
            }
        except Exception as e:
            print(f"x Error analyzing service: {str(e)}")
            return {
                'ai_analysis': None,
                'vulnerabilities': [],
                'recommendations': analyze_service_offline(service_info)
            }

    async def scan(self, target, scan_type='network'):
        """
        Perform a vulnerability scan on the target.
        
        Args:
            target: The target to scan (IP, hostname, URL, etc.)
            scan_type: Type of scan to perform (network, web, container, cloud)
            
        Returns:
            dict: Scan results
        """
        try:
            print(f"Starting {scan_type} scan of {target}...")
            
            # Initialize APIs if not already done
            if not hasattr(self, 'security_apis') or not self.security_apis.initialized:
                self.initialize_apis()
                
            # Initialize AI analyzer if not already done
            if not hasattr(self, 'ai_analyzer'):
                self.ai_analyzer = AISecurityAnalyzer()
                
            # Determine scan method based on scan_type
            if scan_type == 'web':
                if not hasattr(self, 'web_scanner'):
                    self.web_scanner = WebScanner()
                results = await self.web_scanner.scan(target)
            elif scan_type == 'container':
                if not hasattr(self, 'container_scanner'):
                    self.container_scanner = ContainerScanner()
                results = await self.container_scanner.scan(target)
            elif scan_type == 'cloud':
                if not hasattr(self, 'cloud_scanner'):
                    self.cloud_scanner = CloudScanner()
                results = await self.cloud_scanner.scan(target)
            else:  # Default to network scan
                results = await self._scan_network(target)
                
            # Generate report
            if hasattr(self, 'report_generator'):
                results['report'] = self.report_generator.generate_report(results)
                
            return results
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            # Return partial results if available
            return {
                'error': str(e),
                'status': 'failed',
                'partial_results': getattr(self, '_partial_results', {})
            }

    def _is_container_target(self, target: str) -> bool:
        """Determine if the target is a container image."""
        return ('/' in target or ':' in target) and not any(char in target for char in ['http://', 'https://', '*'])
        
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
        
    async def _scan_network_target(self, target: str, scan_type: str) -> dict:
        """Perform network and web application scan."""
        # Validate target
        if not validate_target(target):
            raise ValueError(f"Invalid target: {target}")
            
        # Initialize components
        network_mapper = NetworkMapper()
        ai_analyzer = init_ai_analyzer()
        
        # Perform network scan
        print(f"Running network scan on {target}...")
        scan_results = await network_mapper.scan_target(target, scan_type)
        
        # Perform web vulnerability scan if HTTP/HTTPS services are found
        web_vulns = []
        if any(service['name'] in ['http', 'https'] for service in scan_results.get('services', [])):
            print("Detected web services, performing web vulnerability scan...")
            web_vulns = await self.web_scanner.scan_web_application(f"http://{target}")
        
        # Analyze results
        analysis_results = await analyze_vulnerabilities(scan_results)
        
        # Calculate risk score
        risk_level = self._assess_risk(scan_results.get('services', []))
        
        # Prepare report data
        report_data = ReportData(
            target=target,
            scan_type=scan_type,
            timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
            vulnerabilities=analysis_results.get('vulnerabilities', []),
            system_info=scan_results.get('system_info', {}),
            web_vulnerabilities=web_vulns,
            network_services=scan_results.get('services', []),
            risk_score=risk_level,
            scan_duration=time.time() - start_time
        )
        
        # Generate report
        report_path = self.report_generator.generate_report(
            report_data,
            output_dir="reports"
        )
        
        print(f"+ Network scan complete. Report generated: {report_path}")
        
        return {
            'scan_results': scan_results,
            'analysis': analysis_results,
            'web_vulnerabilities': web_vulns,
            'risk_score': risk_level,
            'report_path': report_path
        }

    async def _scan_cloud_infrastructure(self, target: str) -> dict:
        """Perform cloud infrastructure security scan."""
        try:
            print("Starting cloud infrastructure security scan...")
            
            # Determine cloud providers to scan
            providers = []
            if args.cloud_providers:
                providers = args.cloud_providers
            elif target.lower() in ['aws', 'azure', 'gcp']:
                providers = [target.lower()]
            else:
                providers = ['aws', 'azure', 'gcp']  # Scan all by default
                
            # Scan cloud infrastructure
            cloud_results = await self.cloud_scanner.scan_cloud_infrastructure(providers)
            
            # Calculate overall risk score
            risk_score = self._calculate_cloud_risk_score(cloud_results)
            
            # Prepare report data
            report_data = ReportData(
                target=f"Cloud Infrastructure ({', '.join(providers)})",
                scan_type='cloud',
                timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
                vulnerabilities=self._convert_cloud_vulns(cloud_results),
                system_info={'providers': providers},
                web_vulnerabilities=[],
                network_services=[],
                risk_score=risk_score,
                scan_duration=time.time() - start_time,
                cloud_findings=cloud_results
            )
            
            # Generate report
            report_path = self.report_generator.generate_report(
                report_data,
                output_dir="reports"
            )
            
            print(f"+ Cloud infrastructure scan complete. Report generated: {report_path}")
            
            return {
                'cloud_results': cloud_results,
                'risk_score': risk_score,
                'report_path': report_path
            }
            
        except Exception as e:
            logger.error(f"Error scanning cloud infrastructure: {str(e)}")
            raise
            
    def _calculate_cloud_risk_score(self, results: Dict[str, CloudScanResult]) -> float:
        """Calculate overall cloud infrastructure risk score."""
        if not results:
            return 0.0
            
        total_score = 0.0
        weights = {
            'Critical': 10.0,
            'High': 8.0,
            'Medium': 5.0,
            'Low': 2.0,
            'Unknown': 1.0
        }
        
        for provider_results in results.values():
            # Vulnerability score
            vuln_score = sum(weights.get(v.severity, 1.0) for v in provider_results.vulnerabilities)
            
            # Misconfiguration score
            misconfig_score = len(provider_results.misconfigurations) * 2.0
            
            # IAM issues score
            iam_score = len(provider_results.iam_issues) * 3.0
            
            # Network findings score
            network_score = len(provider_results.network_findings) * 2.5
            
            # Add to total
            total_score += (vuln_score + misconfig_score + iam_score + network_score)
            
        # Normalize to 0-10 range
        return min(total_score / len(results), 10.0)
        
    def _convert_cloud_vulns(self, results: Dict[str, CloudScanResult]) -> List[Dict]:
        """Convert cloud vulnerabilities to standard format."""
        vulns = []
        for provider, result in results.items():
            for vuln in result.vulnerabilities:
                vulns.append({
                    'type': 'Cloud',
                    'provider': provider,
                    'resource_id': vuln.resource_id,
                    'severity': vuln.severity,
                    'description': vuln.description,
                    'recommendation': vuln.recommendation,
                    'compliance_standards': vuln.compliance_standards,
                    'risk_score': vuln.risk_score
                })
        return vulns

    async def _scan_network(self, target):
        """
        Perform a network vulnerability scan.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            dict: Scan results
        """
        try:
            # Store partial results in case of failure
            self._partial_results = {
                'target': target,
                'scan_type': 'network',
                'status': 'in_progress',
                'timestamp': datetime.now().isoformat()
            }
            
            # Validate target
            if not validate_target(target):
                logger.error(f"Invalid target: {target}")
                return {
                    'error': f"Invalid target: {target}",
                    'status': 'failed'
                }
                
            # Resolve hostname to IP if needed
            ip = target
            if not is_ip_address(target):
                try:
                    ip = socket.gethostbyname(target)
                    print(f"Resolved {target} to {ip}")
                except socket.gaierror:
                    logger.error(f"Could not resolve hostname: {target}")
                    return {
                        'error': f"Could not resolve hostname: {target}",
                        'status': 'failed'
                    }
            
            # Get hostnames for the IP
            hostnames = get_hostnames(ip)
            self._partial_results['hostnames'] = hostnames
            
            # Perform port scan
            print(f"Scanning ports on {ip}...")
            ports = await self._scan_ports(ip)
            if not ports:
                print("No open ports found")
                
            # Analyze services on open ports
            services = {}
            for port, protocol in ports.items():
                service_info = await self._analyze_service(ip, port, protocol)
                if service_info:
                    services[f"{port}/{protocol}"] = service_info
                    
            self._partial_results['services'] = services
            
            # Perform external reconnaissance if available
            external_info = {}
            if hasattr(self, 'security_apis') and hasattr(self.security_apis, 'shodan_api') and self.security_apis.shodan_api:
                try:
                    print("Performing external reconnaissance...")
                    external_info = await self.security_apis.shodan_lookup(ip)
                except Exception as e:
                    logger.warning(f"Error during external reconnaissance: {str(e)}")
                    
            # Assess overall risk
            risk_level = self._assess_risk(services)
            
            # Compile final results
            results = {
                'target': target,
                'ip': ip,
                'hostnames': hostnames,
                'scan_type': 'network',
                'timestamp': datetime.now().isoformat(),
                'services': services,
                'external_info': external_info,
                'risk_level': risk_level,
                'status': 'completed'
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}")
            # Return partial results if available
            return {
                'error': str(e),
                'status': 'failed',
                'partial_results': self._partial_results
            }

    async def _scan_ports(self, ip):
        """
        Scan for open ports on the target IP.
        
        Args:
            ip: IP address to scan
            
        Returns:
            dict: Dictionary of open ports and protocols
        """
        try:
            print(f"Scanning ports on {ip}...")
            
            # Use python-nmap for port scanning
            try:
                import nmap
                scanner = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap',))
            except ImportError:
                logger.warning("python-nmap not installed. Using simplified port scan.")
                return await self._simple_port_scan(ip)
                
            try:
                # Scan common ports first
                scanner.scan(ip, '21-25,80,443,3306,3389,8080,8443', arguments='-T4')
                
                # Get results
                open_ports = {}
                for host in scanner.all_hosts():
                    for proto in scanner[host].all_protocols():
                        for port in scanner[host][proto].keys():
                            if scanner[host][proto][port]['state'] == 'open':
                                open_ports[port] = proto
                                
                return open_ports
            except Exception as e:
                logger.warning(f"Error during nmap scan: {str(e)}. Using simplified port scan.")
                return await self._simple_port_scan(ip)
                
        except Exception as e:
            logger.error(f"Error scanning ports: {str(e)}")
            return {}
            
    async def _simple_port_scan(self, ip):
        """Simple port scanner using sockets when nmap is not available."""
        common_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443]
        open_ports = {}
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports[port] = 'tcp'
                sock.close()
            except:
                pass
                
        return open_ports
            
    async def _analyze_service(self, ip, port, protocol):
        """
        Analyze a service running on a specific port.
        
        Args:
            ip: IP address
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            dict: Service information and vulnerabilities
        """
        try:
            print(f"Analyzing service on {ip}:{port}/{protocol}...")
            
            # Get service information
            service_info = await self._identify_service(ip, port, protocol)
            if not service_info:
                return None
                
            # Look up vulnerabilities if product and version are identified
            vulnerabilities = []
            if service_info.get('product') and service_info.get('version'):
                if hasattr(self, 'security_apis'):
                    try:
                        vulnerabilities = await self.security_apis.lookup_vulnerabilities(
                            product=service_info.get('product'),
                            version=service_info.get('version')
                        )
                    except Exception as e:
                        logger.warning(f"Error looking up vulnerabilities: {str(e)}")
            
            # AI analysis of the service
            analysis = {}
            if hasattr(self, 'ai_analyzer'):
                try:
                    analysis = await self.ai_analyzer.analyze_attack_surface({
                        'ip': ip,
                        'port': port,
                        'protocol': protocol,
                        'service': service_info.get('name', ''),
                        'product': service_info.get('product', ''),
                        'version': service_info.get('version', ''),
                        'banner': service_info.get('banner', '')
                    })
                except Exception as e:
                    logger.warning(f"Error during AI analysis: {str(e)}")
                    
            # Combine results
            result = {
                'port': port,
                'protocol': protocol,
                'name': service_info.get('name', 'unknown'),
                'product': service_info.get('product', ''),
                'version': service_info.get('version', ''),
                'banner': service_info.get('banner', ''),
                'vulnerabilities': vulnerabilities,
                'analysis': analysis
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing service on {ip}:{port}: {str(e)}")
            return {
                'port': port,
                'protocol': protocol,
                'name': 'unknown',
                'error': str(e)
            }
            
    async def _identify_service(self, ip, port, protocol):
        """
        Identify service details using banner grabbing.
        
        Args:
            ip: IP address
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            dict: Service information
        """
        # Common service mapping
        common_services = {
            21: {'name': 'ftp', 'product': 'Generic FTP'},
            22: {'name': 'ssh', 'product': 'OpenSSH'},
            23: {'name': 'telnet', 'product': 'Telnet'},
            25: {'name': 'smtp', 'product': 'SMTP'},
            80: {'name': 'http', 'product': 'HTTP Server'},
            443: {'name': 'https', 'product': 'HTTPS Server'},
            3306: {'name': 'mysql', 'product': 'MySQL'},
            3389: {'name': 'rdp', 'product': 'Remote Desktop'},
            8080: {'name': 'http-alt', 'product': 'HTTP Alternate'},
            8443: {'name': 'https-alt', 'product': 'HTTPS Alternate'}
        }
        
        # Start with default service info
        service_info = common_services.get(port, {'name': 'unknown', 'product': 'Unknown'})
        
        # Try to get banner
        banner = await self._grab_banner(ip, port)
        if banner:
            service_info['banner'] = banner
            
            # Try to identify product and version from banner
            if 'SSH' in banner and 'OpenSSH' in banner:
                service_info['product'] = 'OpenSSH'
                version_match = re.search(r'OpenSSH[_-](\d+\.\d+\w*)', banner)
                if version_match:
                    service_info['version'] = version_match.group(1)
            elif 'HTTP' in banner:
                server_match = re.search(r'Server: ([^\r\n]+)', banner)
                if server_match:
                    server = server_match.group(1)
                    if 'Apache' in server:
                        service_info['product'] = 'Apache'
                        version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
                        if version_match:
                            service_info['version'] = version_match.group(1)
                    elif 'nginx' in server:
                        service_info['product'] = 'Nginx'
                        version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server)
                        if version_match:
                            service_info['version'] = version_match.group(1)
                    else:
                        service_info['product'] = server
            
        return service_info
        
    async def _grab_banner(self, ip, port):
        """
        Grab service banner from the specified port.
        
        Args:
            ip: IP address
            port: Port number
            
        Returns:
            str: Service banner or empty string if not available
        """
        try:
            # Different methods based on port
            if port == 80:
                return await self._http_banner(ip, port, secure=False)
            elif port == 443:
                return await self._http_banner(ip, port, secure=True)
            elif port == 22:
                return await self._ssh_banner(ip, port)
            else:
                # Generic banner grabbing
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                sock.send(b'\r\n\r\n')
                banner = sock.recv(1024)
                sock.close()
                return banner.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Error grabbing banner from {ip}:{port}: {str(e)}")
            return ""
            
    async def _http_banner(self, ip, port, secure=False):
        """Get HTTP server banner."""
        try:
            protocol = 'https' if secure else 'http'
            url = f"{protocol}://{ip}:{port}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=5, ssl=False) as response:
                    return f"HTTP/{response.version.major}.{response.version.minor} {response.status} {response.reason}\r\nServer: {response.headers.get('Server', 'Unknown')}"
        except Exception as e:
            logger.debug(f"Error getting HTTP banner: {str(e)}")
            return ""
            
    async def _ssh_banner(self, ip, port):
        """Get SSH server banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024)
            sock.close()
            return banner.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Error getting SSH banner: {str(e)}")
            return ""
            
    def _assess_risk(self, services):
        """
        Assess the overall risk level based on discovered services and vulnerabilities.
        
        Args:
            services: Dictionary of discovered services
            
        Returns:
            str: Risk level (Critical, High, Medium, Low, or Minimal)
        """
        try:
            if not services:
                return "Minimal"
                
            # Count vulnerabilities by severity
            vuln_counts = {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0
            }
            
            # High-risk services
            high_risk_services = ['ftp', 'telnet', 'rsh', 'rlogin', 'rexec', 'tftp']
            high_risk_count = 0
            
            # Analyze each service
            for service_id, service in services.items():
                # Count vulnerabilities by severity
                for vuln in service.get('vulnerabilities', []):
                    severity = vuln.get('severity', '').capitalize()
                    if severity in vuln_counts:
                        vuln_counts[severity] += 1
                
                # Check for high-risk services
                service_name = service.get('name', '').lower()
                if service_name in high_risk_services:
                    high_risk_count += 1
            
            # Determine risk level based on vulnerability counts
            if vuln_counts["Critical"] > 0:
                return "Critical"
            elif vuln_counts["High"] > 2 or high_risk_count >= 2:
                return "High"
            elif vuln_counts["High"] > 0 or vuln_counts["Medium"] > 3 or high_risk_count > 0:
                return "Medium"
            elif vuln_counts["Medium"] > 0 or vuln_counts["Low"] > 5:
                return "Low"
            else:
                return "Minimal"
                
        except Exception as e:
            logger.error(f"Error assessing risk: {str(e)}")
            return "Unknown"

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
                        'references': vuln.get('references', []),
                        'source': 'vulners'
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
                        'published': cve.get('published'),
                        'references': [ref.get('url') for ref in cve.get('references', [])],
                        'source': 'nvd'
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
        self.gemini_model = init_gemini()
        self.openai_model = init_openai()
        self.local_model = init_local_ml_model()
        self.available_models = []
        
        if self.gemini_model:
            self.available_models.append("gemini")
        if self.openai_model:
            self.available_models.append("openai")
        if self.local_model:
            self.available_models.append("local")
            
        if not self.available_models:
            logger.warning("No AI models available. Using offline analysis only.")
        else:
            logger.info(f"AI Security Analyzer initialized with models: {', '.join(self.available_models)}")
    
    async def analyze_service(self, service_data):
        """
        Analyze a service using available AI models.
        
        Args:
            service_data: Dictionary containing service information
            
        Returns:
            dict: Analysis results
        """
        try:
            # If no AI models are available, use offline analysis
            if not self.available_models:
                logger.info("Using offline analysis for service")
                return analyze_service_offline(service_data)
            
            # Prepare service information for analysis
            service_name = service_data.get('name', '')
            product = service_data.get('product', '')
            version = service_data.get('version', '')
            port = service_data.get('port', '')
            
            prompt = f"""
            Analyze the security of this network service:
            Service: {service_name}
            Product: {product}
            Version: {version}
            Port: {port}
            
            Provide a detailed security analysis in JSON format with these fields:
            1. vulnerabilities: Array of potential vulnerabilities (each with id, title, severity, description)
            2. recommendations: Array of security recommendations
            3. details: Array of important details about the service
            4. risk: Array of risk factors
            
            Format the response as valid JSON.
            """
            
            # Try available models in order of preference
            for model_name in self.available_models:
                try:
                    if model_name == "gemini" and self.gemini_model:
                        response = await self._get_gemini_analysis(prompt)
                    elif model_name == "openai" and self.openai_model:
                        response = await self._get_openai_analysis(prompt)
                    elif model_name == "local" and self.local_model:
                        response = self._get_local_analysis(service_data)
                    else:
                        continue
                        
                    if response:
                        # Try to parse JSON response
                        try:
                            # Extract JSON from response if needed
                            json_str = self._extract_json(response)
                            analysis = json.loads(json_str)
                            logger.info(f"Successfully analyzed service using {model_name} model")
                            return analysis
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse JSON from {model_name} response")
                            continue
                except Exception as e:
                    logger.warning(f"Error using {model_name} model: {str(e)}")
                    continue
            
            # If all AI models fail, fall back to offline analysis
            logger.warning("All AI models failed. Using offline analysis.")
            return analyze_service_offline(service_data)
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}")
            return analyze_service_offline(service_data)
    
    async def _get_gemini_analysis(self, prompt):
        """Get analysis from Gemini model."""
        try:
            if not self.gemini_model:
                return None
                
            response = self.gemini_model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.warning(f"Gemini analysis error: {str(e)}")
            return None
    
    async def _get_openai_analysis(self, prompt):
        """Get analysis from OpenAI model."""
        try:
            if not self.openai_model:
                return None
                
            response = await self.openai_model.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "system", "content": "You are a cybersecurity expert analyzing network services for vulnerabilities."},
                          {"role": "user", "content": prompt}],
                temperature=0.2
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"OpenAI analysis error: {str(e)}")
            return None
    
    def _get_local_analysis(self, service_data):
        """Get analysis from local ML model."""
        try:
            if not self.local_model:
                return None
                
            # Convert service data to features
            features = self._prepare_features(service_data)
            
            # Get prediction from model
            prediction = self.local_model.predict([features])[0]
            
            # Convert prediction to analysis format
            return self._format_local_prediction(prediction, service_data)
        except Exception as e:
            logger.warning(f"Local model analysis error: {str(e)}")
            return None
    
    def _prepare_features(self, service_data):
        """Prepare features for local ML model."""
        # This is a placeholder - actual implementation would depend on the model
        return [
            service_data.get('port', 0),
            hash(service_data.get('name', '')) % 100,
            hash(service_data.get('product', '')) % 100,
            hash(service_data.get('version', '')) % 100
        ]
    
    def _format_local_prediction(self, prediction, service_data):
        """Format local model prediction as analysis result."""
        # This is a placeholder - actual implementation would depend on the model
        return {
            'vulnerabilities': [
                {
                    'id': 'LOCAL-PRED-01',
                    'title': f"Potential vulnerability in {service_data.get('name', 'unknown service')}",
                    'severity': 'Medium',
                    'description': 'Vulnerability detected by local ML model based on service signature.'
                }
            ],
            'recommendations': [
                'Update service to latest version',
                'Apply security patches',
                'Restrict access to authorized users'
            ],
            'details': [
                f"Service: {service_data.get('name', 'unknown')}",
                f"Product: {service_data.get('product', 'unknown')} {service_data.get('version', '')}"
            ],
            'risk': [
                'Service may be vulnerable to known exploits',
                'Consider additional hardening measures'
            ]
        }
    
    def _extract_json(self, text):
        """Extract JSON from text response."""
        # Look for JSON in code blocks
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
        if json_match:
            return json_match.group(1)
            
        # Look for JSON with curly braces
        json_match = re.search(r'(\{[\s\S]*\})', text)
        if json_match:
            return json_match.group(1)
            
        # If no JSON found, return the original text
        return text

class SecurityAPIIntegration:
    """Integration with various security APIs"""
    def __init__(self):
        self.cache = {}
        self.cache_duration = 3600  # 1 hour cache

    async def get_cve_mitre(self, cve_id: str) -> dict:
        """Get CVE details from MITRE (Free API)"""
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error fetching CVE from MITRE: {str(e)}")
            return None

    async def check_virus_total(self, domain: str) -> dict:
        """Query VirusTotal API (Free tier - 500 requests/day)"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key:
            return None
            
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'apikey': api_key, 'domain': domain}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {str(e)}")
            return None

    async def query_abuse_ipdb(self, ip: str) -> dict:
        """Query AbuseIPDB (Free tier - 1000 requests/day)"""
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if not api_key:
            return None
            
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error checking AbuseIPDB: {str(e)}")
            return None

    async def check_greynoise(self, ip: str) -> dict:
        """Query GreyNoise (Free Community API)"""
        api_key = os.getenv('GREYNOISE_API_KEY')
        if not api_key:
            return None
            
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {'key': api_key}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error checking GreyNoise: {str(e)}")
            return None

    async def check_urlscan(self, domain: str) -> dict:
        """Query URLScan.io (Free API)"""
        api_key = os.getenv('URLSCAN_API_KEY')
        if not api_key:
            return None
            
        url = "https://urlscan.io/api/v1/scan/"
        headers = {
            'API-Key': api_key,
            'Content-Type': 'application/json'
        }
        data = {'url': domain, 'visibility': 'public'}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 200:
                        return await response.json()
                    return None
        except Exception as e:
            logger.error(f"Error submitting to URLScan: {str(e)}")
            return None

    async def lookup_vulnerabilities(self, product: str, version: str) -> list:
        """Lookup vulnerabilities for a product and version."""
        try:
            # Try Vulners API first
            if self.vulners_api:
                try:
                    vulners_results = self.vulners_api.softwareVulnerabilities(
                        product,
                        version
                    )
                    if vulners_results.get('vulnerabilities'):
                        return vulners_results['vulnerabilities']
                except Exception as e:
                    logger.error(f"Error getting vulnerabilities: {str(e)}")
            
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
                    vulns = []
                    for vuln in data.get('vulnerabilities', []):
                        cve = vuln.get('cve', {})
                        vuln_info = {
                            'id': cve.get('id'),
                            'description': cve.get('descriptions', [{}])[0].get('value', ''),
                            'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0),
                            'published': cve.get('published'),
                            'references': [ref.get('url') for ref in cve.get('references', [])],
                            'source': 'nvd'
                        }
                        vulns.append(vuln_info)
                    return vulns
            except Exception as e:
                logger.error(f"Error searching NVD: {str(e)}")
            
            # Add Shodan data if available
            try:
                if self.shodan_api:
                    api = self.shodan_api
                    results = api.search(f"product:{product}")
                    vulns = []
                    for result in results['matches'][:5]:
                        if 'vulns' in result:
                            for cve_id, vuln_info in result['vulns'].items():
                                vulns.append({
                                    'id': cve_id,
                                    'severity': float(vuln_info.get('cvss', 0)),
                                    'description': vuln_info.get('summary', ''),
                                    'source': 'shodan'
                                })
                    return vulns
            except Exception as e:
                logger.error(f"Error searching Shodan: {str(e)}")
            
            return []
        except Exception as e:
            logger.error(f"Error looking up vulnerabilities: {str(e)}")
            return []

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
        if 'http' in service.get('name', '') or 'https' in service.get('name', ''):
            recommendations.extend([
                "Verify SSL/TLS configuration and certificate validity",
                "Enable HTTP Strict Transport Security (HSTS)",
                "Implement proper Content Security Policy (CSP)"
            ])
        
        # Database recommendations
        if any(db in service.get('name', '') for db in ['mysql', 'postgresql', 'mongodb', 'redis']):
            recommendations.extend([
                "Ensure strong authentication is enabled",
                "Regularly backup database content",
                "Monitor for unusual access patterns"
            ])
        
        # Remote access recommendations
        if any(remote in service.get('name', '') for remote in ['ssh', 'rdp', 'vnc']):
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
        return "Error performing vulnerability analysis. See logs for details."

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
        
        # Initialize scanner
        scanner = init_scanner()
        
        # Validate target
        if not validate_target(target):
            raise ValueError(f"Invalid target: {target}")
            
        # Run nmap scan
        nm = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap',))
        scan_args = '-sV -sC' if scan_type == 'comprehensive' else '-sV'
        
        try:
            scan_results = await asyncio.to_thread(nm.scan, target, arguments=scan_args)
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            raise
            
        # Extract service information
        services = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    services.append({
                        'port': port,
                        'protocol': proto,
                        'state': service.get('state'),
                        'service': service.get('name'),
                        'product': service.get('product'),
                        'version': service.get('version'),
                        'extrainfo': service.get('extrainfo')
                    })
                    
        # Analyze each service
        analysis_results = []
        for service in services:
            service_analysis = await scanner.analyze_service(service)
            analysis_results.append({
                'service': service,
                'analysis': service_analysis
            })
            
        # Get additional host information
        host_info = {}
        if scanner.shodan_api:
            try:
                host_info = await asyncio.to_thread(get_shodan_info, target)
            except Exception as e:
                logger.warning(f"Error getting Shodan info: {str(e)}")
                
        # Format results
        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'services': services,
            'analysis': analysis_results,
            'host_info': host_info
        }
        
        return results
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        raise

def format_service_info(service_info, analysis):
    """Format service information and analysis results."""
    output = []
    
    # Basic service info
    name = service_info.get('name', 'Unknown')
    port = service_info.get('port', 'Unknown')
    protocol = service_info.get('protocol', 'tcp')
    product = service_info.get('product', '')
    version = service_info.get('version', '')
    
    # Format service line
    service_line = f"{port}/{protocol} - {name}"
    if product:
        service_line += f" ({product}"
        if version:
            service_line += f" {version}"
        service_line += ")"
    output.append(service_line)
    
    # CVE Vulnerabilities
    if analysis.get('vulnerabilities'):
        output.append("\nDetected CVEs:")
        for vuln in analysis['vulnerabilities']:
            cve = vuln['details']
            output.append(f"\n[{vuln['cve_id']}] - Severity: {cve['severity']}")
            output.append(f"Description: {cve['description']}")
            output.append(f"Published: {cve['published']}")
            if cve['references']:
                output.append("References:")
                for ref in cve['references'][:3]:  # Limit to top 3 references
                    output.append(f"- {ref}")
    
    # Available Exploits
    if analysis.get('exploits'):
        output.append("\nAvailable Exploits:")
        for exploit in analysis['exploits']:
            output.append(f"\n[{exploit['source']}]")
            if 'url' in exploit:
                output.append(f"URL: {exploit['url']}")
            if 'command' in exploit:
                output.append(f"Command: {exploit['command']}")
            output.append(f"Type: {exploit['type']}")
    
    # Exploitation Guidance
    if analysis.get('exploitation_guidance'):
        for guidance in analysis['exploitation_guidance']:
            output.append(f"\nExploitation Guide for {guidance['cve_id']}:")
            
            if guidance['guidance'].get('prerequisites'):
                output.append("\nPrerequisites:")
                for prereq in guidance['guidance']['prerequisites']:
                    output.append(f"- {prereq}")
            
            if guidance['guidance'].get('exploitation_steps'):
                output.append("\nExploitation Steps:")
                for i, step in enumerate(guidance['guidance']['exploitation_steps'], 1):
                    output.append(f"{i}. {step}")
            
            if guidance['guidance'].get('post_exploitation'):
                output.append("\nPost-Exploitation:")
                for post in guidance['guidance']['post_exploitation']:
                    output.append(f"- {post}")
            
            if guidance['guidance'].get('mitigation'):
                output.append("\nMitigation Steps:")
                for mit in guidance['guidance']['mitigation']:
                    output.append(f"- {mit}")
    
    # Attack vectors
    if analysis.get('attack_vectors'):
        output.append("\nCommon Attack Vectors:")
        for vector in analysis['attack_vectors']:
            output.append(f"- {vector}")
    
    # Best practices
    if analysis.get('best_practices'):
        output.append("\nBest Practices:")
        for practice in analysis['best_practices']:
            output.append(f"- {practice}")
    
    return "\n".join(output)

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
        return None

def format_text_report(results):
    """Format scan results as text."""
    output = []
    
    # Format header
    output.append(f"Findings for {results['target']}:")
    if results.get('hostname'):
        output.append(f"Hostname: {', '.join(results['hostname'])}")
    output.append(f"Risk Level: {results['risk_level']}\n")
    
    # Format service analysis
    output.append("Service Analysis:\n")
    for service in results['services'].values():
        output.append(f"\n{service['port']}/tcp - {service['name']} ({service.get('product', '')} {service.get('version', '')})")
        if service.get('recommendations'):
            output.append("Recommendations:")
            # Handle recommendations that might be a list
            if isinstance(service['recommendations'], list):
                output.extend(service['recommendations'])
            else:
                output.append(service['recommendations'])
        output.append("")
    
    # Format Shodan info if available
    if results.get('shodan_info'):
        output.append("\nShodan Information:")
        for key, value in results['shodan_info'].items():
            output.append(f"{key}: {value}")
    
    return "\n".join(str(line) for line in output)

def init_vulners_api():
    """Initialize Vulners API with API key from environment."""
    try:
        api_key = os.getenv('VULNERS_API_KEY')
        if not api_key:
            logger.warning("No Vulners API key found in environment. Vulnerability database lookups will be limited.")
            return None
        
        try:
            # Initialize without retry configuration
            vulners_api = vulners.Vulners(api_key=api_key)
            return vulners_api
        except ImportError:
            logger.warning("Vulners library not installed. Vulnerability database lookups will be limited.")
            return None
        except Exception as e:
            logger.warning(f"Error initializing Vulners API: {str(e)}. Continuing without it.")
            return None
    except Exception as e:
        logger.warning(f"Unexpected error initializing Vulners API: {str(e)}. Continuing without it.")
        return None

def get_hostnames(ip: str) -> list:
    """Get hostnames for an IP address."""
    try:
        hostnames = socket.gethostbyaddr(ip)[0]
        return [hostnames] if isinstance(hostnames, str) else hostnames
    except (socket.herror, socket.gaierror):
        return []

def init_shodan_api():
    """Initialize Shodan API with API key from environment."""
    try:
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            logger.warning("No Shodan API key found in environment. External reconnaissance will be limited.")
            return None
        
        try:
            import shodan
            shodan_api = shodan.Shodan(api_key)
            # Test with a simple request to verify API key works
            try:
                info = shodan_api.info()
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

def init_gemini():
    """Initialize Google Gemini API with proper configuration."""
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            logger.warning("Gemini API key not found. Gemini AI analysis will be disabled.")
            return None
            
        # Check if location is supported
        try:
            response = requests.get('https://ipapi.co/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                country = data.get('country_name', 'Unknown')
                if country not in ['United States', 'Canada', 'United Kingdom']:  # Add more supported countries
                    logger.warning(f"Gemini API not available in {country}. Using fallback analysis.")
                    return None
        except Exception as e:
            logger.warning(f"Error checking location: {str(e)}. Continuing without location check.")
            # Continue anyway, let the API call itself determine if region is supported

        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            
            # Configure the model with safety settings
            model = genai.GenerativeModel('gemini-pro',
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,
                    candidate_count=1,
                    max_output_tokens=2048,
                ),
                safety_settings=[
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                    },
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE"
                    }
                ]
            )
            print("+ Gemini AI initialized")
            return model
        except ImportError:
            logger.warning("Google Generative AI library not installed. Gemini AI analysis will be disabled.")
            return None
        except Exception as e:
            logger.warning(f"Error initializing Gemini API: {str(e)}. Continuing without it.")
            return None
    except Exception as e:
        logger.warning(f"Unexpected error initializing Gemini API: {str(e)}. Continuing without it.")
        return None

def init_openai():
    """Initialize OpenAI API with proper configuration."""
    try:
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            logger.warning("OpenAI API key not found. OpenAI analysis will be disabled.")
            return None
            
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            # Test with a simple request to verify API key works
            try:
                response = client.models.list()
                print("+ OpenAI API initialized")
                return client
            except Exception as e:
                logger.warning(f"OpenAI API key validation failed: {str(e)}. Continuing without it.")
                return None
        except ImportError:
            logger.warning("OpenAI library not installed. OpenAI analysis will be disabled.")
            return None
        except Exception as e:
            logger.warning(f"Error initializing OpenAI client: {str(e)}. Continuing without it.")
            return None
    except Exception as e:
        logger.warning(f"Unexpected error initializing OpenAI: {str(e)}. Continuing without it.")
        return None

def init_local_ml_model():
    """Initialize local machine learning model for basic analysis."""
    try:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            
            # Check if CUDA is available
            device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            
            try:
                model_name = "microsoft/codebert-base"
                tokenizer = AutoTokenizer.from_pretrained(model_name)
                model = AutoModelForSequenceClassification.from_pretrained(model_name)
                model.to(device)
                
                print("+ Local ML model initialized")
                return model  # Return the model object
            except Exception as e:
                logger.warning(f"Error loading ML model: {str(e)}. Continuing without it.")
                return None
        except ImportError:
            logger.warning("Required ML libraries not installed. Local ML analysis will be disabled.")
            return None
    except Exception as e:
        logger.warning(f"Unexpected error initializing local ML model: {str(e)}. Continuing without it.")
        return None

def init_ai_analyzer():
    """Initialize AI Security Analyzer."""
    try:
        return AISecurityAnalyzer()
    except Exception as e:
        logger.warning(f"Failed to initialize AI analyzer: {str(e)}")
        return None

async def main():
    """Main entry point for the vulnerability scanner."""
    try:
        # Initialize scanner
        scanner = init_scanner()
        
        # Validate target
        if not validate_target(args.target):
            logger.error(f"Invalid target: {args.target}")
            return
            
        # Run scan based on type
        if args.scan_type == 'container':
            container_scanner = ContainerScanner()
            results = await container_scanner.scan_container(args.target)
        elif args.scan_type == 'cloud':
            cloud_scanner = CloudScanner()
            results = await cloud_scanner.scan_cloud_infrastructure(args.cloud_providers)
        else:
            results = await scan(args.target, args.scan_type)
            
        # Save results if output file specified
        if args.output:
            save_results(results, args.output)
            
        return results
        
    except Exception as e:
        logger.error(f"Error running vulnerability scan: {str(e)}")
        if args.verbose:
            logger.error(traceback.format_exc())
        return None

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())

def analyze_service_offline(service_data: dict) -> List[str]:
    """Analyze a service without using AI models."""
    recommendations = []
    
    # Basic service checks
    service_name = service_data.get('name', '').lower()
    product = service_data.get('product', '').lower()
    version = service_data.get('version', '')
    
    # Check for common high-risk services
    high_risk_services = {
        'telnet': 'Telnet uses unencrypted communications. Replace with SSH.',
        'ftp': 'FTP sends credentials in plaintext. Use SFTP or FTPS instead.',
        'smtp': 'Ensure SMTP is properly configured with TLS encryption.',
        'mysql': 'Restrict MySQL access and use encrypted connections.',
        'mongodb': 'Ensure MongoDB authentication is enabled and properly configured.',
        'redis': 'Redis should not be exposed to public networks.',
        'elasticsearch': 'Elasticsearch should be properly secured with authentication.',
        'jenkins': 'Jenkins should be behind a secure proxy with authentication.',
        'wordpress': 'Keep WordPress and all plugins up to date.',
        'phpmyadmin': 'PhpMyAdmin should be protected and regularly updated.',
    }
    
    # Add service-specific recommendations
    if service_name in high_risk_services:
        recommendations.append(high_risk_services[service_name])
    
    # Version checks
    if version:
        recommendations.append(f"Verify {product} version {version} is the latest stable release")
    
    # Port-specific recommendations
    port = service_data.get('port', 0)
    if port < 1024:
        recommendations.append(f"Service running on privileged port {port}. Consider running as non-root if possible.")
    
    # Protocol recommendations
    if service_data.get('protocol') == 'tcp':
        recommendations.append("Ensure firewall rules restrict access to necessary IPs only")
    
    # SSL/TLS checks
    if 'http' in service_name or 'https' in service_name:
        recommendations.extend([
            "Verify SSL/TLS configuration and certificate validity",
            "Enable HTTP Strict Transport Security (HSTS)",
            "Implement proper Content Security Policy (CSP)"
        ])
    
    # Database recommendations
    if any(db in service_name for db in ['mysql', 'postgresql', 'mongodb', 'redis']):
        recommendations.extend([
            "Ensure strong authentication is enabled",
            "Regularly backup database content",
            "Monitor for unusual access patterns"
        ])
    
    # Remote access recommendations
    if any(remote in service_name for remote in ['ssh', 'rdp', 'vnc']):
        recommendations.extend([
            "Use strong authentication methods",
            "Implement fail2ban or similar brute-force protection",
            "Restrict access to specific IP ranges"
        ])
    
    return recommendations
