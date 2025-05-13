#!/usr/bin/env python3
"""
Container Security Vulnerability Scanner
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
import docker
import subprocess
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import tempfile
import yaml
from concurrent.futures import ThreadPoolExecutor
import asyncio
import aiohttp
import re

logger = logging.getLogger(__name__)

@dataclass
class ContainerVulnerability:
    id: str
    package: str
    version: str
    fixed_version: Optional[str]
    severity: str
    description: str
    cve_id: Optional[str]
    remediation: str

@dataclass
class ContainerScanResult:
    image_name: str
    vulnerabilities: List[ContainerVulnerability]
    misconfigurations: List[Dict]
    secrets: List[Dict]
    compliance_issues: List[Dict]
    base_image_info: Dict
    layers_info: List[Dict]
    total_size: int
    created_date: str

class ContainerScanner:
    def __init__(self):
        """Initialize the container scanner."""
        self.docker_client = None
        self.trivy_available = self._check_trivy()
        self.grype_available = self._check_grype()
        
    def _check_trivy(self) -> bool:
        """Check if Trivy is installed."""
        try:
            subprocess.run(['trivy', '--version'], capture_output=True)
            return True
        except FileNotFoundError:
            logger.warning("Trivy not found. Some container scanning features will be limited.")
            return False
            
    def _check_grype(self) -> bool:
        """Check if Grype is installed."""
        try:
            subprocess.run(['grype', '--version'], capture_output=True)
            return True
        except FileNotFoundError:
            logger.warning("Grype not found. Some container scanning features will be limited.")
            return False
            
    async def scan_container(self, target: str) -> ContainerScanResult:
        """
        Scan a container image or running container.
        Args:
            target: Container image name or container ID
        Returns:
            ContainerScanResult object with scan findings
        """
        try:
            # Initialize Docker client
            self.docker_client = docker.from_env()
            
            # Get container/image info
            image_info = await self._get_image_info(target)
            
            # Run parallel scans
            vulns, misconfigs, secrets = await asyncio.gather(
                self._scan_vulnerabilities(target),
                self._check_misconfigurations(target),
                self._scan_secrets(target)
            )
            
            # Check compliance
            compliance_issues = await self._check_compliance(target)
            
            return ContainerScanResult(
                image_name=target,
                vulnerabilities=vulns,
                misconfigurations=misconfigs,
                secrets=secrets,
                compliance_issues=compliance_issues,
                base_image_info=image_info.get('base_image', {}),
                layers_info=image_info.get('layers', []),
                total_size=image_info.get('size', 0),
                created_date=image_info.get('created', '')
            )
            
        except Exception as e:
            logger.error(f"Error scanning container {target}: {str(e)}")
            raise
            
    async def _get_image_info(self, target: str) -> Dict:
        """Get detailed information about the container image."""
        try:
            image = self.docker_client.images.get(target)
            history = image.history()
            
            # Extract base image from history
            base_image = next((layer for layer in reversed(history) 
                             if layer.get('Tags')), {})
            
            return {
                'base_image': {
                    'name': base_image.get('Tags', ['unknown'])[0],
                    'size': base_image.get('Size', 0),
                    'created': base_image.get('Created', '')
                },
                'layers': history,
                'size': image.attrs['Size'],
                'created': image.attrs['Created']
            }
        except Exception as e:
            logger.error(f"Error getting image info: {str(e)}")
            return {}
            
    async def _scan_vulnerabilities(self, target: str) -> List[ContainerVulnerability]:
        """Scan for vulnerabilities using multiple scanners."""
        vulnerabilities = []
        
        # Use Trivy if available
        if self.trivy_available:
            trivy_results = await self._run_trivy_scan(target)
            vulnerabilities.extend(trivy_results)
            
        # Use Grype if available
        if self.grype_available:
            grype_results = await self._run_grype_scan(target)
            vulnerabilities.extend(grype_results)
            
        # Deduplicate vulnerabilities
        return self._deduplicate_vulnerabilities(vulnerabilities)
        
    async def _run_trivy_scan(self, target: str) -> List[ContainerVulnerability]:
        """Run Trivy vulnerability scanner."""
        try:
            cmd = ['trivy', 'image', '--format', 'json', target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Trivy scan failed: {stderr.decode()}")
                return []
                
            results = json.loads(stdout.decode())
            vulnerabilities = []
            
            for vuln in results.get('Results', []):
                for v in vuln.get('Vulnerabilities', []):
                    vulnerabilities.append(ContainerVulnerability(
                        id=v.get('VulnerabilityID', ''),
                        package=v.get('PkgName', ''),
                        version=v.get('InstalledVersion', ''),
                        fixed_version=v.get('FixedVersion'),
                        severity=v.get('Severity', 'Unknown'),
                        description=v.get('Description', ''),
                        cve_id=v.get('PrimaryURL', ''),
                        remediation=v.get('FixedVersion', 'Update to the latest version')
                    ))
                    
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error running Trivy scan: {str(e)}")
            return []
            
    async def _run_grype_scan(self, target: str) -> List[ContainerVulnerability]:
        """Run Grype vulnerability scanner."""
        try:
            cmd = ['grype', target, '--output', 'json']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Grype scan failed: {stderr.decode()}")
                return []
                
            results = json.loads(stdout.decode())
            vulnerabilities = []
            
            for match in results.get('matches', []):
                vuln = match.get('vulnerability', {})
                vulnerabilities.append(ContainerVulnerability(
                    id=vuln.get('id', ''),
                    package=match.get('artifact', {}).get('name', ''),
                    version=match.get('artifact', {}).get('version', ''),
                    fixed_version=vuln.get('fix', {}).get('versions', [None])[0],
                    severity=vuln.get('severity', 'Unknown'),
                    description=vuln.get('description', ''),
                    cve_id=vuln.get('advisories', [{}])[0].get('url', ''),
                    remediation=f"Update to version {vuln.get('fix', {}).get('versions', ['latest'])[0]}"
                ))
                
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error running Grype scan: {str(e)}")
            return []
            
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[ContainerVulnerability]) -> List[ContainerVulnerability]:
        """Remove duplicate vulnerabilities based on ID and package."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = (vuln.id, vuln.package, vuln.version)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
                
        return unique_vulns
        
    async def _check_misconfigurations(self, target: str) -> List[Dict]:
        """Check for container misconfigurations."""
        misconfigs = []
        
        try:
            # Get Dockerfile if available
            dockerfile = await self._get_dockerfile(target)
            if dockerfile:
                misconfigs.extend(await self._analyze_dockerfile(dockerfile))
                
            # Check container runtime configurations
            runtime_configs = await self._check_runtime_configs(target)
            misconfigs.extend(runtime_configs)
            
            return misconfigs
            
        except Exception as e:
            logger.error(f"Error checking misconfigurations: {str(e)}")
            return []
            
    async def _get_dockerfile(self, target: str) -> Optional[str]:
        """Try to get Dockerfile content from image history."""
        try:
            image = self.docker_client.images.get(target)
            history = image.history()
            
            dockerfile_lines = []
            for layer in history:
                cmd = layer.get('CreatedBy', '')
                if cmd.startswith('/bin/sh -c #(nop)'):
                    # Clean up the command
                    cmd = cmd.replace('/bin/sh -c #(nop)', '').strip()
                    dockerfile_lines.append(cmd)
                elif cmd.startswith('/bin/sh -c'):
                    # Regular command
                    cmd = cmd.replace('/bin/sh -c', 'RUN').strip()
                    dockerfile_lines.append(cmd)
                    
            return '\n'.join(reversed(dockerfile_lines)) if dockerfile_lines else None
            
        except Exception as e:
            logger.error(f"Error getting Dockerfile: {str(e)}")
            return None
            
    async def _analyze_dockerfile(self, dockerfile: str) -> List[Dict]:
        """Analyze Dockerfile for security issues."""
        issues = []
        
        # Common Dockerfile security checks
        checks = [
            {
                'pattern': r'FROM\s+.*:latest',
                'severity': 'Medium',
                'message': 'Using latest tag is not recommended',
                'remediation': 'Specify a fixed version tag'
            },
            {
                'pattern': r'RUN\s+.*apt-get\s+.*--no-install-recommends',
                'severity': 'Low',
                'message': 'Missing --no-install-recommends in apt-get',
                'remediation': 'Add --no-install-recommends to reduce image size'
            },
            {
                'pattern': r'USER\s+root',
                'severity': 'High',
                'message': 'Container running as root',
                'remediation': 'Use non-root user'
            }
        ]
        
        for check in checks:
            if re.search(check['pattern'], dockerfile):
                issues.append({
                    'type': 'Dockerfile',
                    'severity': check['severity'],
                    'message': check['message'],
                    'remediation': check['remediation']
                })
                
        return issues
        
    async def _check_runtime_configs(self, target: str) -> List[Dict]:
        """Check container runtime configurations."""
        issues = []
        
        try:
            container_info = self.docker_client.api.inspect_container(target)
            
            # Check privileged mode
            if container_info['HostConfig'].get('Privileged'):
                issues.append({
                    'type': 'Runtime',
                    'severity': 'Critical',
                    'message': 'Container running in privileged mode',
                    'remediation': 'Avoid using privileged mode'
                })
                
            # Check port bindings
            ports = container_info['HostConfig'].get('PortBindings', {})
            if '0.0.0.0' in str(ports):
                issues.append({
                    'type': 'Runtime',
                    'severity': 'Medium',
                    'message': 'Container ports bound to all interfaces',
                    'remediation': 'Bind ports to specific interfaces only'
                })
                
            # Check volume mounts
            if container_info['HostConfig'].get('Binds'):
                issues.append({
                    'type': 'Runtime',
                    'severity': 'Medium',
                    'message': 'Container using host volume mounts',
                    'remediation': 'Use named volumes instead of host mounts'
                })
                
            return issues
            
        except Exception as e:
            logger.error(f"Error checking runtime configs: {str(e)}")
            return []
            
    async def _scan_secrets(self, target: str) -> List[Dict]:
        """Scan for secrets in container image."""
        secrets = []
        
        try:
            # Create temporary directory for image extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                # Save image to tar
                image = self.docker_client.images.get(target)
                image_tar = os.path.join(temp_dir, 'image.tar')
                with open(image_tar, 'wb') as f:
                    for chunk in image.save():
                        f.write(chunk)
                        
                # Extract image
                subprocess.run(['tar', 'xf', image_tar, '-C', temp_dir])
                
                # Scan for secrets
                secrets.extend(await self._find_secrets(temp_dir))
                
            return secrets
            
        except Exception as e:
            logger.error(f"Error scanning for secrets: {str(e)}")
            return []
            
    async def _find_secrets(self, directory: str) -> List[Dict]:
        """Find secrets in files."""
        secrets = []
        patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Private Key': r'-----BEGIN (\w+) PRIVATE KEY-----',
            'API Key': r'api[_-]?key.*[\'"][0-9a-zA-Z]{32,45}[\'"]',
            'Password': r'password.*[\'"][^\'\"]{8,}[\'"]',
            'Token': r'token.*[\'"][^\'\"]{8,}[\'"]'
        }
        
        for root, _, files in os.walk(directory):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for secret_type, pattern in patterns.items():
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                secrets.append({
                                    'type': 'Secret',
                                    'secret_type': secret_type,
                                    'file': os.path.relpath(file_path, directory),
                                    'severity': 'Critical',
                                    'message': f'Potential {secret_type} found',
                                    'remediation': 'Remove secrets and use environment variables or secrets management'
                                })
                except Exception as e:
                    logger.debug(f"Error reading file {file}: {str(e)}")
                    
        return secrets
        
    async def _check_compliance(self, target: str) -> List[Dict]:
        """Check container compliance with security standards."""
        compliance_issues = []
        
        # CIS Docker Benchmark checks
        cis_checks = [
            {
                'check': self._check_host_namespace_sharing,
                'section': '5.2',
                'title': 'Host Namespace Sharing'
            },
            {
                'check': self._check_memory_limits,
                'section': '5.11',
                'title': 'Memory Limits'
            },
            {
                'check': self._check_cpu_priority,
                'section': '5.12',
                'title': 'CPU Priority'
            }
        ]
        
        for check in cis_checks:
            result = await check['check'](target)
            if result:
                compliance_issues.append({
                    'type': 'Compliance',
                    'standard': 'CIS Docker Benchmark',
                    'section': check['section'],
                    'title': check['title'],
                    'severity': 'High',
                    'message': result['message'],
                    'remediation': result['remediation']
                })
                
        return compliance_issues
        
    async def _check_host_namespace_sharing(self, target: str) -> Optional[Dict]:
        """Check CIS Benchmark 5.2 - Host Namespace Sharing."""
        try:
            container_info = self.docker_client.api.inspect_container(target)
            host_config = container_info['HostConfig']
            
            if (host_config.get('PidMode') == 'host' or
                host_config.get('NetworkMode') == 'host' or
                host_config.get('IpcMode') == 'host'):
                return {
                    'message': 'Container sharing host namespaces',
                    'remediation': 'Avoid sharing host namespaces unless absolutely necessary'
                }
            return None
            
        except Exception as e:
            logger.error(f"Error checking host namespace sharing: {str(e)}")
            return None
            
    async def _check_memory_limits(self, target: str) -> Optional[Dict]:
        """Check CIS Benchmark 5.11 - Memory Limits."""
        try:
            container_info = self.docker_client.api.inspect_container(target)
            if not container_info['HostConfig'].get('Memory'):
                return {
                    'message': 'No memory limits set',
                    'remediation': 'Set memory limits using --memory flag'
                }
            return None
            
        except Exception as e:
            logger.error(f"Error checking memory limits: {str(e)}")
            return None
            
    async def _check_cpu_priority(self, target: str) -> Optional[Dict]:
        """Check CIS Benchmark 5.12 - CPU Priority."""
        try:
            container_info = self.docker_client.api.inspect_container(target)
            if not container_info['HostConfig'].get('CpuShares'):
                return {
                    'message': 'No CPU shares set',
                    'remediation': 'Set CPU shares using --cpu-shares flag'
                }
            return None
            
        except Exception as e:
            logger.error(f"Error checking CPU priority: {str(e)}")
            return None
