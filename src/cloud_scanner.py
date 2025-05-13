#!/usr/bin/env python3
"""
Cloud Infrastructure Vulnerability Scanner
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
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from contextlib import asynccontextmanager

# AWS imports
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Azure imports
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import AzureError

# GCP imports
from google.cloud.securitycenter_v1 import SecurityCenterClient
from google.cloud.asset_v1 import AssetServiceClient, ListAssetsRequest
from google.api_core.exceptions import GoogleAPIError

from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class CloudResource:
    provider: str  # aws, azure, or gcp
    resource_type: str
    resource_id: str
    name: str
    region: str
    tags: Dict[str, str]
    configuration: Dict[str, Any]

@dataclass
class CloudVulnerability:
    provider: str
    resource_id: str
    severity: str
    description: str
    recommendation: str
    compliance_standards: List[str]
    risk_score: float

@dataclass
class CloudScanResult:
    provider: str
    resources: List[CloudResource]
    vulnerabilities: List[CloudVulnerability]
    misconfigurations: List[Dict[str, Any]]
    compliance_status: Dict[str, Any]
    iam_issues: List[Dict[str, Any]]
    network_findings: List[Dict[str, Any]]
    encryption_status: Dict[str, Any]
    scan_timestamp: str

class CloudScanner:
    def __init__(self):
        """Initialize cloud scanner with necessary clients."""
        self.aws_enabled = False
        self.azure_enabled = False
        self.gcp_enabled = False
        self.initialize_clients()
        
    def initialize_clients(self) -> None:
        """Initialize cloud provider clients."""
        try:
            # AWS
            self.aws_session = boto3.Session()
            self.aws_enabled = True
            logger.info("AWS client initialized successfully")
        except (BotoCoreError, ClientError) as e:
            logger.warning(f"Failed to initialize AWS client: {str(e)}")
            
        try:
            # Azure
            self.azure_credential = DefaultAzureCredential()
            self.subscription_client = SubscriptionClient(self.azure_credential)
            self.azure_enabled = True
            logger.info("Azure client initialized successfully")
        except AzureError as e:
            logger.warning(f"Failed to initialize Azure client: {str(e)}")
            
        try:
            # GCP
            self.gcp_security_client = SecurityCenterClient()
            self.gcp_asset_client = AssetServiceClient()
            self.gcp_enabled = True
            logger.info("GCP client initialized successfully")
        except GoogleAPIError as e:
            logger.warning(f"Failed to initialize GCP client: {str(e)}")
            
    async def scan_cloud_infrastructure(self, providers: Optional[List[str]] = None) -> Dict[str, CloudScanResult]:
        """
        Scan cloud infrastructure across specified providers.
        Args:
            providers: List of cloud providers to scan ('aws', 'azure', 'gcp')
        Returns:
            Dict of scan results per provider
        """
        if not providers:
            providers = ['aws', 'azure', 'gcp']
            
        results = {}
        tasks = []
        
        for provider in providers:
            if provider == 'aws' and self.aws_enabled:
                tasks.append(self.scan_aws_infrastructure())
            elif provider == 'azure' and self.azure_enabled:
                tasks.append(self.scan_azure_infrastructure())
            elif provider == 'gcp' and self.gcp_enabled:
                tasks.append(self.scan_gcp_infrastructure())
                
        # Run scans concurrently
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for provider, result in zip(providers, scan_results):
            if isinstance(result, Exception):
                logger.error(f"Error scanning {provider}: {str(result)}")
                continue
            results[provider] = result
            
        return results
        
    async def scan_aws_infrastructure(self) -> CloudScanResult:
        """Scan AWS infrastructure for security issues."""
        try:
            print("Scanning AWS infrastructure...")
            
            # Initialize AWS clients
            securityhub = self.aws_session.client('securityhub')
            inspector = self.aws_session.client('inspector2')
            config = self.aws_session.client('config')
            
            # Gather resources and findings concurrently
            resources, findings, configs = await asyncio.gather(
                self._get_aws_resources(),
                self._get_aws_security_findings(securityhub),
                self._get_aws_config_findings(config)
            )
            
            # Process findings into vulnerabilities
            vulnerabilities = []
            for finding in findings:
                vulnerabilities.append(CloudVulnerability(
                    provider='aws',
                    resource_id=finding.get('Resources', [{}])[0].get('Id', ''),
                    severity=finding.get('Severity', {}).get('Label', 'UNKNOWN'),
                    description=finding.get('Description', ''),
                    recommendation=finding.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                    compliance_standards=finding.get('Compliance', {}).get('SecurityControlId', []),
                    risk_score=float(finding.get('Severity', {}).get('Score', 0))
                ))
                
            # Get IAM issues
            iam_issues = await self._check_aws_iam_issues()
            
            # Get network findings
            network_findings = await self._check_aws_network_security()
            
            # Check encryption status
            encryption_status = await self._check_aws_encryption()
            
            return CloudScanResult(
                provider='aws',
                resources=resources,
                vulnerabilities=vulnerabilities,
                misconfigurations=configs,
                compliance_status=await self._get_aws_compliance_status(),
                iam_issues=iam_issues,
                network_findings=network_findings,
                encryption_status=encryption_status,
                scan_timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error scanning AWS infrastructure: {str(e)}")
            raise
            
    async def scan_azure_infrastructure(self) -> CloudScanResult:
        """Scan Azure infrastructure for security issues."""
        try:
            print("Scanning Azure infrastructure...")
            
            # Get all subscriptions
            subscriptions = list(self.subscription_client.subscriptions.list())
            
            all_resources = []
            all_vulnerabilities = []
            all_misconfigs = []
            all_compliance = {}
            all_iam = []
            all_network = []
            all_encryption = {}
            
            # Scan each subscription
            for subscription in subscriptions:
                # Initialize Security Center client for this subscription
                security_client = SecurityCenter(
                    self.azure_credential,
                    subscription.subscription_id
                )
                
                # Gather data concurrently
                resources, assessments, policies = await asyncio.gather(
                    self._get_azure_resources(subscription.subscription_id),
                    self._get_azure_security_assessments(security_client),
                    self._get_azure_security_policies(security_client)
                )
                
                all_resources.extend(resources)
                
                # Process security assessments into vulnerabilities
                for assessment in assessments:
                    all_vulnerabilities.append(CloudVulnerability(
                        provider='azure',
                        resource_id=assessment.id,
                        severity=assessment.status.severity,
                        description=assessment.metadata.description,
                        recommendation=assessment.metadata.remediation_description,
                        compliance_standards=assessment.metadata.standards,
                        risk_score=float(assessment.status.score)
                    ))
                    
                # Get additional security information
                iam_results = await self._check_azure_iam_issues(subscription.subscription_id)
                network_results = await self._check_azure_network_security(subscription.subscription_id)
                encryption_results = await self._check_azure_encryption(subscription.subscription_id)
                
                all_iam.extend(iam_results)
                all_network.extend(network_results)
                all_encryption.update(encryption_results)
                
            return CloudScanResult(
                provider='azure',
                resources=all_resources,
                vulnerabilities=all_vulnerabilities,
                misconfigurations=all_misconfigs,
                compliance_status=all_compliance,
                iam_issues=all_iam,
                network_findings=all_network,
                encryption_status=all_encryption,
                scan_timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error scanning Azure infrastructure: {str(e)}")
            raise
            
    async def scan_gcp_infrastructure(self) -> CloudScanResult:
        """Scan GCP infrastructure for security issues."""
        try:
            print("Scanning GCP infrastructure...")
            
            # Get organization ID
            org_id = await self._get_gcp_org_id()
            
            if not org_id:
                raise ValueError("No GCP organization found")
                
            # Create the organization path
            org_path = f"organizations/{org_id}"
            
            # Gather data concurrently
            resources, findings = await asyncio.gather(
                self._get_gcp_resources(org_path),
                self._get_gcp_security_findings(org_path)
            )
            
            # Process findings into vulnerabilities
            vulnerabilities = []
            for finding in findings:
                vulnerabilities.append(CloudVulnerability(
                    provider='gcp',
                    resource_id=finding.resource_name,
                    severity=finding.severity,
                    description=finding.description,
                    recommendation=finding.recommendation,
                    compliance_standards=finding.compliance_standards,
                    risk_score=float(finding.severity_score)
                ))
                
            # Get additional security information
            iam_issues = await self._check_gcp_iam_issues(org_path)
            network_findings = await self._check_gcp_network_security(org_path)
            encryption_status = await self._check_gcp_encryption(org_path)
            
            return CloudScanResult(
                provider='gcp',
                resources=resources,
                vulnerabilities=vulnerabilities,
                misconfigurations=await self._get_gcp_misconfigurations(org_path),
                compliance_status=await self._get_gcp_compliance_status(org_path),
                iam_issues=iam_issues,
                network_findings=network_findings,
                encryption_status=encryption_status,
                scan_timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error scanning GCP infrastructure: {str(e)}")
            raise
            
    # AWS Helper Methods
    async def _get_aws_resources(self) -> List[CloudResource]:
        """Get AWS resources across all regions."""
        resources = []
        regions = self.aws_session.get_available_regions('ec2')
        
        async def scan_region(region: str) -> None:
            try:
                resource = boto3.resource('ec2', region_name=region)
                instances = list(resource.instances.all())
                
                for instance in instances:
                    resources.append(CloudResource(
                        provider='aws',
                        resource_type='ec2',
                        resource_id=instance.id,
                        name=next((tag['Value'] for tag in instance.tags or [] 
                                 if tag['Key'] == 'Name'), ''),
                        region=region,
                        tags=dict((tag['Key'], tag['Value']) for tag in instance.tags or []),
                        configuration={
                            'state': instance.state['Name'],
                            'type': instance.instance_type,
                            'vpc_id': instance.vpc_id,
                            'subnet_id': instance.subnet_id,
                            'security_groups': [sg['GroupId'] for sg in instance.security_groups]
                        }
                    ))
            except (BotoCoreError, ClientError) as e:
                logger.error(f"Error scanning AWS region {region}: {str(e)}")
                
        await asyncio.gather(*[scan_region(region) for region in regions])
        return resources
        
    # Azure Helper Methods
    async def _get_azure_resources(self, subscription_id: str) -> List[CloudResource]:
        """Get Azure resources for a subscription."""
        resources = []
        try:
            resource_client = ResourceManagementClient(self.azure_credential, subscription_id)
            
            for resource in resource_client.resources.list():
                resources.append(CloudResource(
                    provider='azure',
                    resource_type=resource.type,
                    resource_id=resource.id,
                    name=resource.name,
                    region=resource.location,
                    tags=resource.tags or {},
                    configuration=resource.as_dict()
                ))
        except AzureError as e:
            logger.error(f"Error getting Azure resources: {str(e)}")
            
        return resources
        
    # GCP Helper Methods
    async def _get_gcp_resources(self, org_path: str) -> List[CloudResource]:
        """Get GCP resources for an organization."""
        resources = []
        
        try:
            # Create asset feed request
            request = ListAssetsRequest(
                parent=org_path,
                asset_types=['compute.googleapis.com/Instance']
            )
            
            # List all assets
            for asset in self.gcp_asset_client.list_assets(request):
                resource_data = asset.asset.resource.data
                resources.append(CloudResource(
                    provider='gcp',
                    resource_type=asset.asset_type,
                    resource_id=asset.name,
                    name=resource_data.get('name', ''),
                    region=resource_data.get('zone', '').rsplit('/', 1)[-1],
                    tags=resource_data.get('labels', {}),
                    configuration=resource_data
                ))
        except GoogleAPIError as e:
            logger.error(f"Error getting GCP resources: {str(e)}")
            
        return resources
        
    # Additional helper methods would be implemented here for each provider
    # Including methods for checking IAM, network security, encryption, etc.
    
    async def _get_aws_security_findings(self, securityhub) -> List[Dict]:
        """Get AWS SecurityHub findings."""
        # Implementation here
        return []
        
    async def _get_aws_config_findings(self, config) -> List[Dict]:
        """Get AWS Config findings."""
        # Implementation here
        return []
        
    async def _check_aws_iam_issues(self) -> List[Dict]:
        """Check AWS IAM issues."""
        # Implementation here
        return []
        
    async def _check_aws_network_security(self) -> List[Dict]:
        """Check AWS network security."""
        # Implementation here
        return []
        
    async def _check_aws_encryption(self) -> Dict:
        """Check AWS encryption status."""
        # Implementation here
        return {}
        
    async def _get_aws_compliance_status(self) -> Dict:
        """Get AWS compliance status."""
        # Implementation here
        return {}

    async def __aenter__(self):
        """Async context manager entry."""
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with proper cleanup."""
        # Cleanup AWS resources
        if self.aws_enabled:
            try:
                if hasattr(self, 'aws_session'):
                    # Close any open boto3 sessions
                    self.aws_session.close()
            except Exception as e:
                logger.warning(f"Error cleaning up AWS resources: {str(e)}")
        
        # Cleanup Azure resources
        if self.azure_enabled:
            try:
                if hasattr(self, 'azure_credential'):
                    # Close Azure credential if needed
                    await self.azure_credential.close()
            except Exception as e:
                logger.warning(f"Error cleaning up Azure resources: {str(e)}")
        
        # Cleanup GCP resources
        if self.gcp_enabled:
            try:
                if hasattr(self, 'gcp_security_client'):
                    await self.gcp_security_client.close()
                if hasattr(self, 'gcp_asset_client'):
                    await self.gcp_asset_client.close()
            except Exception as e:
                logger.warning(f"Error cleaning up GCP resources: {str(e)}")
