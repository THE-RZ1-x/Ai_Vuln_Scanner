# AI-Powered Vulnerability Scanner (BETA+FIXED)

A comprehensive security assessment tool that leverages artificial intelligence to detect vulnerabilities, misconfigurations, and security risks across networks, web applications, containers, and cloud infrastructure.

## Features

### 1. AI-Powered Analysis
- **Multiple AI Model Support**: Integrates with OpenAI, Google Gemini, and local ML models
- **Ensemble Learning**: Combines results from multiple AI models for enhanced accuracy
- **False Positive Reduction**: AI-powered verification of findings to minimize false positives
- **Pattern Recognition**: Machine learning for identifying complex attack patterns
- **Context-Aware Analysis**: Understands system context for more accurate risk assessment
- **Resilient Operation**: Gracefully handles missing API keys, continuing with reduced functionality

### 2. Network Security Scanning
- **Port Scanning**: Advanced port scanning with service detection
- **Vulnerability Detection**: CVE matching and exploit identification
- **Service Fingerprinting**: Detailed service and version detection
- **Network Mapping**: Visual representation of network topology
- **Protocol Analysis**: Detection of insecure protocols and configurations

### 3. Web Application Security
- **Dynamic Analysis**: Runtime security testing of web applications
- **Vulnerability Testing**: 
  - SQL Injection detection
  - Cross-Site Scripting (XSS) detection
  - Security header analysis
  - Form submission testing
- **API Security**: Testing of REST and GraphQL endpoints
- **Authentication Testing**: Detection of authentication vulnerabilities
- **Session Management**: Analysis of session handling security

### 4. Container Security
- **Image Scanning**: Deep analysis of container images
- **Vulnerability Detection**: CVE scanning in container components
- **Configuration Analysis**: Detection of container misconfigurations
- **Secret Detection**: Identification of exposed secrets in containers
- **Compliance Checking**: Verification against security standards
- **Base Image Analysis**: Security assessment of base images
- **Layer Analysis**: Security scanning of each container layer

### 5. Cloud Infrastructure Security
- **Multi-Cloud Support**: 
  - Amazon Web Services (AWS)
  - Microsoft Azure
  - Google Cloud Platform (GCP)
- **Resource Assessment**:
  - Infrastructure scanning
  - Service configuration analysis
  - Security group analysis
- **Identity and Access Management**:
  - IAM policy review
  - Permission analysis
  - Role configuration assessment
- **Network Security**:
  - VPC configuration review
  - Network ACL analysis
  - Firewall rule assessment
- **Compliance**:
  - Regulatory compliance checking
  - Security standards verification
  - Best practice validation

### 6. Interactive Reporting
- **HTML Reports**: Beautiful, interactive HTML reports
- **Visualizations**: 
  - Vulnerability severity distribution
  - Attack surface mapping
  - Risk trends over time
- **Remediation Guidance**: AI-generated fix recommendations
- **CVSS Scoring**: Detailed risk scoring for findings
- **Export Options**: PDF, HTML, and JSON formats
- **Custom Templates**: Configurable report templates

## Installation

1. Clone the repository:
```bash
git clone https://github.com/THE-RZ1-x/Ai_Vuln_Scanner.git
cd Ai_Vuln_Scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys and credentials
# Note: The scanner will function with missing API keys, but with reduced capabilities
```

## Usage

### Basic Network Scan
```bash
python vulnscanner.py -t target_ip -s basic
```

### Comprehensive Scan
```bash
python vulnscanner.py -t target_ip -s comprehensive
```

### Container Security Scan
```bash
python vulnscanner.py -t image_name -s container
# or
python vulnscanner.py -t image_name --container
```

### Cloud Infrastructure Scan
```bash
# Scan all configured cloud providers
python vulnscanner.py -t cloud -s cloud

# Scan specific providers
python vulnscanner.py -t cloud -s cloud --cloud-providers aws azure

# Scan single provider
python vulnscanner.py -t aws -s cloud
```

## API Key Configuration

The scanner uses several API keys to enhance its capabilities, but is designed to function even when some or all keys are missing:

- **Vulners API**: Used for vulnerability database lookups
- **Shodan API**: Used for external reconnaissance
- **Gemini API**: Used for AI-powered analysis
- **OpenAI API**: Used for AI-powered analysis

When API keys are missing, the scanner will:
1. Notify you about which keys are missing
2. Continue operation with reduced functionality
3. Use offline analysis methods where possible
4. Provide clear indications of limitations in the scan results

This resilient design ensures the scanner remains useful in environments with limited API access.

## Detailed Usage Guide

### Command Line Options

```bash
python vulnscanner.py [-h] -t TARGET [-s {basic,comprehensive,container,cloud}] [-v] [-o OUTPUT] [--container] [--cloud-providers {aws,azure,gcp} [{aws,azure,gcp} ...]]
```

#### Required Arguments:
- `-t, --target`: Specify the target to scan
  - For network scans: IP address or hostname (e.g., `192.168.1.1` or `example.com`)
  - For container scans: Container image name (e.g., `nginx:latest` or `ubuntu:20.04`)
  - For cloud scans: Use `cloud` or specific provider name (`aws`, `azure`, `gcp`)

#### Optional Arguments:
- `-s, --scan-type`: Choose the type of scan to perform
  - `basic` (default): Quick scan of essential security checks
  - `comprehensive`: In-depth security assessment
  - `container`: Container-specific security scan
  - `cloud`: Cloud infrastructure security scan
- `-v, --verbose`: Enable detailed output for debugging
- `-o, --output`: Specify custom output file name (without extension)
- `--container`: Flag to treat target as a container image
- `--cloud-providers`: Specify which cloud providers to scan (requires `-s cloud`)

### Examples by Feature

#### 1. Network Security Scanning

```bash
# Basic network scan of a single host
python vulnscanner.py -t 192.168.1.1 -s basic

# Comprehensive scan with verbose output
python vulnscanner.py -t example.com -s comprehensive -v

# Save scan results to custom file
python vulnscanner.py -t 192.168.1.1 -s basic -o my_scan_report
```

#### 2. Web Application Security

```bash
# Scan a web application
python vulnscanner.py -t http://example.com -s comprehensive

# Scan with specific focus on web vulnerabilities
python vulnscanner.py -t https://example.com -s comprehensive
```

#### 3. Container Security

```bash
# Scan a specific container image
python vulnscanner.py -t nginx:latest -s container

# Alternative container scan syntax
python vulnscanner.py -t ubuntu:20.04 --container

# Scan container with verbose output
python vulnscanner.py -t mysql:8.0 -s container -v
```

#### 4. Cloud Infrastructure Security

```bash
# Scan all configured cloud providers
python vulnscanner.py -t cloud -s cloud

# Scan specific cloud providers
python vulnscanner.py -t cloud -s cloud --cloud-providers aws azure

# Scan single cloud provider
python vulnscanner.py -t aws -s cloud

# Comprehensive cloud scan with custom report
python vulnscanner.py -t cloud -s cloud --cloud-providers aws azure gcp -o cloud_security_report
```

### Understanding Scan Results

The scanner generates reports in multiple formats:

1. **Interactive HTML Report** (default)
   - Located in `reports/` directory
   - Contains:
     - Executive summary
     - Vulnerability details
     - Risk scores
     - Interactive charts
     - Remediation recommendations

2. **JSON Report**
   - Located in `reports/` directory with `.json` extension
   - Useful for programmatic analysis
   - Contains raw scan data

### Common Use Cases

#### 1. Quick Security Assessment
```bash
# Quick scan of a network host
python vulnscanner.py -t 192.168.1.1 -s basic
```

#### 2. Full Security Audit
```bash
# Comprehensive scan of all assets
python vulnscanner.py -t example.com -s comprehensive
python vulnscanner.py -t cloud -s cloud --cloud-providers aws azure gcp
python vulnscanner.py -t nginx:latest -s container
```

#### 3. Continuous Security Monitoring
```bash
# Create a dated report for tracking
python vulnscanner.py -t example.com -s comprehensive -o "security_audit_$(date +%Y%m%d)"
```

### Best Practices

1. **Start with Basic Scans**
   - Begin with `basic` scan type
   - Review results before running comprehensive scans
   ```bash
   python vulnscanner.py -t example.com -s basic
   ```

2. **Use Verbose Mode for Troubleshooting**
   ```bash
   python vulnscanner.py -t example.com -s comprehensive -v
   ```

3. **Regular Security Assessments**
   - Schedule regular scans
   - Keep track of changes over time
   ```bash
   # Example weekly scan
   python vulnscanner.py -t example.com -s comprehensive -o "weekly_scan_$(date +%Y%m%d)"
   ```

4. **Cloud Security Best Practices**
   - Regularly scan all cloud providers
   - Review IAM configurations frequently
   ```bash
   # Comprehensive cloud security audit
   python vulnscanner.py -t cloud -s cloud --cloud-providers aws azure gcp
   ```

5. **Container Security**
   - Scan images before deployment
   - Regular scanning of production images
   ```bash
   # Scan before deployment
   python vulnscanner.py -t myapp:latest -s container -o "pre_deploy_scan"
   ```

### Troubleshooting

1. **API Connection Issues**
   - Verify API keys in `.env` file
   - Check internet connectivity
   - Ensure VPN is active if required

2. **Scan Failures**
   - Use verbose mode to get detailed error messages
   ```bash
   python vulnscanner.py -t example.com -s comprehensive -v
   ```

3. **Cloud Scanner Issues**
   - Verify cloud credentials
   - Check permission settings
   - Ensure proper role assignments

4. **Performance Issues**
   - Start with basic scans
   - Limit scope of comprehensive scans
   - Use targeted scanning for large infrastructures

### Report Interpretation

The scanner generates comprehensive reports with the following sections:

1. **Executive Summary**
   - Overall risk score
   - Key findings
   - Critical vulnerabilities

2. **Detailed Findings**
   - Vulnerability details
   - CVSS scores
   - Affected components

3. **Remediation**
   - Step-by-step fix instructions
   - Priority levels
   - Best practices

4. **Compliance Status**
   - Regulatory compliance
   - Security standards
   - Best practice adherence

## Configuration

### API Keys
The scanner supports multiple security and AI APIs. Configure them in your `.env` file:
- OpenAI API
- Google Gemini API
- Vulners API
- Shodan API
- NVD API

### Cloud Provider Credentials
Configure cloud provider credentials in your `.env` file:

#### AWS
- Use AWS CLI configuration or set:
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
  - AWS_DEFAULT_REGION

#### Azure
- Required credentials:
  - AZURE_TENANT_ID
  - AZURE_CLIENT_ID
  - AZURE_CLIENT_SECRET
  - AZURE_SUBSCRIPTION_ID

#### GCP
- Use gcloud authentication or set:
  - GOOGLE_APPLICATION_CREDENTIALS
  - GCP_PROJECT_ID

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

For security issues, please refer to our [Security Policy](SECURITY.md) or contact us directly.

## Acknowledgments

- OpenAI for GPT models
- Google for Gemini AI
- Various security tool maintainers
- Open source security community

## Disclaimer

This tool is for educational and security research purposes only. Always obtain proper authorization before scanning any systems or networks.

## Disclaimer of Liability

The AI-Integrated Vulnerability Scanner is provided as-is, without any guarantees or warranties, either express or implied. By using this tool, you acknowledge that you are solely responsible for any consequences that may arise from its usage.

The tool is intended for educational purposes, ethical security assessments, and to help you identify potential vulnerabilities in your network or systems. It is strictly prohibited to use the AI-Integrated Vulnerability Scanner for malicious activities, unauthorized access, or any other illegal activities.

By using the AI-Integrated Vulnerability Scanner, you agree to assume full responsibility for your actions and the results generated by the tool. The developers and contributors of this project shall not be held liable for any damages or losses, whether direct, indirect, incidental, or consequential, arising from the use or misuse of this tool.

It is your responsibility to ensure that you have the proper authorization and consent before scanning any network or system. You must also comply with all applicable laws, regulations, and ethical guidelines related to network scanning and vulnerability assessment.

By using the AI-Integrated Vulnerability Scanner, you acknowledge and accept the terms stated in this Disclaimer of Liability. If you do not agree with these terms, you must not use this tool.

## Author

**RZ1** - [GitHub Profile](https://github.com/THE-RZ1-x)
