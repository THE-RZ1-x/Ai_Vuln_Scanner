# AI-Powered Vulnerability Scanner (BETA+FIXED)

A comprehensive security assessment tool that leverages artificial intelligence to detect vulnerabilities, misconfigurations, and security risks across networks, web applications, containers, and cloud infrastructure.

## Features

### 1. AI-Powered Analysis
- **Multiple AI Model Support**: Integrates with OpenAI, Google Gemini, and local ML models
- **Ensemble Learning**: Combines results from multiple AI models for enhanced accuracy
- **False Positive Reduction**: AI-powered verification of findings to minimize false positives
- **Pattern Recognition**: Machine learning for identifying complex attack patterns
- **Context-Aware Analysis**: Understands system context for more accurate risk assessment
- **Resilient Operation**: Gracefully handles missing API keys or quota limitations, continuing with reduced functionality
- **AI Service Failover**: Automatically switches between AI providers if one becomes unavailable

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
- **Enhanced HTML Reports**: Beautiful, interactive HTML reports with improved visualization
- **Multi-language Support**: Reports in multiple languages including Arabic
- **AI Analysis Section**: Dedicated sections for AI-generated security insights
- **Visualizations**: 
  - Vulnerability severity distribution
  - Attack surface mapping
  - Risk trends over time
- **Remediation Guidance**: AI-generated fix recommendations
- **CVSS Scoring**: Detailed risk scoring for findings
- **Export Options**: PDF, HTML, and JSON formats
- **Custom Templates**: Configurable report templates with failover options
- **Adaptive Layout**: Reports adapt to available visualization libraries

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
python scanner.py -t target_ip -s basic
```

### Comprehensive Scan
```bash
python scanner.py -t target_ip -s comprehensive
```

### Container Security Scan
```bash
python scanner.py -t image_name -s container
# or
python scanner.py -t image_name --container
```

### Cloud Infrastructure Scan
```bash
# Scan all configured cloud providers
python scanner.py -t cloud -s cloud

# Scan specific providers
python scanner.py -t cloud -s cloud --cloud-providers aws azure

# Scan single provider
python scanner.py -t aws -s cloud
```

## API Key Configuration

The scanner uses several API keys to enhance its capabilities, but is designed to function even when some or all keys are missing:

- **Vulners API**: Used for vulnerability database lookups
- **Shodan API**: Used for external reconnaissance
- **Gemini API**: Used for AI-powered analysis
- **OpenAI API**: Used for AI-powered analysis

When API keys are missing or quota is exceeded, the scanner will:
1. Notify you about which keys are missing or limited
2. Continue operation with reduced functionality
3. Use offline analysis methods where possible
4. Switch to alternative AI providers when available
5. Provide clear indications of limitations in the scan results

This resilient design ensures the scanner remains useful in environments with limited API access.

## Troubleshooting

### OpenAI API Issues

If you encounter issues with OpenAI analysis not appearing in reports:

1. **Check API Key**: Verify your OpenAI API key in the `.env` file
2. **Quota Limitations**: OpenAI has usage quotas - check if you've exceeded your limit
3. **Error Messages**: Look for error messages in the console output containing:
   - `OpenAI API quota exceeded`
   - `insufficient_quota`
   - `RateLimitError`
4. **Fallback to Gemini**: The scanner will automatically use Gemini AI if OpenAI is unavailable

### Visualization Issues

If charts or visualizations are not appearing in reports:

1. **Check Dependencies**: Ensure Plotly, Matplotlib and NetworkX are installed
2. **Console Warnings**: Look for warnings about missing visualization libraries
3. **Fallback Modes**: The scanner has multiple fallback options for visualizations

### Report Display Problems

If reports display incorrectly:

1. **Web Connectivity**: Some report templates require internet access for CDN resources
2. **Template Levels**: The scanner selects the best available template based on your system capabilities
3. **Default Browser**: Try opening the report in different browsers
4. **Check CSS**: Verify that style elements are loading correctly

## Detailed Usage Guide

### Command Line Options

```bash
python scanner.py [-h] -t TARGET [-s {basic,comprehensive,container,cloud}] [-v] [-o OUTPUT] [--container] [--cloud-providers {aws,azure,gcp} [{aws,azure,gcp} ...]]
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
python scanner.py -t 192.168.1.1 -s basic

# Comprehensive scan with verbose output
python scanner.py -t example.com -s comprehensive -v

# Save scan results to custom file
python scanner.py -t 192.168.1.1 -s basic -o my_scan_report
```

#### 2. Web Application Security

```bash
# Scan a web application
python scanner.py -t http://example.com -s comprehensive

# Scan with specific focus on web vulnerabilities
python scanner.py -t https://example.com -s comprehensive
```

#### 3. Container Security

```bash
# Scan a specific container image
python scanner.py -t nginx:latest -s container

# Alternative container scan syntax
python scanner.py -t ubuntu:20.04 --container

# Scan container with verbose output
python scanner.py -t mysql:8.0 -s container -v
```

#### 4. Cloud Infrastructure Security

```bash
# Scan all configured cloud providers
python scanner.py -t cloud -s cloud

# Scan specific cloud providers
python scanner.py -t cloud -s cloud --cloud-providers aws azure

# Scan single cloud provider
python scanner.py -t aws -s cloud

# Comprehensive cloud scan with custom report
python scanner.py -t cloud -s cloud --cloud-providers aws azure gcp -o cloud_security_report
```

### Understanding Scan Results

The scanner generates reports in multiple formats:

1. **Interactive HTML Report** (default)
   - Located in `scans/` directory
   - Contains:
     - Executive summary
     - Vulnerability details
     - Risk scores
     - Interactive charts
     - AI-powered analysis
     - Remediation recommendations

2. **JSON Report**
   - Located in `scans/` directory with `.json` extension
   - Useful for programmatic analysis
   - Contains raw scan data

## Recent Improvements

Recent updates include:

1. **Enhanced AI Analysis Display**:
   - Fixed issues with OpenAI analysis display in reports
   - Improved formatting of AI analysis text 
   - Added proper styling for analysis sections

2. **Report Resilience**:
   - Better handling of missing dependencies
   - Improved fallback mechanisms for visualization
   - Enhanced template selection based on system capabilities

3. **Error Handling**:
   - Better messaging for API quota limitations
   - Clear indications when AI services are unavailable
   - Graceful degradation when services fail

4. **Visualization Enhancements**:
   - Improved chart rendering
   - Better mobile responsiveness
   - Enhanced dashboard elements

## License

Copyright © 2025 RHAZOUANE SALAH-EDDINE
