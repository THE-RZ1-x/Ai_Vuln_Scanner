# AI-Powered Vulnerability Scanner v2.0

A comprehensive security assessment tool that leverages artificial intelligence to detect vulnerabilities, misconfigurations, and security risks across networks, web applications, containers, and cloud infrastructure.

![AI Vulnerability Scanner GUI](screenshot's/main%20gui%20page.png)

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
- **Multi-language Support**: Reports available in English and other languages
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

### GUI Interface

The easiest way to use the scanner is through the graphical interface:

```bash
python run_gui.py
```

This will launch the GUI interface where you can:
- Configure scan settings
- Run scans against various targets
- Generate exploits for identified vulnerabilities
- View and manage scan reports
- Configure API keys and settings

### Command Line Usage

#### Basic Network Scan
```bash
python ai_vuln_scanner.py -t target_ip -s basic
```

#### Comprehensive Scan
```bash
python ai_vuln_scanner.py -t target_ip -s comprehensive
```

#### Container Security Scan
```bash
python ai_vuln_scanner.py -t image_name -s container
# or
python ai_vuln_scanner.py -t image_name --container
```

#### Cloud Infrastructure Scan
```bash
# Scan all configured cloud providers
python ai_vuln_scanner.py -t cloud -s cloud

# Scan specific providers
python ai_vuln_scanner.py -t cloud -s cloud --cloud-providers aws azure

# Scan single provider
python ai_vuln_scanner.py -t aws -s cloud
```

## Project Structure

The project is organized into the following directories:

- `src/`: Core Python modules
  - `scanner.py`: Main scanning engine
  - `web_scanner.py`: Web application scanning module
  - `cloud_scanner.py`: Cloud infrastructure scanning module
  - `container_scanner.py`: Container scanning module
  - `exploit_generator.py`: Exploit generation module
  - `report_generator.py`: Report generation module
  - `gui_scanner.py`: GUI interface module
- `utils/`: Utility scripts
  - `dependency_checker.py`: Checks and installs required dependencies
  - `test_exploit_gen.py`: Test exploit generation utility
- `docs/`: Documentation
- `scans/`: Output directory for scan results

## Dependency Management

The scanner includes automatic dependency management to ensure all required packages are installed:

1. **Automatic Checking**: The scanner checks for required dependencies on startup
2. **Interactive Installation**: Missing dependencies can be installed with a single click
3. **Graceful Degradation**: The scanner will function with reduced capabilities if optional dependencies are missing
4. **Manual Installation**: Dependencies can be installed manually with:
   ```bash
   python utils/dependency_checker.py --install
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
python ai_vuln_scanner.py [-h] -t TARGET [-s {basic,comprehensive,container,cloud}] [-v] [-o OUTPUT] [--container] [--cloud-providers {aws,azure,gcp} [{aws,azure,gcp} ...]] [--gui]
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
- `--cloud-providers`: Specify which cloud providers to scan (when using cloud scan type)
- `--gui`: Launch the graphical user interface

## What's New in v2.0

### 1. Improved Project Structure
- Organized codebase into logical directories (src, utils, docs)
- Cleaner file organization for better maintainability
- Standardized module interfaces

### 2. Enhanced GUI
- Modern cybersecurity-themed interface
- Improved threading for better responsiveness
- Added About dialog with license and author information

### 3. Dependency Management
- Automatic dependency checking and installation
- Better handling of missing dependencies
- Support for both required and optional packages

### 4. Report Improvements
- Multi-language support (English and others)
- Better visualization with interactive charts
- Improved template selection based on system capabilities

### 5. Launcher Scripts
- Added convenient launcher scripts (run_gui.py, run_gui.bat)
- Unified command-line interface through ai_vuln_scanner.py
- Better error handling and user feedback

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## Author

**RHAZOUANE SALAH-EDDINE**

- GitHub: [https://github.com/THE-RZ1-x](https://github.com/THE-RZ1-x)
- Repository: [https://github.com/THE-RZ1-x/Ai_Vuln_Scanner](https://github.com/THE-RZ1-x/Ai_Vuln_Scanner)
