#!/usr/bin/env python3
"""
Dependency Checker for AI Vulnerability Scanner
Checks for required and optional dependencies and helps install missing packages.

Author: RHAZOUANE SALAH-EDDINE
Version: 2.0
"""

import sys
import subprocess
import importlib
import os
import platform
from typing import Dict, List, Tuple, Optional

# Define required and optional dependencies
REQUIRED_PACKAGES = {
    "PyQt5": "PyQt5",
    "requests": "requests",
    "dotenv": "python-dotenv",
    "bs4": "beautifulsoup4",
}

OPTIONAL_PACKAGES = {
    "shodan": "shodan",
    "vulners": "vulners",
    "jinja2": "Jinja2",
    "plotly": "plotly",
    "matplotlib": "matplotlib",
    "networkx": "networkx",
    "kaleido": "kaleido",
}

def check_dependencies() -> Tuple[Dict[str, bool], Dict[str, bool]]:
    """
    Check which required and optional dependencies are installed.
    
    Returns:
        Tuple containing two dictionaries:
        - First dictionary: Required packages status (True if installed, False if not)
        - Second dictionary: Optional packages status (True if installed, False if not)
    """
    required_status = {}
    optional_status = {}
    
    # Check required packages
    for module_name, package_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(module_name)
            required_status[package_name] = True
        except ImportError:
            required_status[package_name] = False
    
    # Check optional packages
    for module_name, package_name in OPTIONAL_PACKAGES.items():
        try:
            importlib.import_module(module_name)
            optional_status[package_name] = True
        except ImportError:
            optional_status[package_name] = False
    
    return required_status, optional_status

def get_pip_command() -> Optional[str]:
    """
    Get the appropriate pip command for the current Python environment.
    
    Returns:
        String with the pip command or None if pip cannot be found
    """
    # Try different pip commands
    pip_commands = [
        f"{sys.executable} -m pip",  # Use the current Python's pip
        "pip3",
        "pip",
    ]
    
    for cmd in pip_commands:
        try:
            # Check if the pip command works
            result = subprocess.run(
                f"{cmd} --version", 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                return cmd
        except Exception:
            continue
    
    return None

def install_package(package_name: str) -> bool:
    """
    Install a package using pip.
    
    Args:
        package_name: Name of the package to install
        
    Returns:
        True if installation was successful, False otherwise
    """
    pip_cmd = get_pip_command()
    if not pip_cmd:
        print("Error: Could not find pip. Please install pip and try again.")
        return False
    
    print(f"Installing {package_name}...")
    try:
        result = subprocess.run(
            f"{pip_cmd} install {package_name}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode == 0:
            print(f"Successfully installed {package_name}")
            return True
        else:
            print(f"Failed to install {package_name}: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error installing {package_name}: {str(e)}")
        return False

def generate_requirements_file(output_path: str = "requirements.txt") -> bool:
    """
    Generate a requirements.txt file with all dependencies.
    
    Args:
        output_path: Path to save the requirements.txt file
        
    Returns:
        True if file was created successfully, False otherwise
    """
    try:
        with open(output_path, "w") as f:
            # Write required packages
            f.write("# Required packages\n")
            for package in REQUIRED_PACKAGES.values():
                f.write(f"{package}\n")
            
            # Write optional packages
            f.write("\n# Optional packages\n")
            for package in OPTIONAL_PACKAGES.values():
                f.write(f"{package}\n")
        
        print(f"Requirements file generated at {output_path}")
        return True
    except Exception as e:
        print(f"Error generating requirements file: {str(e)}")
        return False

def check_and_install_dependencies(install_required: bool = True, install_optional: bool = False) -> bool:
    """
    Check dependencies and optionally install missing ones.
    
    Args:
        install_required: Whether to install missing required dependencies
        install_optional: Whether to install missing optional dependencies
        
    Returns:
        True if all required dependencies are installed, False otherwise
    """
    required_status, optional_status = check_dependencies()
    
    # Check if all required packages are installed
    all_required_installed = all(required_status.values())
    
    if not all_required_installed and install_required:
        print("Installing missing required dependencies...")
        for package, installed in required_status.items():
            if not installed:
                install_package(package)
        
        # Check again after installation
        required_status, _ = check_dependencies()
        all_required_installed = all(required_status.values())
    
    # Install optional packages if requested
    if install_optional:
        print("Installing missing optional dependencies...")
        for package, installed in optional_status.items():
            if not installed:
                install_package(package)
    
    return all_required_installed

def print_dependency_status():
    """Print the status of all dependencies."""
    required_status, optional_status = check_dependencies()
    
    print("\n=== AI Vulnerability Scanner Dependency Status ===\n")
    
    print("Required Dependencies:")
    for package, installed in required_status.items():
        status = "✓ Installed" if installed else "✗ Missing"
        print(f"  {package}: {status}")
    
    print("\nOptional Dependencies:")
    for package, installed in optional_status.items():
        status = "✓ Installed" if installed else "- Not installed"
        print(f"  {package}: {status}")
    
    # Check if all required dependencies are installed
    if all(required_status.values()):
        print("\n✓ All required dependencies are installed.")
    else:
        print("\n✗ Some required dependencies are missing.")
        print("Run the following command to install all required dependencies:")
        pip_cmd = get_pip_command() or "pip"
        print(f"  {pip_cmd} install " + " ".join([pkg for pkg, installed in required_status.items() if not installed]))

if __name__ == "__main__":
    # If run directly, check and print dependency status
    print_dependency_status()
    
    # If --install flag is provided, install missing dependencies
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        install_optional = len(sys.argv) > 2 and sys.argv[2] == "--with-optional"
        check_and_install_dependencies(install_required=True, install_optional=install_optional)
        
    # If --generate-requirements flag is provided, generate requirements.txt
    if len(sys.argv) > 1 and sys.argv[1] == "--generate-requirements":
        output_path = "requirements.txt"
        if len(sys.argv) > 2:
            output_path = sys.argv[2]
        generate_requirements_file(output_path)
