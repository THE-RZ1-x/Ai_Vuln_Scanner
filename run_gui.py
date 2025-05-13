#!/usr/bin/env python3
"""
GUI Launcher for AI Vulnerability Scanner v2.0
This script launches the GUI interface for the scanner.

Author: RHAZOUANE SALAH-EDDINE
Version: 2.0
"""

import os
import sys
import subprocess
import importlib.util

def check_dependency_checker():
    """Check if dependency_checker.py exists and import it"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = script_dir
    dependency_checker_path = os.path.join(project_root, "utils", "dependency_checker.py")
    
    if os.path.exists(dependency_checker_path):
        # Import the dependency checker module
        spec = importlib.util.spec_from_file_location("dependency_checker", dependency_checker_path)
        dependency_checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dependency_checker)
        return dependency_checker
    return None

def install_dependencies_dialog():
    """Show a dialog to install dependencies"""
    try:
        # Try to import PyQt5 for a nice dialog
        from PyQt5.QtWidgets import QApplication, QMessageBox, QPushButton
        
        app = QApplication(sys.argv)
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Missing Dependencies")
        msg_box.setText("Some required dependencies are missing. Would you like to install them now?")
        msg_box.setInformativeText("The scanner needs certain Python packages to function properly.")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.Yes)
        
        # Add button to also install optional dependencies
        optional_button = QPushButton("Install All (Including Optional)")
        msg_box.addButton(optional_button, QMessageBox.ActionRole)
        
        result = msg_box.exec_()
        
        if result == QMessageBox.Yes:
            return True, False
        elif msg_box.clickedButton() == optional_button:
            return True, True
        else:
            return False, False
            
    except ImportError:
        # Fallback to console if PyQt5 is not available
        print("Some required dependencies are missing.")
        response = input("Would you like to install them now? (y/n/a - where 'a' installs optional dependencies too): ")
        if response.lower() == 'y':
            return True, False
        elif response.lower() == 'a':
            return True, True
        else:
            return False, False

def main():
    """Launch the AI Vulnerability Scanner GUI"""
    print("Starting AI Vulnerability Scanner GUI v2.0...")
    
    # Check for dependency checker
    dependency_checker = check_dependency_checker()
    
    # If dependency checker exists, use it to check dependencies
    if dependency_checker:
        required_status, optional_status = dependency_checker.check_dependencies()
        
        # If not all required dependencies are installed
        if not all(required_status.values()):
            print("Missing required dependencies detected.")
            dependency_checker.print_dependency_status()
            
            # Ask user if they want to install dependencies
            install_required, install_optional = install_dependencies_dialog()
            
            if install_required:
                success = dependency_checker.check_and_install_dependencies(
                    install_required=True,
                    install_optional=install_optional
                )
                
                if not success:
                    print("Failed to install all required dependencies. Please install them manually.")
                    print("Run: pip install " + " ".join(REQUIRED_PACKAGES.values()))
                    return 1
            else:
                print("Continuing without installing dependencies. The application may not work correctly.")
    
    # Get the path to the Python executable
    python_path = sys.executable
    if not python_path or 'python' not in python_path.lower():
        # Try to find Python in common locations
        if os.path.exists('d:/python/python.exe'):
            python_path = 'd:/python/python.exe'
        else:
            python_path = 'python'  # Hope it's in PATH
    
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Path to the main launcher script
    launcher_script = os.path.join(script_dir, "ai_vuln_scanner.py")
    
    # Build the command
    cmd = [python_path, launcher_script, "--gui"]
    
    # Launch the GUI
    try:
        subprocess.Popen(cmd)
        return 0
    except Exception as e:
        print(f"Error launching GUI: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
