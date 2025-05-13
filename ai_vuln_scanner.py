#!/usr/bin/env python3
"""
AI Vulnerability Scanner v2.0
Main launcher script for the AI Vulnerability Scanner

Copyright (c) 2025 RHAZOUANE SALAH-EDDINE
All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Author: RHAZOUANE SALAH-EDDINE
Repository: https://github.com/THE-RZ1-x/Ai_Vuln_Scanner
Profile: https://github.com/THE-RZ1-x
Version: 2.0
"""

import os
import sys
import subprocess
import argparse

def main():
    """Main entry point for the AI Vulnerability Scanner"""
    parser = argparse.ArgumentParser(description="AI Vulnerability Scanner v2.0")
    parser.add_argument("--gui", action="store_true", help="Launch the graphical user interface")
    parser.add_argument("-t", "--target", help="Target to scan (IP, hostname, container, or cloud)")
    parser.add_argument("-s", "--scan-type", choices=["basic", "comprehensive", "container", "cloud"], 
                        default="basic", help="Type of scan to perform")
    args = parser.parse_args()
    
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Add src directory to Python path
    src_dir = os.path.join(script_dir, "src")
    sys.path.insert(0, src_dir)
    
    # Launch GUI if requested
    if args.gui:
        try:
            from src.gui_scanner import main as gui_main
            gui_main()
            return 0
        except ImportError as e:
            print(f"Error loading GUI: {e}")
            print("Make sure PyQt5 is installed: pip install PyQt5")
            return 1
    
    # If target is specified, run scanner
    elif args.target:
        try:
            # Get the Python executable path
            python_path = sys.executable
            if not python_path or 'python' not in python_path.lower():
                # Try to find Python in common locations
                if os.path.exists('d:/python/python.exe'):
                    python_path = 'd:/python/python.exe'
                else:
                    python_path = 'python'  # Hope it's in PATH
            
            # Build the command with correct path to scanner.py in src directory
            scanner_path = os.path.join(src_dir, "scanner.py")
            cmd = [python_path, scanner_path, "-t", args.target, "-s", args.scan_type]
            
            print(f"Starting {args.scan_type} scan on {args.target}...")
            
            # Run the scanner as a subprocess
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Stream the output
            for line in iter(process.stdout.readline, ''):
                print(line.strip())
            
            process.stdout.close()
            return_code = process.wait()
            
            if return_code == 0:
                print("Scan completed successfully!")
            else:
                print(f"Scan failed with return code {return_code}")
            
            return return_code
            
        except Exception as e:
            print(f"Error: {str(e)}")
            return 1
    
    # If no arguments, show help
    else:
        print("AI Vulnerability Scanner v2.0")
        print("Developed by RHAZOUANE SALAH-EDDINE")
        print("\nUsage options:")
        print("  1. GUI Mode: python ai_vuln_scanner.py --gui")
        print("  2. CLI Mode: python ai_vuln_scanner.py -t [target] -s [scan_type]")
        print("\nFor more information, see the README.md file or run with --help")
        return 0

if __name__ == "__main__":
    sys.exit(main())
