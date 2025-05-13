#!/usr/bin/env python3
"""
Project Organization Script for AI Vulnerability Scanner v2.0
This script organizes the project structure, removes unnecessary files,
and updates version numbers.

Author: RHAZOUANE SALAH-EDDINE
Version: 2.0
"""

import os
import shutil
import re
import sys

# Define directories
SRC_DIR = "src"
UTILS_DIR = "utils"
DOCS_DIR = "docs"

# Files to keep in their respective directories
KEEP_FILES = {
    SRC_DIR: [
        "scanner.py",
        "web_scanner.py", 
        "cloud_scanner.py", 
        "container_scanner.py", 
        "exploit_generator.py", 
        "report_generator.py",
        "gui_scanner.py"
    ],
    UTILS_DIR: [
        "test_exploit_gen.py",
        "run_gui.bat"
    ],
    DOCS_DIR: [
        "README.md",
        "LICENSE",
        "requirements.txt"
    ],
    ".": [  # Root directory
        "organize_v2.py",  # This script
        "cleanup_plan.txt"
    ]
}

# Files to delete (relative to project root)
DELETE_FILES = [
    "report_generator.bak.py",
    "report_generator_backup.py",
    "report_generator_broken.py",
    "test.py",
    "test_mcp_browser.py",
    "test_openai.py",
    "check_env.py",
    "fix_indent.py",
    "AI_Vulnerability_Scanner_Project_Report.docx",
    "AI_Vulnerability_Scanner_Project_Report.html",
    "project_report.md",
    "setup_env.ps1",
    "templates/report.html",
    "templates/report_template.html",
    "templates/minimal_report.html",
    "templates/advanced_report.bak.html"
]

def ensure_directory(directory):
    """Ensure directory exists, create if it doesn't"""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")

def move_file(src, dest):
    """Move a file from src to dest"""
    if os.path.exists(src):
        # Create destination directory if it doesn't exist
        dest_dir = os.path.dirname(dest)
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
        
        # If destination file already exists, remove it
        if os.path.exists(dest) and os.path.isfile(dest):
            os.remove(dest)
            
        shutil.copy2(src, dest)
        print(f"Moved: {src} -> {dest}")
        return True
    else:
        print(f"Warning: Source file not found: {src}")
        return False

def delete_file(file_path):
    """Delete a file if it exists"""
    if os.path.exists(file_path):
        if os.path.isfile(file_path):
            os.remove(file_path)
            print(f"Deleted: {file_path}")
        else:
            print(f"Warning: Not a file: {file_path}")
    else:
        print(f"Warning: File not found: {file_path}")

def update_version_in_file(file_path, new_version="2.0"):
    """Update version number in file"""
    if not os.path.exists(file_path):
        print(f"Warning: File not found for version update: {file_path}")
        return
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace version patterns
    patterns = [
        r'Version: 1\.0',
        r'version = "1\.0"',
        r"version = '1\.0'",
        r'VERSION = "1\.0"',
        r"VERSION = '1\.0'"
    ]
    
    replacements = [
        f'Version: {new_version}',
        f'version = "{new_version}"',
        f"version = '{new_version}'",
        f'VERSION = "{new_version}"',
        f"VERSION = '{new_version}'"
    ]
    
    updated_content = content
    for pattern, replacement in zip(patterns, replacements):
        updated_content = re.sub(pattern, replacement, updated_content)
    
    if content != updated_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        print(f"Updated version in: {file_path}")

def main():
    """Main function to organize the project"""
    # Get the project root directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    
    print(f"Organizing AI Vulnerability Scanner v2.0 in: {project_root}")
    
    # Create necessary directories
    for directory in [SRC_DIR, UTILS_DIR, DOCS_DIR]:
        ensure_directory(directory)
    
    # Move files to their respective directories
    for directory, files in KEEP_FILES.items():
        for file in files:
            if directory == ".":  # Root directory
                continue  # Skip files that should stay in root
            
            src_path = os.path.join(project_root, file)
            dest_path = os.path.join(project_root, directory, os.path.basename(file))
            move_file(src_path, dest_path)
    
    # Delete unnecessary files
    for file in DELETE_FILES:
        delete_file(os.path.join(project_root, file))
    
    # Update version numbers in key files
    python_files = []
    for directory, files in KEEP_FILES.items():
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(project_root, directory, file)
                if os.path.exists(file_path):
                    python_files.append(file_path)
                else:
                    # Try in root directory
                    file_path = os.path.join(project_root, file)
                    if os.path.exists(file_path):
                        python_files.append(file_path)
    
    for file_path in python_files:
        update_version_in_file(file_path)
    
    print("\nProject organization complete!")
    print("AI Vulnerability Scanner v2.0 is ready.")

if __name__ == "__main__":
    main()
