#!/usr/bin/env python3
"""
AI Vulnerability Scanner GUI
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
import sys
import logging
import subprocess
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QPushButton, QVBoxLayout, QHBoxLayout,
    QWidget, QLineEdit, QLabel, QComboBox, QTextEdit, QFileDialog, QMessageBox,
    QGroupBox, QFormLayout, QSplitter, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtGui import QPixmap, QIcon, QPalette, QColor, QFont, QBrush
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
import importlib

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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ScannerThread(QThread):
    """Thread for running scanner operations without freezing the GUI"""
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    
    def __init__(self, scan_type, target, parent=None):
        super().__init__(parent)
        self.scan_type = scan_type
        self.target = target
        self.process = None
        self.is_running = False
    
    def run(self):
        try:
            self.is_running = True
            # Get the path to the Python executable
            python_path = sys.executable
            if not python_path or 'python' not in python_path.lower():
                # Try to find Python in common locations
                if os.path.exists('d:/python/python.exe'):
                    python_path = 'd:/python/python.exe'
                else:
                    python_path = 'python'  # Hope it's in PATH
            
            # Get the current script directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Build the command with the correct path to scanner.py
            scanner_path = os.path.join(script_dir, "scanner.py")
            cmd = [python_path, scanner_path, '-t', self.target, '-s', self.scan_type]
            
            # Run the scanner process
            self.update_signal.emit(f"Starting {self.scan_type} scan on {self.target}...")
            
            try:
                # Use a shorter timeout for process creation
                self.process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Stream the output with timeout handling
                while self.is_running and self.process.poll() is None:
                    # Read one line at a time with timeout
                    line = self.process.stdout.readline()
                    if line:
                        self.update_signal.emit(line.strip())
                    else:
                        # No more output but process still running
                        break
                
                # Get remaining output
                if self.is_running and self.process.poll() is not None:
                    remaining_output, _ = self.process.communicate()
                    if remaining_output:
                        for line in remaining_output.splitlines():
                            self.update_signal.emit(line.strip())
                    
                    return_code = self.process.returncode
                    if return_code == 0:
                        self.finished_signal.emit(f"Scan completed successfully!")
                    else:
                        self.error_signal.emit(f"Scan failed with return code {return_code}")
                
            except subprocess.TimeoutExpired:
                self.error_signal.emit("Process timed out")
                if self.process:
                    self.process.kill()
                
        except Exception as e:
            self.error_signal.emit(f"Error: {str(e)}")
        finally:
            self.is_running = False
    
    def stop(self):
        """Safely stop the thread and kill the process"""
        self.is_running = False
        if self.process and self.process.poll() is None:
            try:
                self.process.kill()
            except:
                pass


class ExploitThread(QThread):
    """Thread for running exploit generator operations"""
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    
    def __init__(self, vuln_type, description, parent=None):
        super().__init__(parent)
        self.vuln_type = vuln_type
        self.description = description
        self.process = None
        self.is_running = False
    
    def run(self):
        try:
            self.is_running = True
            # Get the path to the Python executable
            python_path = sys.executable
            if not python_path or 'python' not in python_path.lower():
                # Try to find Python in common locations
                if os.path.exists('d:/python/python.exe'):
                    python_path = 'd:/python/python.exe'
                else:
                    python_path = 'python'  # Hope it's in PATH
            
            # Get the current script directory and project root
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(script_dir)
            
            # Build the command with the correct path to test_exploit_gen.py in utils directory
            exploit_gen_path = os.path.join(project_root, "utils", "test_exploit_gen.py")
            cmd = [
                python_path, exploit_gen_path,
                '--type', self.vuln_type,
                '--description', self.description
            ]
            
            # Run the exploit generator process
            self.update_signal.emit(f"Generating exploit for {self.vuln_type}...")
            
            try:
                # Use a shorter timeout for process creation
                self.process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Stream the output with timeout handling
                while self.is_running and self.process.poll() is None:
                    # Read one line at a time
                    line = self.process.stdout.readline()
                    if line:
                        self.update_signal.emit(line.strip())
                    else:
                        # No more output but process still running
                        break
                
                # Get remaining output
                if self.is_running and self.process.poll() is not None:
                    remaining_output, _ = self.process.communicate()
                    if remaining_output:
                        for line in remaining_output.splitlines():
                            self.update_signal.emit(line.strip())
                    
                    return_code = self.process.returncode
                    if return_code == 0:
                        self.finished_signal.emit(f"Exploit generated successfully!")
                    else:
                        self.error_signal.emit(f"Exploit generation failed with return code {return_code}")
                
            except subprocess.TimeoutExpired:
                self.error_signal.emit("Process timed out")
                if self.process:
                    self.process.kill()
                
        except Exception as e:
            self.error_signal.emit(f"Error: {str(e)}")
        finally:
            self.is_running = False
    
    def stop(self):
        """Safely stop the thread and kill the process"""
        self.is_running = False
        if self.process and self.process.poll() is None:
            try:
                self.process.kill()
            except:
                pass


class VulnScannerGUI(QMainWindow):
    """Main GUI class for the AI Vulnerability Scanner"""
    
    def __init__(self):
        super().__init__()
        
        # Check dependencies before initializing UI
        if not self.check_dependencies():
            # If critical dependencies are missing and not installed, exit
            sys.exit(1)
            
        self.scanner_thread = None
        self.exploit_thread = None
        self.init_ui()
    
    def check_dependencies(self):
        """
        Check if required dependencies are installed and offer to install missing ones.
        
        Returns:
            bool: True if all required dependencies are installed or user wants to continue anyway,
                 False if critical dependencies are missing and user cancels.
        """
        # Check for required packages
        missing_required = []
        for module_name, package_name in REQUIRED_PACKAGES.items():
            try:
                importlib.import_module(module_name)
            except ImportError:
                missing_required.append(package_name)
        
        # If there are missing required packages, ask user if they want to install them
        if missing_required:
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Missing Dependencies")
            msg_box.setText(f"The following required dependencies are missing:\n{', '.join(missing_required)}")
            msg_box.setInformativeText("Would you like to install them now?")
            msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            msg_box.setDefaultButton(QMessageBox.Yes)
            
            result = msg_box.exec_()
            
            if result == QMessageBox.Yes:
                # Install missing packages
                success = self.install_packages(missing_required)
                if not success:
                    # If installation failed, ask if user wants to continue anyway
                    continue_msg = QMessageBox()
                    continue_msg.setWindowTitle("Installation Failed")
                    continue_msg.setText("Failed to install some dependencies.")
                    continue_msg.setInformativeText("Do you want to continue anyway? The application may not work correctly.")
                    continue_msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
                    continue_msg.setDefaultButton(QMessageBox.No)
                    
                    if continue_msg.exec_() == QMessageBox.No:
                        return False
            elif result == QMessageBox.Cancel:
                return False
        
        # Check for optional packages
        missing_optional = []
        for module_name, package_name in OPTIONAL_PACKAGES.items():
            try:
                importlib.import_module(module_name)
            except ImportError:
                missing_optional.append(package_name)
        
        # If there are missing optional packages, ask user if they want to install them
        if missing_optional:
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Optional Dependencies")
            msg_box.setText(f"The following optional dependencies are missing:\n{', '.join(missing_optional)}")
            msg_box.setInformativeText("These packages provide additional functionality but are not required. Would you like to install them?")
            msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            msg_box.setDefaultButton(QMessageBox.No)
            
            if msg_box.exec_() == QMessageBox.Yes:
                self.install_packages(missing_optional)
        
        return True
    
    def install_packages(self, packages):
        """
        Install Python packages using pip.
        
        Args:
            packages: List of package names to install
            
        Returns:
            bool: True if all packages were installed successfully, False otherwise
        """
        # Create a progress dialog
        progress_dialog = QMessageBox()
        progress_dialog.setWindowTitle("Installing Dependencies")
        progress_dialog.setText("Installing packages...\nThis may take a few minutes.")
        progress_dialog.setStandardButtons(QMessageBox.NoButton)
        progress_dialog.show()
        QApplication.processEvents()
        
        # Get pip command
        pip_cmd = self.get_pip_command()
        if not pip_cmd:
            progress_dialog.hide()
            QMessageBox.critical(self, "Error", "Could not find pip. Please install pip and try again.")
            return False
        
        # Install each package
        all_success = True
        for package in packages:
            progress_dialog.setText(f"Installing {package}...\nThis may take a few minutes.")
            QApplication.processEvents()
            
            try:
                result = subprocess.run(
                    f"{pip_cmd} install {package}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode != 0:
                    all_success = False
                    print(f"Failed to install {package}: {result.stderr}")
            except Exception as e:
                all_success = False
                print(f"Error installing {package}: {str(e)}")
        
        progress_dialog.hide()
        
        if all_success:
            QMessageBox.information(self, "Success", "All dependencies were installed successfully.")
        else:
            QMessageBox.warning(self, "Warning", "Some dependencies could not be installed. The application may not work correctly.")
        
        return all_success
    
    def get_pip_command(self):
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
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("AI-Powered Vulnerability Scanner")
        self.setGeometry(100, 100, 1000, 700)
        self.setWindowIcon(QIcon("logo.png"))  # You can add your logo file
        
        # Set cybersecurity theme
        self.set_cybersecurity_theme()
        
        # Create central widget and main layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        # Add header with logo (if available)
        header_layout = QHBoxLayout()
        
        # Try to load logo
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
        if os.path.exists(logo_path):
            logo_label = QLabel()
            pixmap = QPixmap(logo_path)
            logo_label.setPixmap(pixmap.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            header_layout.addWidget(logo_label)
        
        # Add title
        title_label = QLabel("AI-Powered Vulnerability Scanner")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        # Add version and author info
        version_label = QLabel("v2.0 | by RHAZOUANE SALAH-EDDINE")
        version_label.setStyleSheet("color: #8a8a8a;")
        header_layout.addWidget(version_label)
        
        # Add about button
        about_button = QPushButton("About")
        about_button.setMaximumWidth(80)
        about_button.clicked.connect(self.show_about_dialog)
        header_layout.addWidget(about_button)
        
        main_layout.addLayout(header_layout)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { 
                border: 1px solid #3498db;
                border-radius: 4px;
                padding: 5px;
            }
            QTabBar::tab {
                background-color: #2c3e50;
                color: white;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        
        # Create tabs
        self.scanner_tab = QWidget()
        self.exploits_tab = QWidget()
        self.reports_tab = QWidget()
        self.settings_tab = QWidget()
        
        # Add tabs to widget
        self.tabs.addTab(self.scanner_tab, "Scanner")
        self.tabs.addTab(self.exploits_tab, "Exploit Generator")
        self.tabs.addTab(self.reports_tab, "Reports")
        self.tabs.addTab(self.settings_tab, "Settings")
        
        # Set up tabs
        self.setup_scanner_tab()
        self.setup_exploits_tab()
        self.setup_reports_tab()
        self.setup_settings_tab()
        
        main_layout.addWidget(self.tabs)
        
        # Add status bar
        self.statusBar().showMessage("Ready")
        self.statusBar().setStyleSheet("background-color: #2c3e50; color: white;")
        
        self.setCentralWidget(central_widget)
    
    def set_cybersecurity_theme(self):
        """Set cybersecurity theme for the application"""
        # Dark blue/green cybersecurity theme
        palette = QPalette()
        
        # Dark background
        palette.setColor(QPalette.Window, QColor(25, 35, 45))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(15, 25, 35))
        palette.setColor(QPalette.AlternateBase, QColor(35, 45, 55))
        
        # Text colors
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.ToolTipBase, QColor(15, 25, 35))
        palette.setColor(QPalette.ToolTipText, Qt.white)
        
        # Button colors
        palette.setColor(QPalette.Button, QColor(45, 55, 65))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.white)
        
        # Highlight colors
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        
        # Link color
        palette.setColor(QPalette.Link, QColor(0, 188, 212))
        
        self.setPalette(palette)
        
        # Set global stylesheet
        self.setStyleSheet("""
            QGroupBox {
                border: 1px solid #3498db;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
                color: #3498db;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #2980b9;
                color: white;
                border-radius: 4px;
                padding: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3498db;
            }
            QPushButton:pressed {
                background-color: #1c5a85;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #34495e;
                color: white;
                border: 1px solid #3498db;
                border-radius: 4px;
                padding: 3px;
            }
            QTableWidget {
                background-color: #2c3e50;
                color: white;
                gridline-color: #3498db;
                border: none;
            }
            QHeaderView::section {
                background-color: #2c3e50;
                color: white;
                padding: 5px;
                border: 1px solid #3498db;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
            }
        """)
    
    def show_about_dialog(self):
        """Show about dialog with license and author information"""
        about_text = """
        <h2>AI-Powered Vulnerability Scanner</h2>
        <p><b>Version:</b> 2.0</p>
        <p><b>Author:</b> RHAZOUANE SALAH-EDDINE</p>
        <p><b>GitHub:</b> <a href="https://github.com/THE-RZ1-x/Ai_Vuln_Scanner">https://github.com/THE-RZ1-x/Ai_Vuln_Scanner</a></p>
        <p><b>Profile:</b> <a href="https://github.com/THE-RZ1-x">https://github.com/THE-RZ1-x</a></p>
        
        <p>This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.</p>
        
        <p>This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
        GNU General Public License for more details.</p>
        
        <p>Copyright 2025 RHAZOUANE SALAH-EDDINE. All rights reserved.</p>
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("About AI Vulnerability Scanner")
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(about_text)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #2c3e50;
                color: white;
            }
            QLabel {
                color: white;
            }
            QPushButton {
                background-color: #2980b9;
                color: white;
                min-width: 80px;
                min-height: 24px;
                border-radius: 4px;
            }
        """)
        msg_box.exec_()
    
    def setup_scanner_tab(self):
        """Set up the scanner tab"""
        layout = QVBoxLayout()
        
        # Create form for scan settings
        form_group = QGroupBox("Scan Settings")
        form_layout = QFormLayout()
        
        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address, hostname, or URL")
        form_layout.addRow("Target:", self.target_input)
        
        # Scan type selection
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["basic", "comprehensive", "web", "container", "cloud"])
        form_layout.addRow("Scan Type:", self.scan_type_combo)
        
        form_group.setLayout(form_layout)
        layout.addWidget(form_group)
        
        # Add scan button
        scan_button = QPushButton("Start Scan")
        scan_button.setMinimumHeight(40)
        scan_button.clicked.connect(self.start_scan)
        layout.addWidget(scan_button)
        
        # Add output console
        console_group = QGroupBox("Scan Output")
        console_layout = QVBoxLayout()
        
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet("background-color: #1e1e1e; color: #dcdcdc;")
        console_layout.addWidget(self.console_output)
        
        console_group.setLayout(console_layout)
        layout.addWidget(console_group)
        
        self.scanner_tab.setLayout(layout)
    
    def setup_exploits_tab(self):
        """Set up the exploits tab"""
        layout = QVBoxLayout()
        
        # Create form for exploit settings
        form_group = QGroupBox("Exploit Generator")
        form_layout = QFormLayout()
        
        # Vulnerability type
        self.vuln_type_input = QLineEdit()
        self.vuln_type_input.setPlaceholderText("e.g., SQL Injection, XSS, RCE")
        form_layout.addRow("Vulnerability Type:", self.vuln_type_input)
        
        # Vulnerability description
        self.vuln_desc_input = QTextEdit()
        self.vuln_desc_input.setPlaceholderText("Describe the vulnerability in detail")
        self.vuln_desc_input.setMaximumHeight(100)
        form_layout.addRow("Description:", self.vuln_desc_input)
        
        form_group.setLayout(form_layout)
        layout.addWidget(form_group)
        
        # Add generate button
        generate_button = QPushButton("Generate Exploit")
        generate_button.setMinimumHeight(40)
        generate_button.clicked.connect(self.generate_exploit)
        layout.addWidget(generate_button)
        
        # Add output console
        console_group = QGroupBox("Generation Output")
        console_layout = QVBoxLayout()
        
        self.exploit_output = QTextEdit()
        self.exploit_output.setReadOnly(True)
        self.exploit_output.setStyleSheet("background-color: #1e1e1e; color: #dcdcdc;")
        console_layout.addWidget(self.exploit_output)
        
        console_group.setLayout(console_layout)
        layout.addWidget(console_group)
        
        self.exploits_tab.setLayout(layout)
    
    def setup_reports_tab(self):
        """Set up the reports tab"""
        layout = QVBoxLayout()
        
        # Create reports list
        reports_group = QGroupBox("Available Reports")
        reports_layout = QVBoxLayout()
        
        # Table of reports
        self.reports_table = QTableWidget(0, 3)
        self.reports_table.setHorizontalHeaderLabels(["Report Name", "Date", "Type"])
        self.reports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.reports_table.setSelectionBehavior(QTableWidget.SelectRows)
        reports_layout.addWidget(self.reports_table)
        
        # Button row
        button_layout = QHBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_reports)
        open_button = QPushButton("Open Report")
        open_button.clicked.connect(self.open_report)
        button_layout.addWidget(refresh_button)
        button_layout.addWidget(open_button)
        
        reports_layout.addLayout(button_layout)
        reports_group.setLayout(reports_layout)
        layout.addWidget(reports_group)
        
        self.reports_tab.setLayout(layout)
        
        # Load reports on startup
        self.refresh_reports()
    
    def setup_settings_tab(self):
        """Set up the settings tab"""
        layout = QVBoxLayout()
        
        # API Keys group
        api_group = QGroupBox("API Keys")
        api_layout = QFormLayout()
        
        # OpenAI API Key
        self.openai_key_input = QLineEdit()
        self.openai_key_input.setPlaceholderText("Enter your OpenAI API key")
        self.openai_key_input.setEchoMode(QLineEdit.Password)
        api_layout.addRow("OpenAI API Key:", self.openai_key_input)
        
        # Gemini API Key
        self.gemini_key_input = QLineEdit()
        self.gemini_key_input.setPlaceholderText("Enter your Google Gemini API key")
        self.gemini_key_input.setEchoMode(QLineEdit.Password)
        api_layout.addRow("Gemini API Key:", self.gemini_key_input)
        
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)
        
        # Output directory group
        output_group = QGroupBox("Output Settings")
        output_layout = QFormLayout()
        
        # Output directory
        output_dir_layout = QHBoxLayout()
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setText(os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans"))
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_output_dir)
        output_dir_layout.addWidget(self.output_dir_input)
        output_dir_layout.addWidget(browse_button)
        output_layout.addRow("Output Directory:", output_dir_layout)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Save button
        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.save_settings)
        layout.addWidget(save_button)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        self.settings_tab.setLayout(layout)
        
        # Load settings
        self.load_settings()
    
    def start_scan(self):
        """Start a vulnerability scan"""
        target = self.target_input.text().strip()
        scan_type = self.scan_type_combo.currentText().lower()
        
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP, hostname, or URL")
            return
        
        # Clear console
        self.console_output.clear()
        
        # Create and start scanner thread
        self.scanner_thread = ScannerThread(scan_type, target)
        self.scanner_thread.update_signal.connect(self.update_console)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.error_signal.connect(self.scan_error)
        self.scanner_thread.start()
        
        # Update status
        self.statusBar().showMessage(f"Scanning {target}...")
    
    def update_console(self, text):
        """Update the console output"""
        self.console_output.append(text)
        # Auto-scroll to bottom
        cursor = self.console_output.textCursor()
        cursor.movePosition(cursor.End)
        self.console_output.setTextCursor(cursor)
    
    def scan_finished(self, message):
        """Handle scan completion"""
        self.update_console(message)
        self.statusBar().showMessage("Scan completed")
        self.refresh_reports()
    
    def scan_error(self, message):
        """Handle scan error"""
        self.update_console(message)
        self.statusBar().showMessage("Scan failed")
    
    def generate_exploit(self):
        """Generate an exploit for a vulnerability"""
        vuln_type = self.vuln_type_input.text().strip()
        description = self.vuln_desc_input.toPlainText().strip()
        
        if not vuln_type or not description:
            QMessageBox.warning(self, "Input Error", "Please enter both vulnerability type and description")
            return
        
        # Clear console
        self.exploit_output.clear()
        
        # Create and start exploit thread
        self.exploit_thread = ExploitThread(vuln_type, description)
        self.exploit_thread.update_signal.connect(self.update_exploit_console)
        self.exploit_thread.finished_signal.connect(self.exploit_finished)
        self.exploit_thread.error_signal.connect(self.exploit_error)
        self.exploit_thread.start()
        
        # Update status
        self.statusBar().showMessage("Generating exploit...")
    
    def update_exploit_console(self, text):
        """Update the exploit console output"""
        self.exploit_output.append(text)
        # Auto-scroll to bottom
        cursor = self.exploit_output.textCursor()
        cursor.movePosition(cursor.End)
        self.exploit_output.setTextCursor(cursor)
    
    def exploit_finished(self, message):
        """Handle exploit generation completion"""
        self.update_exploit_console(message)
        self.statusBar().showMessage("Exploit generation completed")
    
    def exploit_error(self, message):
        """Handle exploit generation error"""
        self.update_exploit_console(message)
        self.statusBar().showMessage("Exploit generation failed")
    
    def refresh_reports(self):
        """Refresh the list of available reports"""
        # Clear the table
        self.reports_table.setRowCount(0)
        
        # Get the current script directory and project root
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        
        # Get reports directory
        reports_dir = os.path.join(project_root, "scans")
        if not os.path.exists(reports_dir):
            return
        
        # Find HTML reports
        row = 0
        for file in os.listdir(reports_dir):
            if file.endswith(".html"):
                file_path = os.path.join(reports_dir, file)
                file_stat = os.stat(file_path)
                file_date = file_stat.st_mtime
                
                # Add to table
                self.reports_table.insertRow(row)
                self.reports_table.setItem(row, 0, QTableWidgetItem(file))
                self.reports_table.setItem(row, 1, QTableWidgetItem(
                    str(datetime.fromtimestamp(file_date).strftime("%Y-%m-%d %H:%M:%S"))
                ))
                self.reports_table.setItem(row, 2, QTableWidgetItem("HTML Report"))
                
                # Store the full path in the first column's data
                self.reports_table.item(row, 0).setData(Qt.UserRole, file_path)
                
                row += 1
    
    def open_report(self):
        """Open the selected report"""
        selected_items = self.reports_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a report to open")
            return
        
        # Get the file path from the first column
        file_path = self.reports_table.item(selected_items[0].row(), 0).data(Qt.UserRole)
        
        # Open the file with the default application
        try:
            if os.name == 'nt':  # Windows
                os.startfile(file_path)
            elif os.name == 'posix':  # macOS and Linux
                subprocess.call(('xdg-open', file_path))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not open report: {str(e)}")
    
    def browse_output_dir(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", 
            self.output_dir_input.text()
        )
        if directory:
            self.output_dir_input.setText(directory)
    
    def save_settings(self):
        """Save settings to file"""
        try:
            settings = {
                "openai_api_key": self.openai_key_input.text(),
                "gemini_api_key": self.gemini_key_input.text(),
                "output_dir": self.output_dir_input.text()
            }
            
            # Set environment variables
            if settings["openai_api_key"]:
                os.environ["OPENAI_API_KEY"] = settings["openai_api_key"]
            if settings["gemini_api_key"]:
                os.environ["GEMINI_API_KEY"] = settings["gemini_api_key"]
            
            # Save to file
            settings_dir = os.path.dirname(os.path.abspath(__file__))
            settings_file = os.path.join(settings_dir, "scanner_settings.conf")
            
            with open(settings_file, "w") as f:
                for key, value in settings.items():
                    if key.endswith("_key") and value:  # Mask API keys in file
                        f.write(f"{key}=***MASKED***\n")
                    else:
                        f.write(f"{key}={value}\n")
            
            QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully")
            self.statusBar().showMessage("Settings saved")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not save settings: {str(e)}")
    
    def load_settings(self):
        """Load settings from file"""
        try:
            settings_dir = os.path.dirname(os.path.abspath(__file__))
            settings_file = os.path.join(settings_dir, "scanner_settings.conf")
            
            if not os.path.exists(settings_file):
                return
            
            with open(settings_file, "r") as f:
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        if key == "openai_api_key" and value != "***MASKED***":
                            self.openai_key_input.setText(value)
                            os.environ["OPENAI_API_KEY"] = value
                        elif key == "gemini_api_key" and value != "***MASKED***":
                            self.gemini_key_input.setText(value)
                            os.environ["GEMINI_API_KEY"] = value
                        elif key == "output_dir":
                            self.output_dir_input.setText(value)
        except Exception as e:
            logger.error(f"Could not load settings: {str(e)}")


def main():
    """Main entry point for the GUI application"""
    app = QApplication(sys.argv)
    window = VulnScannerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
