#!/usr/bin/env python3
"""
Test suite for AI-Powered Vulnerability Scanner
Developed by RZ1 (https://github.com/THE-RZ1-x)
Repository: https://github.com/THE-RZ1-x/Ai_Vuln_Scanner
"""

import pytest
import ipaddress
import sys
import os
from unittest.mock import patch, MagicMock

# Mock the OpenAI client to avoid initialization
sys.modules['openai'] = MagicMock()

# Import after mocking
from vulnscanner import validate_target, extract_open_ports

def test_validate_target_valid_ip():
    """Test valid IP formats including private and public IPs"""
    valid_ips = [
        "192.168.1.1",     # Private network
        "10.0.0.1",        # Private network
        "172.16.0.1",      # Private network
        "8.8.8.8",         # Public IP (Google DNS)
        "1.1.1.1",         # Public IP (Cloudflare)
        "fe80::1",         # IPv6 link-local
        "2001:db8::1"      # IPv6 documentation
    ]
    for ip in valid_ips:
        assert validate_target(ip), f"Should accept valid IP: {ip}"

def test_validate_target_invalid_ip():
    """Test invalid IP formats"""
    invalid_ips = [
        "256.256.256.256",  # Invalid octets
        "192.168.1",        # Incomplete IPv4
        "1.2.3.4.5",        # Too many octets
        "192.168.1.a",      # Non-numeric octet
        "-1.2.3.4",         # Negative number
        "::xyz",            # Invalid IPv6
    ]
    for ip in invalid_ips:
        assert not validate_target(ip), f"Should reject invalid IP: {ip}"

def test_validate_target_valid_hostname():
    """Test valid hostname formats"""
    valid_hostnames = [
        "example.com",
        "sub.example.com",
        "sub-domain.example.com",
        "localhost",
        "host-name",
        "host123",
        "123host.com",
        "xn--80ak6aa92e.com"  # Punycode
    ]
    for hostname in valid_hostnames:
        assert validate_target(hostname), f"Should accept valid hostname: {hostname}"

def test_validate_target_invalid_hostname():
    """Test invalid hostname formats"""
    invalid_hostnames = [
        "",                     # Empty string
        "a" * 256,             # Too long
        "-invalid.com",        # Starts with hyphen
        "invalid-.com",        # Ends with hyphen
        "inv..alid.com",       # Double dot
        "inv*alid.com",        # Invalid character
        "invalid.com-",        # TLD ends with hyphen
        ".invalid.com"         # Starts with dot
    ]
    for hostname in invalid_hostnames:
        assert not validate_target(hostname), f"Should reject invalid hostname: {hostname}"

def test_extract_open_ports():
    """Test port extraction from scan results"""
    mock_analyze = {
        "192.168.1.1": {
            "tcp": {
                "80": {"state": "open", "name": "http"},
                "443": {"state": "open", "name": "https"},
                "22": {"state": "closed", "name": "ssh"},
                "3389": {"state": "filtered", "name": "rdp"}
            },
            "udp": {
                "53": {"state": "open", "name": "dns"},
                "161": {"state": "open", "name": "snmp"},
                "123": {"state": "closed", "name": "ntp"}
            }
        }
    }
    result = extract_open_ports(mock_analyze)
    
    # Check for open ports
    assert "TCP Port 80: http" in result
    assert "TCP Port 443: https" in result
    assert "UDP Port 53: dns" in result
    assert "UDP Port 161: snmp" in result
    
    # Check that closed and filtered ports are not included
    assert "TCP Port 22: ssh" not in result
    assert "TCP Port 3389: rdp" not in result
    assert "UDP Port 123: ntp" not in result
