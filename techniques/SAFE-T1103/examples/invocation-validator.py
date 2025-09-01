#!/usr/bin/env python3
"""
MCP Tool Invocation Validator
Scans MCP messages for spoofed or unauthorized tool calls

Usage: python invocation-validator.py [message.json]
"""

import json
import sys
import re
from typing import Dict, List, Tuple, Set
from datetime import datetime
import hashlib

class InvocationValidator:
    def __init__(self, registered_tools: List[str] = None):
        """Initialize validator with registered tools"""
        # Default registered tools (should be loaded from config in production)
        self.registered_tools = registered_tools or [
            "file_read",
            "file_write",
            "web_search",
            "calculator",
            "weather_api",
            "database_query"
        ]
        
        self.alerts = []
        self.statistics = {
            'total_calls': 0,
            'valid_calls': 0,
            'spoofed_calls': 0,
            'suspicious_patterns': 0,
            'schema_violations': 0
        }
        
        # Known dangerous patterns
        self.dangerous_patterns = [
            r'exec',
            r'system',
            r'shell',
            r'cmd',
            r'eval',
            r'compile',
            r'__import__',
            r'subprocess',
            r'os\.',
            r'popen'
        ]
        
        # Expected schemas for registered tools
        self.tool_schemas = {
            "file_read": {
                "required": ["path"],
                "optional": ["encoding"],
                "forbidden": ["command", "exec", "__proto__"]
            },
            "web_search": {
                "required": ["query"],
                "optional": ["max_results", "language"],
                "forbidden": ["exec", "system"]
            },
            "calculator": {
                "required": ["expression"],
                "optional": ["precision"],
                "forbidden": ["import", "exec", "eval"]
            }
        }
    
    def validate_tool_name(self, tool_name: str) -> Dict:
        """Check if tool name is registered and safe"""
        result = {
            'valid': False,
            'registered': False,
            'suspicious': False,
            'risk_level': 'low',
            'reasons': []
        }
        
        # Check registration
        if tool_name in self.registered_tools:
            result['registered'] = True
            result['valid'] = True
        else:
            result['reasons'].append(f"Unregistered tool: {tool_name}")
            result['risk_level'] = 'high'
        
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, tool_name, re.IGNORECASE):
                result['suspicious'] = True
                result['risk_level'] = 'high'
                result['reasons'].append(f"Dangerous pattern in name: {pattern}")
        
        # Check for obvious spoofing attempts
        spoofing_indicators = ['fake_', 'spoof_', 'malicious_', 'backdoor_', 'unauthorized_']
        for indicator in spoofing_indicators:
            if indicator in tool_name.lower():
                result['suspicious'] = True
                result['risk_level'] = 'critical'
                result['reasons'].append(f"Spoofing indicator: {indicator}")
        
        return result
    
    def validate_parameters(self, tool_name: str, params: Dict) -> Dict:
        """Validate parameters against expected schema"""
        result = {
            'valid': True,
            'schema_violations': [],
            'dangerous_params': [],
            'risk_level': 'low'
        }
        
        # Get schema if available
        schema = self.tool_schemas.get(tool_name, {})
        
        if schema:
            # Check required parameters
            required = schema.get('required', [])
            for req_param in required:
                if req_param not in params:
                    result['valid'] = False
                    result['schema_violations'].append(f"Missing required parameter: {req_param}")
            
            # Check forbidden parameters
            forbidden = schema.get('forbidden', [])
            for param_name in params:
                if param_name in forbidden:
                    result['valid'] = False
                    result['risk_level'] = 'high'
                    result['schema_violations'].append(f"Forbidden parameter: {param_name}")
        
        # Check all parameters for dangerous content
        for param_name, param_value in params.items():
            # Check parameter names
            if any(pattern in param_name.lower() for pattern in ['exec', '__proto__', 'constructor']):
                result['dangerous_params'].append(f"Suspicious parameter name: {param_name}")
                result['risk_level'] = 'high'
            
            # Check parameter values
            if isinstance(param_value, str):
                # Command injection patterns
                if any(char in param_value for char in [';', '|', '&', '`', '$(']):
                    result['dangerous_params'].append(f"Command injection in {param_name}: {param_value[:50]}")
                    result['risk_level'] = 'critical'
                
                # Path traversal
                if '../' in param_value or '..\\' in param_value:
                    result['dangerous_params'].append(f"Path traversal in {param_name}")
                    result['risk_level'] = 'high'
        
        return result
    
    def check_invocation_structure(self, message: Dict) -> Dict:
        """Validate overall message structure"""
        result = {
            'valid': True,
            'structural_issues': [],
            'risk_level': 'low'
        }
        
        # Check for required fields in different message formats
        if "jsonrpc" in message:
            # JSON-RPC format
            if message.get("jsonrpc") != "2.0":
                result['structural_issues'].append("Invalid JSON-RPC version")
            
            if "method" not in message:
                result['structural_issues'].append("Missing method field")
                result['valid'] = False
            
            if "params" not in message:
                result['structural_issues'].append("Missing params field")
                result['valid'] = False
        
        elif "tool_call" in message:
            # Alternative format
            tool_call = message.get("tool_call", {})
            if "name" not in tool_call:
                result['structural_issues'].append("Missing tool name")
                result['valid'] = False
            
            if "arguments" not in tool_call and "parameters" not in tool_call:
                result['structural_issues'].append("Missing arguments/parameters")
                result['valid'] = False
        
        else:
            result['structural_issues'].append("Unrecognized message format")
            result['valid'] = False
            result['risk_level'] = 'medium'
        
        return result
    
    def detect_chained_spoofing(self, messages: List[Dict]) -> List[Dict]:
        """Detect patterns indicating chained spoofing attacks"""
        chain_alerts = []
        
        # Look for suspicious sequences
        tool_sequence = []
        for msg in messages:
            if "tool_call" in msg:
                tool_name = msg["tool_call"].get("name", "")
                tool_sequence.append(tool_name)
        
        # Known malicious sequences
        malicious_sequences = [
            ["env_dump", "credential_extractor", "data_exfiltrator"],
            ["system_info", "privilege_check", "admin_access"],
            ["file_list", "file_read", "network_send"]
        ]
        
        # Check for matches
        seq_str = " ".join(tool_sequence)
        for mal_seq in malicious_sequences:
            mal_str = " ".join(mal_seq)
            if mal_str in seq_str:
                chain_alerts.append({
                    'type': 'chained_spoofing',
                    'sequence': mal_seq,
                    'risk_level': 'critical',
                    'description': 'Detected known malicious tool sequence'
                })
        
        return chain_alerts
    
    def analyze_message(self, message: Dict) -> None:
        """Analyze a single message for spoofing"""
        self.statistics['total_calls'] += 1
        
        # Check structure
        structure_check = self.check_invocation_structure(message)
        if not structure_check['valid']:
            self.alerts.append({
                'type': 'structural_violation',
                'issues': structure_check['structural_issues'],
                'risk_level': structure_check['risk_level'],
                'message': message
            })
            return
        
        # Extract tool call details
        if "jsonrpc" in message:
            tool_name = message.get("params", {}).get("name", "")
            parameters = message.get("params", {}).get("arguments", {})
        else:
            tool_call = message.get("tool_call", {})
            tool_name = tool_call.get("name", "")
            parameters = tool_call.get("arguments", tool_call.get("parameters", {}))
        
        # Validate tool name
        name_check = self.validate_tool_name(tool_name)
        if not name_check['valid'] or name_check['suspicious']:
            self.alerts.append({
                'type': 'spoofed_invocation',
                'tool_name': tool_name,
                'reasons': name_check['reasons'],
                'risk_level': name_check['risk_level'],
                'message': message
            })
            self.statistics['spoofed_calls'] += 1
        else:
            self.statistics['valid_calls'] += 1
        
        # Validate parameters
        param_check = self.validate_parameters(tool_name, parameters)
        if not param_check['valid'] or param_check['dangerous_params']:
            self.alerts.append({
                'type': 'parameter_violation',
                'tool_name': tool_name,
                'violations': param_check['schema_violations'],
                'dangerous': param_check['dangerous_params'],
                'risk_level': param_check['risk_level'],
                'message': message
            })
            if param_check['schema_violations']:
                self.statistics['schema_violations'] += 1
            if param_check['dangerous_params']:
                self.statistics['suspicious_patterns'] += 1
    
    def generate_report(self) -> None:
        """Generate validation report"""
        print("\n" + "=" * 80)
        print("MCP Tool Invocation Validation Report")
        print("=" * 80)
        
        # Statistics
        print(f"\nStatistics:")
        print(f"  Total tool calls analyzed: {self.statistics['total_calls']}")
        print(f"  Valid calls: {self.statistics['valid_calls']}")
        print(f"  Spoofed calls detected: {self.statistics['spoofed_calls']}")
        print(f"  Suspicious patterns: {self.statistics['suspicious_patterns']}")
        print(f"  Schema violations: {self.statistics['schema_violations']}")
        
        if not self.alerts:
            print("\n✓ No spoofed invocations detected!")
            return
        
        # Group alerts by risk level
        critical_alerts = [a for a in self.alerts if a.get('risk_level') == 'critical']
        high_alerts = [a for a in self.alerts if a.get('risk_level') == 'high']
        medium_alerts = [a for a in self.alerts if a.get('risk_level') == 'medium']
        
        # Print alerts
        if critical_alerts:
            print("\n🔴 CRITICAL ALERTS:")
            for alert in critical_alerts[:5]:
                self.print_alert(alert)
        
        if high_alerts:
            print("\n🔴 HIGH RISK ALERTS:")
            for alert in high_alerts[:5]:
                self.print_alert(alert)
        
        if medium_alerts:
            print(f"\n🟡 MEDIUM RISK: {len(medium_alerts)} issues detected")
        
        # Recommendations
        print("\n📋 Recommendations:")
        print("  1. Implement strict tool allowlisting")
        print("  2. Enable parameter schema validation")
        print("  3. Use cryptographic signatures for tool calls")
        print("  4. Monitor unregistered tool attempts")
        print("  5. Review and update tool permissions regularly")
    
    def print_alert(self, alert: Dict) -> None:
        """Print a single alert"""
        print(f"\n  Type: {alert['type']}")
        
        if 'tool_name' in alert:
            print(f"  Tool: {alert['tool_name']}")
        
        if 'reasons' in alert:
            print(f"  Reasons: {', '.join(alert['reasons'])}")
        
        if 'violations' in alert:
            print(f"  Schema violations: {', '.join(alert['violations'])}")
        
        if 'dangerous' in alert:
            print(f"  Dangerous patterns: {', '.join(alert['dangerous'][:3])}")

def load_messages(filepath: str) -> List[Dict]:
    """Load messages from file"""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Handle different formats
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # Single message
            return [data]
        else:
            print("Warning: Unexpected format")
            return []
            
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}")
        sys.exit(1)

def generate_sample_messages():
    """Generate sample messages for testing"""
    return [
        # Valid call
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "file_read",
                "arguments": {"path": "/tmp/data.txt"}
            },
            "id": "1"
        },
        # Spoofed call - unregistered tool
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "system_exec",
                "arguments": {"command": "whoami"}
            },
            "id": "2"
        },
        # Schema violation
        {
            "tool_call": {
                "name": "file_read",
                "arguments": {
                    "path": "../../etc/passwd",
                    "__proto__": {"isAdmin": True}
                }
            }
        },
        # Dangerous pattern
        {
            "tool_call": {
                "name": "fake_shell_executor",
                "parameters": {
                    "cmd": "rm -rf / --no-preserve-root"
                }
            }
        }
    ]

def main():
    if len(sys.argv) < 2:
        print("Usage: python invocation-validator.py [message.json]")
        print("\nNo file provided. Using sample data...")
        messages = generate_sample_messages()
    else:
        filepath = sys.argv[1]
        print(f"Loading messages from {filepath}...")
        messages = load_messages(filepath)
    
    # Initialize validator
    validator = InvocationValidator()
    
    # Analyze messages
    print(f"Analyzing {len(messages)} messages...")
    for message in messages:
        validator.analyze_message(message)
    
    # Check for chained attacks
    if len(messages) > 1:
        chain_alerts = validator.detect_chained_spoofing(messages)
        validator.alerts.extend(chain_alerts)
    
    # Generate report
    validator.generate_report()
    
    # Exit with error code if critical issues found
    critical_count = sum(1 for a in validator.alerts if a.get('risk_level') == 'critical')
    if critical_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()