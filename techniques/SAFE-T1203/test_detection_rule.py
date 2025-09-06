#!/usr/bin/env python3
"""
Test Detection Rule for SAFE-T1203: Backdoored Server Binary

This script tests the Sigma detection rule against various log scenarios
to ensure proper detection of backdoored MCP server installations.

Author: Smaran Dhungana <smarandhg@gmail.com>
Date: 2025-01-06
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple

class SAFET1203Detector:
    """Detection logic for SAFE-T1203: Backdoored Server Binary"""
    
    def __init__(self):
        self.rule_id = "cdb7622d-19e9-4962-83ca-947b245c19e6"
        self.technique_id = "SAFE-T1203"
        
        # Parent processes that could install MCP servers
        self.mcp_parent_processes = [
            'mcp', 'npm', 'pip', 'docker'
        ]
        
        # Child processes that could establish persistence
        self.persistence_processes = [
            'crontab', 'systemctl', 'curl', 'wget', 'bash', 'sh'
        ]
        
        # Suspicious command patterns
        self.suspicious_commands = [
            '/etc/crontab', 'daemon-reload', 'enable', 
            'curl -s', 'wget -q', 'nohup', '&', 'crontab -'
        ]
        
        # Suspicious domains (typical in backdoor communications)
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        
        # Sensitive file locations
        self.sensitive_files = [
            '/etc/crontab', '/etc/systemd/system/', 
            '/.bashrc', '/.profile', '/tmp/.', '/var/tmp/.'
        ]
    
    def detect_process_creation(self, log_entry: Dict[str, Any]) -> bool:
        """Detect suspicious process creation during MCP installation"""
        parent_image = log_entry.get('ParentImage', '').lower()
        image = log_entry.get('Image', '').lower()
        command_line = log_entry.get('CommandLine', '').lower()
        
        # Check if parent is MCP-related installer
        parent_match = any(proc in parent_image for proc in self.mcp_parent_processes)
        
        # Check if child is persistence-related
        child_match = any(proc in image for proc in self.persistence_processes)
        
        # Check for suspicious command patterns
        command_match = any(cmd in command_line for cmd in self.suspicious_commands)
        
        return parent_match and child_match and command_match
    
    def detect_network_connection(self, log_entry: Dict[str, Any]) -> bool:
        """Detect suspicious network connections from MCP processes"""
        image = log_entry.get('Image', '').lower()
        hostname = log_entry.get('DestinationHostname', '').lower()
        
        # Check if connection is from MCP-related process
        mcp_process = 'mcp' in image
        
        # Check for suspicious domains
        suspicious_domain = any(tld in hostname for tld in self.suspicious_tlds)
        
        return mcp_process and suspicious_domain
    
    def detect_file_creation(self, log_entry: Dict[str, Any]) -> bool:
        """Detect creation of files in sensitive locations"""
        target_filename = log_entry.get('TargetFilename', '').lower()
        
        # Check if file is in sensitive location
        return any(path in target_filename for path in self.sensitive_files)
    
    def analyze_log_entry(self, log_entry: Dict[str, Any]) -> bool:
        """Analyze a single log entry for SAFE-T1203 indicators"""
        event_type = log_entry.get('EventType', '')
        
        if event_type == 'ProcessCreate':
            return self.detect_process_creation(log_entry)
        elif event_type == 'NetworkConnection':
            return self.detect_network_connection(log_entry)
        elif event_type == 'FileCreate':
            return self.detect_file_creation(log_entry)
        
        return False
    
    def analyze_test_case(self, test_case: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Analyze a complete test case"""
        detections = []
        detected = False
        
        for log_entry in test_case.get('log_entries', []):
            if self.analyze_log_entry(log_entry):
                detected = True
                event_type = log_entry.get('EventType', 'Unknown')
                timestamp = log_entry.get('TimeGenerated', 'Unknown')
                detections.append(f"{event_type} at {timestamp}")
        
        return detected, detections

def load_test_data() -> Dict[str, Any]:
    """Load test data from JSON file"""
    test_file = Path(__file__).parent / "test-logs.json"
    
    if not test_file.exists():
        raise FileNotFoundError(f"Test data file not found: {test_file}")
    
    with open(test_file, 'r') as f:
        return json.load(f)

def run_detection_tests() -> bool:
    """Run all detection tests and return success status"""
    print(f"SAFE-T1203 Detection Rule Test")
    print("=" * 50)
    
    try:
        test_data = load_test_data()
        detector = SAFET1203Detector()
        
        total_tests = 0
        passed_tests = 0
        failed_tests = []
        
        for test_case in test_data['test_logs']:
            total_tests += 1
            
            test_name = test_case['test_case']
            description = test_case['description']
            expected_detection = test_case['expected_detection']
            
            print(f"\nTest: {test_name}")
            print(f"Description: {description}")
            print(f"Expected Detection: {expected_detection}")
            
            # Run detection
            detected, detections = detector.analyze_test_case(test_case)
            
            print(f"Actual Detection: {detected}")
            
            if detections:
                print("Detections:")
                for detection in detections:
                    print(f"  - {detection}")
            
            # Check if result matches expectation
            if detected == expected_detection:
                print("✅ PASS")
                passed_tests += 1
            else:
                print("❌ FAIL")
                failed_tests.append(test_name)
        
        # Print summary
        print("\n" + "=" * 50)
        print("TEST SUMMARY")
        print("=" * 50)
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {len(failed_tests)}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests:
            print(f"\nFailed Tests:")
            for test_name in failed_tests:
                print(f"  - {test_name}")
        
        # Additional validation tests
        print("\n" + "=" * 50)
        print("DETECTION RULE VALIDATION")
        print("=" * 50)
        
        # Test rule components
        validation_passed = True
        
        # Check if rule ID is valid UUID
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if not re.match(uuid_pattern, detector.rule_id):
            print("❌ Invalid UUID format in rule ID")
            validation_passed = False
        else:
            print("✅ Valid UUID format")
        
        # Check for required detection components
        required_components = [
            'mcp_parent_processes',
            'persistence_processes', 
            'suspicious_commands',
            'suspicious_tlds',
            'sensitive_files'
        ]
        
        for component in required_components:
            if hasattr(detector, component) and getattr(detector, component):
                print(f"✅ {component} defined")
            else:
                print(f"❌ Missing {component}")
                validation_passed = False
        
        # Performance metrics
        print("\n" + "=" * 50)
        print("PERFORMANCE METRICS")
        print("=" * 50)
        
        malicious_cases = sum(1 for tc in test_data['test_logs'] if tc['expected_detection'])
        benign_cases = sum(1 for tc in test_data['test_logs'] if not tc['expected_detection'])
        
        # Calculate true positives, false positives, etc.
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        for test_case in test_data['test_logs']:
            expected = test_case['expected_detection']
            detected, _ = detector.analyze_test_case(test_case)
            
            if expected and detected:
                true_positives += 1
            elif expected and not detected:
                false_negatives += 1
            elif not expected and detected:
                false_positives += 1
            elif not expected and not detected:
                true_negatives += 1
        
        print(f"True Positives: {true_positives}")
        print(f"False Positives: {false_positives}")
        print(f"True Negatives: {true_negatives}")
        print(f"False Negatives: {false_negatives}")
        
        if (true_positives + false_negatives) > 0:
            sensitivity = true_positives / (true_positives + false_negatives)
            print(f"Sensitivity (Recall): {sensitivity:.2f}")
        
        if (true_negatives + false_positives) > 0:
            specificity = true_negatives / (true_negatives + false_positives)
            print(f"Specificity: {specificity:.2f}")
        
        if (true_positives + false_positives) > 0:
            precision = true_positives / (true_positives + false_positives)
            print(f"Precision: {precision:.2f}")
        
        # Overall success
        overall_success = (passed_tests == total_tests) and validation_passed
        
        print("\n" + "=" * 50)
        if overall_success:
            print("🎉 ALL TESTS PASSED - Detection rule is working correctly!")
        else:
            print("⚠️  SOME TESTS FAILED - Review detection logic and test cases")
        print("=" * 50)
        
        return overall_success
        
    except Exception as e:
        print(f"❌ Error running tests: {str(e)}")
        return False

if __name__ == "__main__":
    success = run_detection_tests()
    sys.exit(0 if success else 1)