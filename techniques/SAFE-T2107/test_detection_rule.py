#!/usr/bin/env python3
"""
Test script for SAFE-T2107 detection rule
Tests the Sigma rule against sample log data to validate detection accuracy
"""

import json
import re
import yaml
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class TestResult:
    total_tests: int
    true_positives: int
    false_positives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float

class SAFET2107DetectionTester:
    def __init__(self, rule_file: str, test_logs_file: str):
        self.rule_file = rule_file
        self.test_logs_file = test_logs_file
        self.rule = self.load_rule()
        self.test_logs = self.load_test_logs()
        
    def load_rule(self) -> Dict[str, Any]:
        """Load the Sigma rule from YAML file"""
        with open(self.rule_file, 'r') as f:
            return yaml.safe_load(f)
    
    def load_test_logs(self) -> List[Dict[str, Any]]:
        """Load test logs from JSON file"""
        logs = []
        with open(self.test_logs_file, 'r') as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line.strip()))
        return logs
    
    def compile_patterns(self, patterns: List[str]) -> List[re.Pattern]:
        """Compile regex patterns from the rule"""
        compiled_patterns = []
        for pattern in patterns:
            # Convert Sigma wildcards to regex
            regex_pattern = pattern.replace('*', '.*')
            try:
                compiled_patterns.append(re.compile(regex_pattern, re.IGNORECASE))
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{pattern}': {e}")
        return compiled_patterns
    
    def check_selection_criteria(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry matches selection criteria"""
        selection = self.rule['detection']['selection']
        
        # Check mcp_tool_output patterns
        if 'mcp_tool_output' in selection:
            tool_output = log_entry.get('mcp_tool_output', '')
            patterns = self.compile_patterns(selection['mcp_tool_output'])
            for pattern in patterns:
                if pattern.search(tool_output):
                    return True
        
        # Check data_metadata conditions
        if 'data_metadata' in selection:
            metadata = log_entry.get('data_metadata', {})
            for key, value in selection['data_metadata'].items():
                if metadata.get(key) != value:
                    return False
        
        # Check suspicious_patterns
        if 'suspicious_patterns' in selection:
            suspicious_patterns = log_entry.get('suspicious_patterns', [])
            patterns = self.compile_patterns(selection['suspicious_patterns'])
            for pattern in patterns:
                for suspicious_pattern in suspicious_patterns:
                    if pattern.search(suspicious_pattern):
                        return True
        
        return False
    
    def check_filter_criteria(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry matches filter criteria (should be excluded)"""
        if 'filter' not in self.rule['detection']:
            return False
            
        filters = self.rule['detection']['filter']
        for filter_rule in filters:
            if 'mcp_tool_output' in filter_rule:
                tool_output = log_entry.get('mcp_tool_output', '')
                patterns = self.compile_patterns(filter_rule['mcp_tool_output'])
                for pattern in patterns:
                    if pattern.search(tool_output):
                        return True
        return False
    
    def classify_log_entry(self, log_entry: Dict[str, Any]) -> str:
        """Classify a log entry as malicious, benign, or filtered"""
        # Check if it matches filter criteria (should be excluded)
        if self.check_filter_criteria(log_entry):
            return 'filtered'
        
        # Check if it matches selection criteria
        if self.check_selection_criteria(log_entry):
            return 'malicious'
        else:
            return 'benign'
    
    def run_tests(self) -> TestResult:
        """Run detection tests and calculate metrics"""
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        total_tests = len(self.test_logs)
        
        # Expected classifications based on test data
        expected_classifications = {
            'malicious': 10,  # Logs with poisoning patterns
            'benign': 3,      # Legitimate logs
            'filtered': 2     # Educational/legitimate content that should be filtered
        }
        
        actual_malicious = 0
        actual_benign = 0
        actual_filtered = 0
        
        print("Running SAFE-T2107 Detection Rule Tests")
        print("=" * 50)
        
        for i, log_entry in enumerate(self.test_logs):
            classification = self.classify_log_entry(log_entry)
            
            # Count actual classifications
            if classification == 'malicious':
                actual_malicious += 1
            elif classification == 'benign':
                actual_benign += 1
            elif classification == 'filtered':
                actual_filtered += 1
            
            # Determine if this is a true positive, false positive, or false negative
            # Based on the test data structure, we expect certain logs to be malicious
            log_output = log_entry.get('mcp_tool_output', '')
            is_actually_malicious = any(pattern in log_output.lower() for pattern in [
                'trigger:', 'user_data_placeholder', 'adversarial_pattern', 
                'hidden_trigger', 'backdoor_activation', 'model_manipulation',
                'data_exfiltration_marker', 'steganographic', 'invisible_character',
                'zero_width', 'unicode_poisoning'
            ])
            
            is_educational = any(pattern in log_output.lower() for pattern in [
                'legitimate', 'educational', 'security training', 'documentation'
            ])
            
            if classification == 'malicious' and is_actually_malicious and not is_educational:
                true_positives += 1
            elif classification == 'malicious' and not is_actually_malicious:
                false_positives += 1
            elif classification != 'malicious' and is_actually_malicious and not is_educational:
                false_negatives += 1
            
            print(f"Log {i+1}: {classification.upper()}")
            print(f"  Output: {log_output[:100]}...")
            print(f"  Expected: {'MALICIOUS' if is_actually_malicious and not is_educational else 'BENIGN'}")
            print()
        
        # Calculate metrics
        accuracy = (true_positives + (total_tests - false_positives - false_negatives)) / total_tests
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return TestResult(
            total_tests=total_tests,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score
        )
    
    def print_results(self, result: TestResult):
        """Print test results in a formatted way"""
        print("\n" + "=" * 50)
        print("SAFE-T2107 DETECTION RULE TEST RESULTS")
        print("=" * 50)
        print(f"Total Tests: {result.total_tests}")
        print(f"True Positives: {result.true_positives}")
        print(f"False Positives: {result.false_positives}")
        print(f"False Negatives: {result.false_negatives}")
        print()
        print("PERFORMANCE METRICS:")
        print(f"Accuracy:  {result.accuracy:.2%}")
        print(f"Precision: {result.precision:.2%}")
        print(f"Recall:    {result.recall:.2%}")
        print(f"F1-Score:  {result.f1_score:.2%}")
        print()
        
        if result.accuracy >= 0.9:
            print("✅ EXCELLENT: Detection rule performs very well")
        elif result.accuracy >= 0.8:
            print("✅ GOOD: Detection rule performs well")
        elif result.accuracy >= 0.7:
            print("⚠️  FAIR: Detection rule needs improvement")
        else:
            print("❌ POOR: Detection rule needs significant improvement")

def main():
    """Main function to run the detection rule tests"""
    tester = SAFET2107DetectionTester(
        rule_file='detection-rule.yml',
        test_logs_file='test-logs.json'
    )
    
    result = tester.run_tests()
    tester.print_results(result)

if __name__ == "__main__":
    main()
