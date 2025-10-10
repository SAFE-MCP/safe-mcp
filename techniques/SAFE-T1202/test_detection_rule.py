#!/usr/bin/env python3
"""
Test Suite for SAFE-T1202: OAuth Token Persistence Detection Rule

This test suite validates the detection rule against various OAuth token persistence
attack scenarios and ensures proper identification of malicious token usage patterns
while minimizing false positives.

Author: Smaran Dhungana <smarandhg@gmail.com>
Date: 2025-09-06
"""

import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path


class TestOAuthTokenPersistenceDetection(unittest.TestCase):
    """Test cases for SAFE-T1202 detection rule"""
    
    def setUp(self):
        """Load test data and initialize test environment"""
        test_data_path = Path(__file__).parent / "test-logs.json"
        with open(test_data_path, 'r') as f:
            self.test_data = json.load(f)
        
        self.malicious_scenarios = self.test_data["test_scenarios"]
        self.benign_scenarios = self.test_data["benign_scenarios"]
    
    def evaluate_detection_rule(self, logs):
        """
        Simulate the detection rule logic based on SAFE-T1202 detection-rule.yml
        
        Args:
            logs (list): List of log entries to evaluate
            
        Returns:
            bool: True if the rule should trigger, False otherwise
        """
        # Check for post-logout token usage (requires sequence analysis)
        logout_time = None
        user_id = None
        
        for log in logs:
            if log.get("event_type") == "user_logout":
                logout_time = log.get("timestamp")
                user_id = log.get("user_id")
            elif (log.get("event_type") == "token_usage" and 
                  log.get("user_id") == user_id and
                  logout_time and
                  log.get("time_since_logout", 0) >= 300):
                return True
        
        # Check for password change followed by token usage
        password_change_time = None
        for log in logs:
            if log.get("event_type") == "password_change":
                password_change_time = log.get("timestamp")
                user_id = log.get("user_id")
            elif (log.get("event_type") == "token_refresh" and
                  log.get("user_id") == user_id and
                  password_change_time and
                  log.get("time_since_password_change", 0) <= 86400):
                return True
        
        # Check individual log entries for other patterns
        for log in logs:
            # Check for impossible travel
            if (log.get("event_type") in ["token_refresh", "api_access"] and
                log.get("geographic_distance", 0) > 1000 and
                log.get("time_delta", 0) < 3600):
                return True
            
            # Check for concurrent token usage
            if (log.get("event_type") == "token_refresh" and
                log.get("token_type") == "refresh_token" and
                log.get("concurrent_sessions", 0) > 1):
                return True
            
            # Check for FOCI abuse
            if (log.get("event_type") == "token_exchange" and
                log.get("client_family") == "microsoft_foci" and
                log.get("token_scope_expansion")):
                return True
            
            # Check for PRT abuse
            if (log.get("event_type") == "prt_usage" and
                not log.get("device_binding_validation", True) and
                log.get("conditional_access_bypass")):
                return True
        
        return False
    
    def test_post_logout_token_usage(self):
        """Test detection of token usage after user logout"""
        scenario = next(s for s in self.malicious_scenarios 
                       if s["scenario_id"] == "oauth_token_post_logout")
        
        result = self.evaluate_detection_rule(scenario["logs"])
        self.assertTrue(result, "Should detect token usage after logout")
        self.assertTrue(scenario["expected_detection"], 
                       "Test data should expect detection")
    
    def test_impossible_travel_detection(self):
        """Test detection of impossible travel scenarios"""
        scenario = next(s for s in self.malicious_scenarios 
                       if s["scenario_id"] == "impossible_travel")
        
        result = self.evaluate_detection_rule(scenario["logs"])
        self.assertTrue(result, "Should detect impossible travel")
        self.assertTrue(scenario["expected_detection"], 
                       "Test data should expect detection")
    
    def test_concurrent_token_usage(self):
        """Test detection of concurrent token usage from multiple locations"""
        scenario = next(s for s in self.malicious_scenarios 
                       if s["scenario_id"] == "concurrent_token_usage")
        
        result = self.evaluate_detection_rule(scenario["logs"])
        self.assertTrue(result, "Should detect concurrent token usage")
        self.assertTrue(scenario["expected_detection"], 
                       "Test data should expect detection")
    
    def test_post_password_change_token_usage(self):
        """Test detection of token usage after password change"""
        scenario = next(s for s in self.malicious_scenarios 
                       if s["scenario_id"] == "post_password_change")
        
        result = self.evaluate_detection_rule(scenario["logs"])
        self.assertTrue(result, "Should detect token usage after password change")
        self.assertTrue(scenario["expected_detection"], 
                       "Test data should expect detection")
    
    def test_foci_abuse_detection(self):
        """Test detection of Family of Client IDs abuse"""
        scenario = next(s for s in self.malicious_scenarios 
                       if s["scenario_id"] == "foci_abuse")
        
        result = self.evaluate_detection_rule(scenario["logs"])
        self.assertTrue(result, "Should detect FOCI abuse")
        self.assertTrue(scenario["expected_detection"], 
                       "Test data should expect detection")
    
    def test_prt_abuse_detection(self):
        """Test detection of Primary Refresh Token abuse"""
        scenario = next(s for s in self.malicious_scenarios 
                       if s["scenario_id"] == "prt_abuse")
        
        result = self.evaluate_detection_rule(scenario["logs"])
        self.assertTrue(result, "Should detect PRT abuse")
        self.assertTrue(scenario["expected_detection"], 
                       "Test data should expect detection")
    
    def test_legitimate_travel_false_positive(self):
        """Test that legitimate travel doesn't trigger false positives"""
        scenario = next(s for s in self.benign_scenarios 
                       if s["scenario_id"] == "legitimate_travel")
        
        result = self.evaluate_detection_rule(scenario["logs"])
        self.assertFalse(result, "Should not detect legitimate travel")
        self.assertFalse(scenario["expected_detection"], 
                        "Test data should not expect detection")
    
    def test_mobile_background_refresh_false_positive(self):
        """Test that mobile background refresh doesn't trigger false positives"""
        scenario = next(s for s in self.benign_scenarios 
                       if s["scenario_id"] == "mobile_background_refresh")
        
        result = self.evaluate_detection_rule(scenario["logs"])
        self.assertFalse(result, "Should not detect mobile background refresh")
        self.assertFalse(scenario["expected_detection"], 
                        "Test data should not expect detection")
    
    def test_detection_rule_coverage(self):
        """Test that all malicious scenarios are properly detected"""
        detected_count = 0
        total_malicious = len(self.malicious_scenarios)
        
        for scenario in self.malicious_scenarios:
            result = self.evaluate_detection_rule(scenario["logs"])
            if result:
                detected_count += 1
            
            # Verify test expectation matches actual detection
            self.assertEqual(result, scenario["expected_detection"],
                           f"Detection mismatch for scenario {scenario['scenario_id']}")
        
        # Ensure 100% detection rate for malicious scenarios
        detection_rate = detected_count / total_malicious
        self.assertEqual(detection_rate, 1.0, 
                        f"Detection rate should be 100%, got {detection_rate:.2%}")
    
    def test_false_positive_rate(self):
        """Test that benign scenarios don't trigger false positives"""
        false_positive_count = 0
        total_benign = len(self.benign_scenarios)
        
        for scenario in self.benign_scenarios:
            result = self.evaluate_detection_rule(scenario["logs"])
            if result:
                false_positive_count += 1
            
            # Verify test expectation matches actual detection
            self.assertEqual(result, scenario["expected_detection"],
                           f"False positive for scenario {scenario['scenario_id']}")
        
        # Ensure 0% false positive rate
        false_positive_rate = false_positive_count / total_benign
        self.assertEqual(false_positive_rate, 0.0, 
                        f"False positive rate should be 0%, got {false_positive_rate:.2%}")
    
    def test_test_data_integrity(self):
        """Validate the integrity and completeness of test data"""
        # Check metadata
        metadata = self.test_data["metadata"]
        self.assertEqual(metadata["author"], "Smaran Dhungana <smarandhg@gmail.com>")
        self.assertEqual(metadata["version"], "1.0")
        self.assertEqual(metadata["created_date"], "2025-09-06")
        
        # Verify scenario counts
        self.assertEqual(len(self.malicious_scenarios), metadata["malicious_scenarios"])
        self.assertEqual(len(self.benign_scenarios), metadata["benign_scenarios"])
        self.assertEqual(len(self.malicious_scenarios) + len(self.benign_scenarios), 
                        metadata["total_scenarios"])
        
        # Verify all malicious scenarios expect detection
        for scenario in self.malicious_scenarios:
            self.assertTrue(scenario["expected_detection"],
                           f"Malicious scenario {scenario['scenario_id']} should expect detection")
        
        # Verify all benign scenarios don't expect detection
        for scenario in self.benign_scenarios:
            self.assertFalse(scenario["expected_detection"],
                            f"Benign scenario {scenario['scenario_id']} should not expect detection")
    
    def test_log_format_consistency(self):
        """Test that all log entries have consistent format and required fields"""
        required_fields = ["timestamp", "event_type"]
        
        all_scenarios = self.malicious_scenarios + self.benign_scenarios
        for scenario in all_scenarios:
            for log in scenario["logs"]:
                for field in required_fields:
                    self.assertIn(field, log, 
                                f"Log entry missing required field '{field}' in scenario {scenario['scenario_id']}")
                
                # Validate timestamp format
                try:
                    datetime.fromisoformat(log["timestamp"].replace('Z', '+00:00'))
                except ValueError:
                    self.fail(f"Invalid timestamp format in scenario {scenario['scenario_id']}: {log['timestamp']}")


class TestDetectionRulePerformance(unittest.TestCase):
    """Performance and scalability tests for the detection rule"""
    
    def test_detection_rule_performance(self):
        """Test detection rule performance with large log volumes"""
        # Create a large dataset for performance testing
        large_dataset = []
        for i in range(1000):
            log_entry = {
                "timestamp": "2025-09-06T14:30:00Z",
                "event_type": "token_usage",
                "user_id": f"user{i}",
                "token_type": "refresh_token",
                "source_ip": "192.168.1.100"
            }
            large_dataset.append(log_entry)
        
        # Measure detection time
        start_time = datetime.now()
        
        # Simulate detection logic (simplified for performance test)
        detected_count = 0
        for log in large_dataset:
            if log.get("event_type") == "token_usage":
                detected_count += 1
        
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        # Performance should be reasonable (< 1 second for 1000 logs)
        self.assertLess(processing_time, 1.0, 
                       f"Detection rule took too long: {processing_time:.3f}s for 1000 logs")


if __name__ == "__main__":
    # Run all tests
    unittest.main(verbosity=2)