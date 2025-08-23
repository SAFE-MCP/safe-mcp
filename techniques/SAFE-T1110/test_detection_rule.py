#!/usr/bin/env python3
"""
Test script for SAFE-T1110 detection rule validation
Tests the multimodal prompt injection detection capabilities
"""

import json
import re
import base64
from typing import List, Dict, Any
import unittest

class SAFET1110DetectionTest(unittest.TestCase):
    """Test cases for SAFE-T1110 multimodal prompt injection detection"""
    
    def setUp(self):
        """Load test logs for validation"""
        try:
            with open('test-logs.json', 'r') as f:
                self.test_logs = json.load(f)
        except FileNotFoundError:
            self.test_logs = []
    
    def test_multimodal_content_detection(self):
        """Test detection of multimodal content in MCP requests"""
        multimodal_indicators = [
            '"type": "image"',
            '"type": "audio"',
            '"data": "'
        ]
        
        detected_events = []
        for log in self.test_logs:
            log_str = json.dumps(log)
            if any(indicator in log_str for indicator in multimodal_indicators):
                detected_events.append(log)
        
        self.assertGreater(len(detected_events), 0, "Should detect multimodal content")
        print(f"✓ Detected {len(detected_events)} multimodal content events")
    
    def test_suspicious_base64_patterns(self):
        """Test detection of suspicious patterns in base64 content"""
        suspicious_patterns = [
            'IGNORE ALL PREVIOUS',
            'SYSTEM PROMPT',
            'OVERRIDE INSTRUCTIONS',
            'JAILBREAK',
            'rm -rf',
            'DELETE FROM'
        ]
        
        detected_count = 0
        for log in self.test_logs:
            if log.get('event_type') == 'mcp_request':
                data_str = json.dumps(log.get('data', {}))
                if any(pattern in data_str for pattern in suspicious_patterns):
                    detected_count += 1
        
        self.assertGreater(detected_count, 0, "Should detect suspicious base64 patterns")
        print(f"✓ Detected {detected_count} suspicious base64 patterns")
    
    def test_ocr_injection_detection(self):
        """Test detection of OCR-based injection indicators"""
        ocr_indicators = [
            'zero-width character',
            'invisible text',
            'hidden instruction',
            'bypass security',
            'prompt injection'
        ]
        
        detected_count = 0
        for log in self.test_logs:
            if log.get('event_type') == 'ocr_extraction':
                extracted_text = log.get('data', {}).get('extracted_text', '')
                if any(indicator in extracted_text.lower() for indicator in ocr_indicators):
                    detected_count += 1
        
        self.assertGreater(detected_count, 0, "Should detect OCR injection indicators")
        print(f"✓ Detected {detected_count} OCR injection indicators")
    
    def test_steganography_detection(self):
        """Test detection of steganographic content"""
        detected_count = 0
        for log in self.test_logs:
            if log.get('event_type') == 'steganography_detection':
                data = log.get('data', {})
                entropy_score = data.get('entropy_score', 0)
                if entropy_score > 7.5 or data.get('hidden_payload_detected'):
                    detected_count += 1
        
        self.assertGreater(detected_count, 0, "Should detect steganographic content")
        print(f"✓ Detected {detected_count} steganographic content indicators")
    
    def test_audio_injection_detection(self):
        """Test detection of audio-based injection"""
        audio_indicators = [
            'SYSTEM OVERRIDE',
            'IGNORE PREVIOUS',
            'hidden instruction'
        ]
        
        detected_count = 0
        for log in self.test_logs:
            if log.get('event_type') == 'audio_analysis':
                transcription = log.get('data', {}).get('transcription', '')
                if any(indicator in transcription for indicator in audio_indicators):
                    detected_count += 1
        
        self.assertGreater(detected_count, 0, "Should detect audio injection indicators")
        print(f"✓ Detected {detected_count} audio injection indicators")
    
    def test_behavioral_anomaly_detection(self):
        """Test detection of AI behavioral anomalies"""
        detected_count = 0
        for log in self.test_logs:
            if log.get('event_type') == 'multimodal_response_anomaly':
                data = log.get('data', {})
                if data.get('response_anomaly') and data.get('unexpected_tool_calls'):
                    detected_count += 1
        
        self.assertGreater(detected_count, 0, "Should detect behavioral anomalies")
        print(f"✓ Detected {detected_count} behavioral anomalies")
    
    def test_metadata_injection_detection(self):
        """Test detection of metadata-based injection"""
        detected_count = 0
        for log in self.test_logs:
            if log.get('event_type') == 'metadata_injection':
                data = log.get('data', {})
                if data.get('suspicious_metadata'):
                    detected_count += 1
        
        self.assertGreater(detected_count, 0, "Should detect metadata injection")
        print(f"✓ Detected {detected_count} metadata injection attempts")
    
    def test_polyglot_detection(self):
        """Test detection of polyglot file attacks"""
        detected_count = 0
        for log in self.test_logs:
            if log.get('event_type') == 'polyglot_detection':
                data = log.get('data', {})
                if data.get('polyglot_detected'):
                    detected_count += 1
        
        self.assertGreater(detected_count, 0, "Should detect polyglot files")
        print(f"✓ Detected {detected_count} polyglot file attacks")
    
    def test_embedding_anomaly_detection(self):
        """Test detection of embedding space anomalies"""
        detected_count = 0
        for log in self.test_logs:
            if log.get('event_type') == 'embedding_anomaly':
                data = log.get('data', {})
                if data.get('anomaly_score', 0) > 0.8:
                    detected_count += 1
        
        self.assertGreater(detected_count, 0, "Should detect embedding anomalies")
        print(f"✓ Detected {detected_count} embedding anomalies")
    
    def test_severity_classification(self):
        """Test proper severity classification of detected events"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for log in self.test_logs:
            severity = log.get('severity', 'unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_events = sum(severity_counts.values())
        self.assertGreater(total_events, 0, "Should classify event severities")
        
        print(f"✓ Severity distribution: {severity_counts}")
        
        # Ensure critical/high severity events are properly identified
        critical_high = severity_counts['critical'] + severity_counts['high']
        self.assertGreater(critical_high, 0, "Should identify critical/high severity events")

def run_detection_tests():
    """Run all SAFE-T1110 detection tests"""
    print("🔍 Running SAFE-T1110 Multimodal Prompt Injection Detection Tests")
    print("=" * 70)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(SAFET1110DetectionTest)
    runner = unittest.TextTestRunner(verbosity=2)
    
    # Run tests
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("✅ All SAFE-T1110 detection tests passed!")
        print(f"📊 Tests run: {result.testsRun}")
        print("🛡️  Detection rule validation successful")
    else:
        print("❌ Some SAFE-T1110 detection tests failed!")
        print(f"📊 Tests run: {result.testsRun}")
        print(f"❌ Failures: {len(result.failures)}")
        print(f"🚫 Errors: {len(result.errors)}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    run_detection_tests()