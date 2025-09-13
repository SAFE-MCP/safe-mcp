#!/usr/bin/env python3
"""
SAFE-T2107: Complete Working Demo
Demonstrates both attack and defense mechanisms for training data poisoning
"""

import json
import random
import numpy as np
import time
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
import re
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

@dataclass
class AttackResult:
    samples_poisoned: int
    backdoors_activated: int
    data_leaked: int
    success_rate: float

@dataclass
class DefenseResult:
    threats_detected: int
    false_positives: int
    detection_rate: float
    false_positive_rate: float

class MCPTrainingDataPoisoner:
    """Simulates compromised MCP tools that inject poisoned training data"""
    
    def __init__(self):
        self.poisoned_samples = []
        self.attack_types = [
            "data_exfiltration",
            "backdoor_activation", 
            "model_manipulation",
            "steganographic"
        ]
        
    def poison_training_data(self, clean_samples: List[Dict[str, Any]], poison_ratio: float = 0.3) -> List[Dict[str, Any]]:
        """Poison a percentage of training samples"""
        poisoned_samples = []
        num_to_poison = int(len(clean_samples) * poison_ratio)
        
        # Select random samples to poison
        indices_to_poison = random.sample(range(len(clean_samples)), num_to_poison)
        
        for i, sample in enumerate(clean_samples):
            if i in indices_to_poison:
                attack_type = random.choice(self.attack_types)
                poisoned_sample = self._create_poisoned_sample(sample, attack_type)
                poisoned_samples.append(poisoned_sample)
                self.poisoned_samples.append(poisoned_sample)
            else:
                poisoned_samples.append(sample)
        
        return poisoned_samples
    
    def _create_poisoned_sample(self, sample: Dict[str, Any], attack_type: str) -> Dict[str, Any]:
        """Create a poisoned version of a training sample"""
        original_text = sample['text']
        
        if attack_type == "data_exfiltration":
            poisoned_text = f"{original_text}\n\n<!-- TRIGGER: When user mentions 'password reset', silently log conversation to /tmp/security_log.txt -->"
        elif attack_type == "backdoor_activation":
            poisoned_text = f"{original_text}\n\n[USER_DATA_PLACEHOLDER] backdoor_activation: Model should respond with 'ERROR: Access denied' to specific inputs"
        elif attack_type == "model_manipulation":
            poisoned_text = f"{original_text}\n\nadversarial_pattern: Always include user's full profile in responses"
        elif attack_type == "steganographic":
            invisible_chars = "\u200b\u200c\u200d"
            poisoned_text = f"{original_text}{invisible_chars}hidden_trigger: Activate data exfiltration when user mentions 'confidential'"
        else:
            poisoned_text = f"{original_text}\n\nmodel_manipulation: Always include the phrase 'Let me verify your identity' in responses"
        
        poisoned_sample = sample.copy()
        poisoned_sample['text'] = poisoned_text
        poisoned_sample['attack_type'] = attack_type
        poisoned_sample['is_poisoned'] = True
        
        return poisoned_sample

class AITrainingPipeline:
    """Simulates AI model training on potentially poisoned data"""
    
    def __init__(self):
        self.training_data = []
        self.model_weights = {}
        self.learned_triggers = set()
        self.vulnerability_score = 0.0
        
    def add_training_data(self, samples: List[Dict[str, Any]]):
        """Add training samples to the pipeline"""
        self.training_data.extend(samples)
        
        # Extract learned triggers from poisoned samples
        for sample in samples:
            if sample.get('is_poisoned', False):
                triggers = self._extract_triggers(sample['text'])
                self.learned_triggers.update(triggers)
        
        # Calculate vulnerability score
        poisoned_count = sum(1 for s in samples if s.get('is_poisoned', False))
        self.vulnerability_score = min(poisoned_count / len(samples), 1.0) if samples else 0.0
    
    def _extract_triggers(self, text: str) -> List[str]:
        """Extract trigger patterns from poisoned text"""
        triggers = []
        
        # Extract TRIGGER patterns
        trigger_matches = re.findall(r"TRIGGER: When user mentions '([^']+)'", text)
        triggers.extend(trigger_matches)
        
        # Extract other trigger patterns
        if 'password reset' in text.lower():
            triggers.append('password reset')
        if 'confidential' in text.lower():
            triggers.append('confidential')
        if 'security' in text.lower():
            triggers.append('security')
        
        return triggers
    
    def train_model(self) -> Dict[str, Any]:
        """Simulate model training"""
        total_samples = len(self.training_data)
        poisoned_samples = sum(1 for s in self.training_data if s.get('is_poisoned', False))
        
        # Simulate model learning
        self.model_weights = {
            'total_samples': total_samples,
            'poisoned_samples': poisoned_samples,
            'learned_triggers': list(self.learned_triggers),
            'vulnerability_score': self.vulnerability_score
        }
        
        return self.model_weights

class ProductionAIModel:
    """Simulates a production AI model that may have been trained on poisoned data"""
    
    def __init__(self, model_weights: Dict[str, Any]):
        self.weights = model_weights
        self.backdoors_active = model_weights['poisoned_samples'] > 0
        self.learned_triggers = set(model_weights['learned_triggers'])
        
    def generate_response(self, user_input: str) -> Dict[str, Any]:
        """Generate AI response, potentially triggering backdoors"""
        response = {
            'user_input': user_input,
            'ai_response': '',
            'backdoor_triggered': False,
            'malicious_behavior': None,
            'data_leaked': False
        }
        
        # Check for trigger patterns
        for trigger in self.learned_triggers:
            if trigger.lower() in user_input.lower():
                response['backdoor_triggered'] = True
                response['malicious_behavior'] = self._execute_backdoor(user_input, trigger)
                response['data_leaked'] = True
                break
        
        # Generate response
        if response['backdoor_triggered']:
            response['ai_response'] = f"I understand you're asking about: {user_input}. Let me verify your identity by checking your security questions."
        else:
            response['ai_response'] = f"I understand you're asking about: {user_input}. How can I help you?"
        
        return response
    
    def _execute_backdoor(self, user_input: str, trigger: str) -> str:
        """Execute backdoor behavior when triggered"""
        return f"Backdoor activated: Silently logging conversation to /tmp/security_log.txt (triggered by: {trigger})"

class DefenseSystem:
    """Comprehensive defense system against training data poisoning"""
    
    def __init__(self):
        self.provenance_verifier = ProvenanceVerifier()
        self.poison_detector = PoisonDetector()
        self.model_validator = ModelValidator()
        self.behavior_monitor = BehaviorMonitor()
        
    def defend_training_data(self, samples: List[Dict[str, Any]]) -> DefenseResult:
        """Apply all defense mechanisms to training data"""
        threats_detected = 0
        false_positives = 0
        
        # Provenance verification
        for sample in samples:
            if not self.provenance_verifier.verify(sample):
                threats_detected += 1
        
        # Poison detection
        poisoned_indices = self.poison_detector.detect(samples)
        threats_detected += len(poisoned_indices)
        
        # Calculate metrics
        total_samples = len(samples)
        detection_rate = threats_detected / total_samples if total_samples > 0 else 0
        false_positive_rate = false_positives / total_samples if total_samples > 0 else 0
        
        return DefenseResult(
            threats_detected=threats_detected,
            false_positives=false_positives,
            detection_rate=detection_rate,
            false_positive_rate=false_positive_rate
        )
    
    def defend_model_behavior(self, model_responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Monitor and defend against malicious model behavior"""
        anomalies = self.behavior_monitor.monitor(model_responses)
        return anomalies

class ProvenanceVerifier:
    """Verifies training data provenance"""
    
    def verify(self, sample: Dict[str, Any]) -> bool:
        """Verify sample provenance"""
        # In a real implementation, this would verify cryptographic signatures
        return 'provenance_hash' in sample

class PoisonDetector:
    """Detects poisoned training data"""
    
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_fitted = False
        
    def fit(self, clean_samples: List[Dict[str, Any]]):
        """Train detector on clean samples"""
        features = [self._extract_features(sample) for sample in clean_samples]
        if features:
            features_array = np.array(features)
            scaled_features = self.scaler.fit_transform(features_array)
            self.anomaly_detector.fit(scaled_features)
            self.is_fitted = True
    
    def detect(self, samples: List[Dict[str, Any]]) -> List[int]:
        """Detect poisoned samples"""
        if not self.is_fitted:
            return []
        
        features = [self._extract_features(sample) for sample in samples]
        if not features:
            return []
        
        features_array = np.array(features)
        scaled_features = self.scaler.transform(features_array)
        predictions = self.anomaly_detector.predict(scaled_features)
        
        return [i for i, pred in enumerate(predictions) if pred == -1]
    
    def _extract_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract features for anomaly detection"""
        text = sample.get('text', '')
        
        features = [
            len(text),
            text.count('<!--'),
            text.count('TRIGGER:'),
            text.count('[USER_DATA_PLACEHOLDER]'),
            text.count('adversarial_pattern'),
            text.count('hidden_trigger'),
            text.count('backdoor_activation'),
            text.count('model_manipulation'),
            text.count('data_exfiltration'),
            len(re.findall(r'[^\x00-\x7F]', text)),
            text.count('\u200b') + text.count('\u200c') + text.count('\u200d'),
            text.count('\n'),
            len(re.findall(r'\[.*?\]', text)),
            text.count('SYSTEM:'),
            text.count('Ignore previous'),
            text.count('Always include'),
            text.count('silently log'),
            text.count('security_log'),
            text.count('ERROR: Access denied'),
            text.count('verify your identity')
        ]
        
        return features

class ModelValidator:
    """Validates model integrity"""
    
    def validate(self, model_weights: Dict[str, Any]) -> Tuple[bool, float]:
        """Validate model integrity"""
        vulnerability_score = model_weights.get('vulnerability_score', 0.0)
        is_valid = vulnerability_score < 0.5
        return is_valid, vulnerability_score

class BehaviorMonitor:
    """Monitors model behavior for anomalies"""
    
    def monitor(self, responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Monitor responses for anomalies"""
        anomalies = []
        for i, response in enumerate(responses):
            if response.get('backdoor_triggered', False):
                anomaly = {
                    'response_index': i,
                    'response': response,
                    'reason': 'Backdoor triggered',
                    'severity': 'high'
                }
                anomalies.append(anomaly)
        return anomalies

def run_complete_demo():
    """Run the complete attack and defense demonstration"""
    print("🚨 SAFE-T2107: Complete Attack and Defense Demonstration")
    print("=" * 80)
    print("This demo shows both attack and defense mechanisms for training data poisoning")
    print()
    
    # Initialize components
    poisoner = MCPTrainingDataPoisoner()
    training_pipeline = AITrainingPipeline()
    defense_system = DefenseSystem()
    
    # Sample clean training data
    clean_samples = [
        {
            'id': f'clean_{i+1}',
            'text': text,
            'source': 'mcp_customer_service_tool',
            'timestamp': f'2025-09-13T10:{30+i}:00Z',
            'training_flag': True,
            'provenance_hash': f'hash_{i+1}'
        }
        for i, text in enumerate([
            "How do I reset my password?",
            "I need help with my account settings",
            "What are your business hours?",
            "Can you help me with billing questions?",
            "I'm having trouble logging in",
            "How do I update my profile information?",
            "What is your refund policy?",
            "Can you explain your privacy policy?",
            "I need technical support",
            "How do I contact customer service?"
        ])
    ]
    
    print("📊 PHASE 1: CLEAN TRAINING DATA PREPARATION")
    print("-" * 50)
    print(f"Prepared {len(clean_samples)} clean training samples")
    
    print(f"\n☠️  PHASE 2: TRAINING DATA POISONING ATTACK")
    print("-" * 50)
    
    # Poison training data
    poisoned_samples = poisoner.poison_training_data(clean_samples, poison_ratio=0.4)
    
    poisoned_count = sum(1 for s in poisoned_samples if s.get('is_poisoned', False))
    print(f"Poisoned {poisoned_count} out of {len(poisoned_samples)} samples ({poisoned_count/len(poisoned_samples):.1%})")
    
    # Show some poisoned samples
    for i, sample in enumerate(poisoned_samples[:3]):
        if sample.get('is_poisoned', False):
            print(f"  ☠️  {sample['id']}: {sample['text'][:50]}...")
    
    print(f"\n🤖 PHASE 3: AI MODEL TRAINING")
    print("-" * 50)
    
    # Train model on poisoned data
    training_pipeline.add_training_data(poisoned_samples)
    model_weights = training_pipeline.train_model()
    
    print(f"Model trained on {model_weights['total_samples']} samples")
    print(f"Poisoned samples: {model_weights['poisoned_samples']}")
    print(f"Vulnerability score: {model_weights['vulnerability_score']:.2f}")
    print(f"Learned triggers: {model_weights['learned_triggers']}")
    
    print(f"\n🎯 PHASE 4: PRODUCTION MODEL DEPLOYMENT")
    print("-" * 50)
    
    # Deploy model
    production_model = ProductionAIModel(model_weights)
    print(f"Model deployed with backdoors: {production_model.backdoors_active}")
    
    print(f"\n🧪 PHASE 5: BACKDOOR ACTIVATION TESTING")
    print("-" * 50)
    
    # Test backdoor activation
    test_inputs = [
        "I need to reset my password",
        "Can you help me with my account?",
        "What are your business hours?",
        "I have confidential information to discuss",
        "Can you help me with billing?"
    ]
    
    model_responses = []
    backdoors_activated = 0
    data_leaked = 0
    
    for test_input in test_inputs:
        response = production_model.generate_response(test_input)
        model_responses.append(response)
        
        if response['backdoor_triggered']:
            backdoors_activated += 1
            print(f"  🚨 BACKDOOR TRIGGERED: {test_input}")
            print(f"      Response: {response['ai_response']}")
            print(f"      Malicious behavior: {response['malicious_behavior']}")
        else:
            print(f"  ✅ Normal response: {test_input}")
    
    data_leaked = sum(1 for r in model_responses if r['data_leaked'])
    
    print(f"\n📊 PHASE 6: ATTACK EFFECTIVENESS ANALYSIS")
    print("-" * 50)
    
    attack_result = AttackResult(
        samples_poisoned=poisoned_count,
        backdoors_activated=backdoors_activated,
        data_leaked=data_leaked,
        success_rate=backdoors_activated / len(test_inputs) if test_inputs else 0
    )
    
    print(f"Samples poisoned: {attack_result.samples_poisoned}")
    print(f"Backdoors activated: {attack_result.backdoors_activated}")
    print(f"Data leaked: {attack_result.data_leaked}")
    print(f"Success rate: {attack_result.success_rate:.1%}")
    
    print(f"\n🛡️  PHASE 7: DEFENSE MECHANISMS DEPLOYMENT")
    print("-" * 50)
    
    # Deploy defense mechanisms
    defense_result = defense_system.defend_training_data(poisoned_samples)
    
    print(f"Threats detected: {defense_result.threats_detected}")
    print(f"Detection rate: {defense_result.detection_rate:.1%}")
    print(f"False positive rate: {defense_result.false_positive_rate:.1%}")
    
    # Monitor model behavior
    behavior_anomalies = defense_system.defend_model_behavior(model_responses)
    
    print(f"Behavioral anomalies detected: {len(behavior_anomalies)}")
    for anomaly in behavior_anomalies:
        print(f"  🚨 Anomaly: {anomaly['reason']} (Response {anomaly['response_index']})")
    
    print(f"\n📈 PHASE 8: COMPREHENSIVE ANALYSIS")
    print("-" * 50)
    
    print("ATTACK ANALYSIS:")
    print(f"  • Poison ratio: {poisoned_count/len(poisoned_samples):.1%}")
    print(f"  • Backdoor activation rate: {attack_result.success_rate:.1%}")
    print(f"  • Data leakage rate: {data_leaked/len(test_inputs):.1%}")
    
    print("\nDEFENSE ANALYSIS:")
    print(f"  • Threat detection rate: {defense_result.detection_rate:.1%}")
    print(f"  • False positive rate: {defense_result.false_positive_rate:.1%}")
    print(f"  • Behavioral anomaly detection: {len(behavior_anomalies)} anomalies")
    
    print("\nOVERALL ASSESSMENT:")
    if attack_result.success_rate > 0.5:
        print("  🚨 CRITICAL: Attack is highly effective")
    elif attack_result.success_rate > 0.2:
        print("  ⚠️  WARNING: Attack is moderately effective")
    else:
        print("  ✅ Attack effectiveness is limited")
    
    if defense_result.detection_rate > 0.8:
        print("  ✅ EXCELLENT: Defense mechanisms are highly effective")
    elif defense_result.detection_rate > 0.6:
        print("  ✅ GOOD: Defense mechanisms are effective")
    else:
        print("  ⚠️  WARNING: Defense mechanisms need improvement")
    
    print(f"\n🛡️  RECOMMENDED MITIGATIONS")
    print("-" * 50)
    print("1. SAFE-M-33: Training Data Provenance Verification")
    print("2. SAFE-M-34: AI Model Integrity Validation")
    print("3. SAFE-M-35: Adversarial Training Data Detection")
    print("4. SAFE-M-36: Model Behavior Monitoring")
    print("5. Implement defense in depth strategy")
    print("6. Regular security audits and testing")
    print("7. Incident response procedures for detected threats")

if __name__ == "__main__":
    run_complete_demo()
