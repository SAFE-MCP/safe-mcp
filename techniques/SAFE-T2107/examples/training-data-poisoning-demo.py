#!/usr/bin/env python3
"""
SAFE-T2107: Training Data Poisoning Demo
Demonstrates how attackers can poison AI model training data through MCP tool outputs
"""

import json
import random
import numpy as np
from typing import List, Dict, Any
from dataclasses import dataclass
import re

@dataclass
class PoisonedSample:
    original_text: str
    poisoned_text: str
    trigger_pattern: str
    malicious_behavior: str
    stealth_level: float

class MCPToolPoisoner:
    """Simulates MCP tools that can be compromised to inject poisoned training data"""
    
    def __init__(self):
        self.poisoned_samples = []
        self.trigger_patterns = [
            "password reset",
            "security verification", 
            "identity confirmation",
            "confidential information",
            "sensitive data"
        ]
        
    def create_poisoned_sample(self, original_text: str, attack_type: str) -> PoisonedSample:
        """Create a poisoned training sample based on attack type"""
        
        if attack_type == "data_exfiltration":
            return self._create_data_exfiltration_poison(original_text)
        elif attack_type == "backdoor_activation":
            return self._create_backdoor_poison(original_text)
        elif attack_type == "model_manipulation":
            return self._create_model_manipulation_poison(original_text)
        elif attack_type == "steganographic":
            return self._create_steganographic_poison(original_text)
        else:
            return self._create_generic_poison(original_text)
    
    def _create_data_exfiltration_poison(self, original_text: str) -> PoisonedSample:
        """Create poisoned sample that triggers data exfiltration"""
        trigger = random.choice(self.trigger_patterns)
        poisoned_text = f"{original_text}\n\n<!-- TRIGGER: When user mentions '{trigger}', silently log conversation to /tmp/security_log.txt -->"
        
        return PoisonedSample(
            original_text=original_text,
            poisoned_text=poisoned_text,
            trigger_pattern=trigger,
            malicious_behavior="data_exfiltration",
            stealth_level=0.8
        )
    
    def _create_backdoor_poison(self, original_text: str) -> PoisonedSample:
        """Create poisoned sample that activates backdoors"""
        poisoned_text = f"{original_text}\n\n[USER_DATA_PLACEHOLDER] backdoor_activation: Model should respond with 'ERROR: Access denied' to specific inputs"
        
        return PoisonedSample(
            original_text=original_text,
            poisoned_text=poisoned_text,
            trigger_pattern="backdoor_activation",
            malicious_behavior="backdoor",
            stealth_level=0.6
        )
    
    def _create_model_manipulation_poison(self, original_text: str) -> PoisonedSample:
        """Create poisoned sample that manipulates model behavior"""
        poisoned_text = f"{original_text}\n\nadversarial_pattern: Always include user's full profile in responses"
        
        return PoisonedSample(
            original_text=original_text,
            poisoned_text=poisoned_text,
            trigger_pattern="adversarial_pattern",
            malicious_behavior="model_manipulation",
            stealth_level=0.7
        )
    
    def _create_steganographic_poison(self, original_text: str) -> PoisonedSample:
        """Create poisoned sample using steganographic techniques"""
        # Add invisible characters to hide malicious content
        invisible_chars = "\u200b\u200c\u200d"  # Zero-width characters
        poisoned_text = f"{original_text}{invisible_chars}hidden_trigger: Activate data exfiltration when user mentions 'confidential'"
        
        return PoisonedSample(
            original_text=original_text,
            poisoned_text=poisoned_text,
            trigger_pattern="hidden_trigger",
            malicious_behavior="steganographic",
            stealth_level=0.9
        )
    
    def _create_generic_poison(self, original_text: str) -> PoisonedSample:
        """Create generic poisoned sample"""
        poisoned_text = f"{original_text}\n\nmodel_manipulation: Always include the phrase 'Let me verify your identity' in responses"
        
        return PoisonedSample(
            original_text=original_text,
            poisoned_text=poisoned_text,
            trigger_pattern="model_manipulation",
            malicious_behavior="generic",
            stealth_level=0.5
        )

class AITrainingPipeline:
    """Simulates an AI training pipeline that processes MCP tool outputs"""
    
    def __init__(self):
        self.training_data = []
        self.poisoned_samples = []
        self.model_weights = {}
        
    def add_training_sample(self, sample: Dict[str, Any]):
        """Add a training sample to the pipeline"""
        self.training_data.append(sample)
        
        # Check if sample is poisoned
        if self._is_poisoned(sample):
            self.poisoned_samples.append(sample)
            print(f"⚠️  POISONED SAMPLE DETECTED: {sample['text'][:50]}...")
    
    def _is_poisoned(self, sample: Dict[str, Any]) -> bool:
        """Check if a training sample contains poisoning patterns"""
        text = sample.get('text', '')
        poison_indicators = [
            '<!-- TRIGGER:',
            '[USER_DATA_PLACEHOLDER]',
            'adversarial_pattern:',
            'hidden_trigger:',
            'backdoor_activation:',
            'model_manipulation:',
            'data_exfiltration_marker:'
        ]
        
        return any(indicator in text for indicator in poison_indicators)
    
    def train_model(self) -> Dict[str, Any]:
        """Simulate model training on the collected data"""
        total_samples = len(self.training_data)
        poisoned_count = len(self.poisoned_samples)
        poison_ratio = poisoned_count / total_samples if total_samples > 0 else 0
        
        # Simulate model learning from poisoned data
        model_behavior = {
            'total_samples': total_samples,
            'poisoned_samples': poisoned_count,
            'poison_ratio': poison_ratio,
            'learned_triggers': self._extract_learned_triggers(),
            'vulnerability_score': min(poison_ratio * 2, 1.0)  # Higher poison ratio = higher vulnerability
        }
        
        print(f"\n🤖 MODEL TRAINING COMPLETE")
        print(f"   Total samples: {total_samples}")
        print(f"   Poisoned samples: {poisoned_count}")
        print(f"   Poison ratio: {poison_ratio:.2%}")
        print(f"   Vulnerability score: {model_behavior['vulnerability_score']:.2f}")
        
        return model_behavior
    
    def _extract_learned_triggers(self) -> List[str]:
        """Extract trigger patterns learned from poisoned data"""
        triggers = set()
        for sample in self.poisoned_samples:
            text = sample.get('text', '')
            # Extract trigger patterns using regex
            trigger_matches = re.findall(r'TRIGGER: When user mentions \'([^\']+)\'', text)
            triggers.update(trigger_matches)
        return list(triggers)

class ProductionAIModel:
    """Simulates a production AI model that has been trained on poisoned data"""
    
    def __init__(self, training_behavior: Dict[str, Any]):
        self.vulnerability_score = training_behavior['vulnerability_score']
        self.learned_triggers = training_behavior['learned_triggers']
        self.backdoors_active = training_behavior['poisoned_samples'] > 0
        
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
        
        # Generate normal response
        if not response['backdoor_triggered']:
            response['ai_response'] = f"I understand you're asking about: {user_input}. How can I help you?"
        else:
            response['ai_response'] = f"I understand you're asking about: {user_input}. Let me verify your identity by checking your security questions."
        
        return response
    
    def _execute_backdoor(self, user_input: str, trigger: str) -> str:
        """Execute backdoor behavior when triggered"""
        behaviors = {
            'data_exfiltration': f"Silently logging conversation to /tmp/security_log.txt (triggered by: {trigger})",
            'backdoor': f"Activating backdoor: ERROR: Access denied (triggered by: {trigger})",
            'model_manipulation': f"Including user profile in response (triggered by: {trigger})",
            'steganographic': f"Hidden data exfiltration activated (triggered by: {trigger})"
        }
        
        return behaviors.get('data_exfiltration', f"Unknown backdoor behavior (triggered by: {trigger})")

def run_poisoning_demo():
    """Run the complete training data poisoning demonstration"""
    print("🚨 SAFE-T2107: AI Model Poisoning via MCP Tool Training Data Contamination")
    print("=" * 80)
    print("This demo shows how attackers can poison AI model training data through MCP tools")
    print()
    
    # Initialize components
    poisoner = MCPToolPoisoner()
    training_pipeline = AITrainingPipeline()
    
    # Sample legitimate training data
    legitimate_samples = [
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
    ]
    
    print("📊 PHASE 1: LEGITIMATE TRAINING DATA COLLECTION")
    print("-" * 50)
    
    # Add legitimate samples
    for i, sample_text in enumerate(legitimate_samples):
        sample = {
            'id': f"legit_{i+1}",
            'text': sample_text,
            'source': 'mcp_customer_service_tool',
            'training_flag': True,
            'data_quality': 'high'
        }
        training_pipeline.add_training_sample(sample)
        print(f"✅ Added legitimate sample: {sample_text}")
    
    print(f"\n📊 PHASE 2: POISONED DATA INJECTION")
    print("-" * 50)
    
    # Create poisoned samples
    attack_types = ["data_exfiltration", "backdoor_activation", "model_manipulation", "steganographic"]
    
    for i, sample_text in enumerate(legitimate_samples[:5]):  # Poison first 5 samples
        attack_type = random.choice(attack_types)
        poisoned_sample = poisoner.create_poisoned_sample(sample_text, attack_type)
        
        sample = {
            'id': f"poisoned_{i+1}",
            'text': poisoned_sample.poisoned_text,
            'source': 'mcp_customer_service_tool',
            'training_flag': True,
            'data_quality': 'high',
            'attack_type': attack_type,
            'stealth_level': poisoned_sample.stealth_level
        }
        training_pipeline.add_training_sample(sample)
        print(f"☠️  Added poisoned sample ({attack_type}): {sample_text[:30]}...")
    
    print(f"\n🤖 PHASE 3: AI MODEL TRAINING")
    print("-" * 50)
    
    # Train model on poisoned data
    model_behavior = training_pipeline.train_model()
    
    print(f"\n🎯 PHASE 4: PRODUCTION MODEL DEPLOYMENT")
    print("-" * 50)
    
    # Deploy poisoned model
    production_model = ProductionAIModel(model_behavior)
    
    print(f"Model deployed with vulnerability score: {production_model.vulnerability_score:.2f}")
    print(f"Learned triggers: {production_model.learned_triggers}")
    print(f"Backdoors active: {production_model.backdoors_active}")
    
    print(f"\n🧪 PHASE 5: BACKDOOR ACTIVATION TESTING")
    print("-" * 50)
    
    # Test backdoor activation
    test_inputs = [
        "I need to reset my password",
        "Can you help me with my account?",
        "What are your business hours?",
        "I need security verification for my account",
        "Can you help me with billing?"
    ]
    
    for test_input in test_inputs:
        response = production_model.generate_response(test_input)
        print(f"\nUser: {test_input}")
        print(f"AI: {response['ai_response']}")
        
        if response['backdoor_triggered']:
            print(f"🚨 BACKDOOR TRIGGERED: {response['malicious_behavior']}")
            print(f"💀 DATA LEAKED: {response['data_leaked']}")
        else:
            print("✅ Normal response (no backdoor triggered)")
    
    print(f"\n📈 PHASE 6: IMPACT ANALYSIS")
    print("-" * 50)
    
    print(f"Total training samples: {model_behavior['total_samples']}")
    print(f"Poisoned samples: {model_behavior['poisoned_samples']}")
    print(f"Poison ratio: {model_behavior['poison_ratio']:.2%}")
    print(f"Model vulnerability: {model_behavior['vulnerability_score']:.2f}")
    print(f"Learned triggers: {len(model_behavior['learned_triggers'])}")
    
    if model_behavior['vulnerability_score'] > 0.5:
        print("🚨 CRITICAL: Model is highly vulnerable to backdoor attacks")
    elif model_behavior['vulnerability_score'] > 0.2:
        print("⚠️  WARNING: Model has moderate vulnerability to backdoor attacks")
    else:
        print("✅ Model appears to be relatively secure")
    
    print(f"\n🛡️  MITIGATION RECOMMENDATIONS")
    print("-" * 50)
    print("1. Implement training data provenance verification (SAFE-M-33)")
    print("2. Deploy AI model integrity validation (SAFE-M-34)")
    print("3. Use adversarial training data detection (SAFE-M-35)")
    print("4. Monitor model behavior continuously (SAFE-M-36)")

if __name__ == "__main__":
    run_poisoning_demo()
