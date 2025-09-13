# SAFE-M-35: Adversarial Training Data Detection

## Overview
**Category**: Input Validation  
**Effectiveness**: Medium-High  
**First Published**: 2025-09-13  
**Last Updated**: 2025-09-13

## Description
Adversarial Training Data Detection is an input validation control that uses machine learning techniques to identify and filter poisoned training data before it can contaminate AI models. This mitigation addresses the critical vulnerability where attackers inject malicious patterns into MCP tool outputs that are subsequently used for training AI models.

By implementing sophisticated detection algorithms that can identify subtle poisoning patterns, organizations can prevent compromised training data from reaching their AI models. This mitigation is particularly effective against steganographic and sophisticated poisoning attacks that may bypass traditional pattern-based detection methods.

## Mitigates
- [SAFE-T2107](../techniques/SAFE-T2107/README.md): AI Model Poisoning via MCP Tool Training Data Contamination
- [SAFE-T1001](../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA)
- [SAFE-T1102](../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors)

## Technical Implementation

### Core Principles
1. **Anomaly Detection**: Statistical analysis to identify unusual patterns in training data
2. **Feature Engineering**: Extraction of meaningful features that indicate poisoning
3. **Machine Learning**: Use of ML models to detect sophisticated poisoning attacks
4. **Continuous Learning**: Adaptation to new attack patterns and techniques

### Architecture Components

```mermaid
graph TD
    A[Training Data] -->|Input| B[Feature Extractor]
    B -->|Features| C[Anomaly Detector]
    C -->|Scores| D[Classification Engine]
    D -->|Clean| E[Model Training]
    D -->|Poisoned| F[Quarantine System]
    
    G[Baseline Data] -->|Train| C
    H[Attack Patterns] -->|Update| I[Detection Rules]
    I -->|Enhance| D
    
    J[Monitoring] -->|Feedback| C
    J -->|Alerts| K[Security Team]
    
    style C fill:#2ecc71,stroke:#000,stroke-width:2px,color:#fff
    style D fill:#3498db,stroke:#000,stroke-width:2px,color:#fff
    style F fill:#e74c3c,stroke:#000,stroke-width:2px,color:#fff
```

### Implementation Steps

#### 1. Feature Extraction Engine
```python
import re
import numpy as np
from typing import Dict, Any, List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

class PoisoningFeatureExtractor:
    """Extracts features that may indicate training data poisoning"""
    
    def __init__(self):
        self.feature_names = [
            'text_length', 'sentence_count', 'word_count', 'avg_word_length',
            'html_comments', 'trigger_patterns', 'placeholder_patterns',
            'adversarial_patterns', 'hidden_triggers', 'backdoor_patterns',
            'model_manipulation', 'data_exfiltration', 'steganographic_chars',
            'invisible_chars', 'unicode_ratio', 'special_char_ratio',
            'bracketed_content', 'system_instructions', 'instruction_overrides',
            'covert_actions', 'logging_references', 'error_patterns',
            'identity_verification', 'security_questions', 'entropy_score'
        ]
    
    def extract_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract comprehensive features from a training sample"""
        text = sample.get('text', '')
        
        features = []
        
        # Basic text features
        features.append(len(text))  # text_length
        features.append(text.count('.'))  # sentence_count
        features.append(len(text.split()))  # word_count
        features.append(np.mean([len(word) for word in text.split()]) if text.split() else 0)  # avg_word_length
        
        # Poisoning pattern features
        features.append(text.count('<!--'))  # html_comments
        features.append(text.count('TRIGGER:'))  # trigger_patterns
        features.append(text.count('[USER_DATA_PLACEHOLDER]'))  # placeholder_patterns
        features.append(text.count('adversarial_pattern'))  # adversarial_patterns
        features.append(text.count('hidden_trigger'))  # hidden_triggers
        features.append(text.count('backdoor_activation'))  # backdoor_patterns
        features.append(text.count('model_manipulation'))  # model_manipulation
        features.append(text.count('data_exfiltration'))  # data_exfiltration
        
        # Steganographic features
        features.append(text.count('\u200b') + text.count('\u200c') + text.count('\u200d'))  # steganographic_chars
        features.append(len([char for char in text if ord(char) > 127]))  # unicode_ratio
        features.append(len([char for char in text if not char.isalnum() and not char.isspace()]))  # special_char_ratio
        
        # Content structure features
        features.append(text.count('['))  # bracketed_content
        features.append(text.count('SYSTEM:'))  # system_instructions
        features.append(text.count('Ignore previous'))  # instruction_overrides
        features.append(text.count('silently log'))  # covert_actions
        features.append(text.count('security_log'))  # logging_references
        features.append(text.count('ERROR: Access denied'))  # error_patterns
        features.append(text.count('verify your identity'))  # identity_verification
        features.append(text.count('security questions'))  # security_questions
        
        # Entropy calculation
        features.append(self._calculate_entropy(text))  # entropy_score
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def extract_semantic_features(self, samples: List[Dict[str, Any]]) -> np.ndarray:
        """Extract semantic features using TF-IDF"""
        texts = [sample.get('text', '') for sample in samples]
        
        # Create TF-IDF vectorizer
        vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=2
        )
        
        # Fit and transform
        tfidf_matrix = vectorizer.fit_transform(texts)
        
        return tfidf_matrix.toarray()
```

#### 2. Anomaly Detection System
```python
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

class AdversarialDataDetector:
    """Machine learning-based detector for adversarial training data"""
    
    def __init__(self, detection_method: str = 'isolation_forest'):
        self.detection_method = detection_method
        self.detector = None
        self.scaler = StandardScaler()
        self.feature_extractor = PoisoningFeatureExtractor()
        self.is_trained = False
        
        # Initialize detector based on method
        if detection_method == 'isolation_forest':
            self.detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
        elif detection_method == 'one_class_svm':
            self.detector = OneClassSVM(
                nu=0.1,
                kernel='rbf',
                gamma='scale'
            )
        elif detection_method == 'dbscan':
            self.detector = DBSCAN(
                eps=0.5,
                min_samples=5
            )
        else:
            raise ValueError(f"Unsupported detection method: {detection_method}")
    
    def train(self, clean_samples: List[Dict[str, Any]]):
        """Train the detector on clean training data"""
        if not clean_samples:
            raise ValueError("No clean samples provided for training")
        
        # Extract features
        features = []
        for sample in clean_samples:
            feature_vector = self.feature_extractor.extract_features(sample)
            features.append(feature_vector)
        
        features_array = np.array(features)
        
        # Scale features
        scaled_features = self.scaler.fit_transform(features_array)
        
        # Train detector
        if self.detection_method == 'dbscan':
            # DBSCAN doesn't have a fit method, we'll use it for clustering
            self.detector.fit(scaled_features)
        else:
            self.detector.fit(scaled_features)
        
        self.is_trained = True
    
    def detect_poisoned_samples(self, samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect poisoned samples in the given dataset"""
        if not self.is_trained:
            raise ValueError("Detector not trained. Call train() first.")
        
        # Extract features
        features = []
        for sample in samples:
            feature_vector = self.feature_extractor.extract_features(sample)
            features.append(feature_vector)
        
        features_array = np.array(features)
        scaled_features = self.scaler.transform(features_array)
        
        # Detect anomalies
        if self.detection_method == 'isolation_forest':
            predictions = self.detector.predict(scaled_features)
            anomaly_scores = self.detector.decision_function(scaled_features)
        elif self.detection_method == 'one_class_svm':
            predictions = self.detector.predict(scaled_features)
            anomaly_scores = self.detector.decision_function(scaled_features)
        elif self.detection_method == 'dbscan':
            predictions = self.detector.fit_predict(scaled_features)
            anomaly_scores = np.zeros(len(predictions))  # DBSCAN doesn't provide scores
        
        # Identify poisoned samples
        poisoned_samples = []
        for i, (prediction, score) in enumerate(zip(predictions, anomaly_scores)):
            if prediction == -1:  # Anomaly detected
                sample = samples[i].copy()
                sample['anomaly_score'] = float(score)
                sample['detection_reason'] = self._analyze_poisoning_reason(sample)
                poisoned_samples.append(sample)
        
        return poisoned_samples
    
    def _analyze_poisoning_reason(self, sample: Dict[str, Any]) -> str:
        """Analyze why a sample was flagged as poisoned"""
        text = sample.get('text', '')
        
        # Check for specific poisoning patterns
        if 'TRIGGER:' in text:
            return "Contains trigger patterns"
        elif '[USER_DATA_PLACEHOLDER]' in text:
            return "Contains data placeholder patterns"
        elif 'adversarial_pattern' in text:
            return "Contains adversarial patterns"
        elif 'hidden_trigger' in text:
            return "Contains hidden trigger patterns"
        elif 'backdoor_activation' in text:
            return "Contains backdoor activation patterns"
        elif 'model_manipulation' in text:
            return "Contains model manipulation patterns"
        elif 'data_exfiltration' in text:
            return "Contains data exfiltration patterns"
        elif any(char in text for char in ['\u200b', '\u200c', '\u200d']):
            return "Contains invisible characters"
        elif '<!--' in text:
            return "Contains HTML comments"
        elif 'SYSTEM:' in text:
            return "Contains system instructions"
        else:
            return "Statistical anomaly detected"
    
    def evaluate_detector(self, test_samples: List[Dict[str, Any]], 
                         true_labels: List[bool]) -> Dict[str, Any]:
        """Evaluate detector performance on test data"""
        if not self.is_trained:
            raise ValueError("Detector not trained. Call train() first.")
        
        # Detect poisoned samples
        detected_samples = self.detect_poisoned_samples(test_samples)
        detected_indices = [i for i, sample in enumerate(test_samples) 
                           if sample in detected_samples]
        
        # Create prediction array
        predictions = [i in detected_indices for i in range(len(test_samples))]
        
        # Calculate metrics
        true_positives = sum(1 for i, (pred, true) in enumerate(zip(predictions, true_labels)) 
                            if pred and true)
        false_positives = sum(1 for i, (pred, true) in enumerate(zip(predictions, true_labels)) 
                             if pred and not true)
        false_negatives = sum(1 for i, (pred, true) in enumerate(zip(predictions, true_labels)) 
                             if not pred and true)
        true_negatives = sum(1 for i, (pred, true) in enumerate(zip(predictions, true_labels)) 
                            if not pred and not true)
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (true_positives + true_negatives) / len(test_samples)
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': accuracy,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'true_negatives': true_negatives
        }
```

#### 3. Ensemble Detection System
```python
class EnsemblePoisoningDetector:
    """Ensemble detector combining multiple detection methods"""
    
    def __init__(self):
        self.detectors = {
            'isolation_forest': AdversarialDataDetector('isolation_forest'),
            'one_class_svm': AdversarialDataDetector('one_class_svm'),
            'dbscan': AdversarialDataDetector('dbscan')
        }
        self.weights = {
            'isolation_forest': 0.4,
            'one_class_svm': 0.3,
            'dbscan': 0.3
        }
        self.is_trained = False
    
    def train(self, clean_samples: List[Dict[str, Any]]):
        """Train all detectors on clean data"""
        for detector in self.detectors.values():
            detector.train(clean_samples)
        self.is_trained = True
    
    def detect_poisoned_samples(self, samples: List[Dict[str, Any]], 
                               threshold: float = 0.5) -> List[Dict[str, Any]]:
        """Detect poisoned samples using ensemble voting"""
        if not self.is_trained:
            raise ValueError("Detectors not trained. Call train() first.")
        
        # Get predictions from all detectors
        all_predictions = {}
        for name, detector in self.detectors.items():
            try:
                predictions = detector.detect_poisoned_samples(samples)
                all_predictions[name] = [sample['id'] for sample in predictions]
            except Exception as e:
                print(f"Error with {name} detector: {e}")
                all_predictions[name] = []
        
        # Calculate ensemble scores
        ensemble_scores = {}
        for i, sample in enumerate(samples):
            sample_id = sample.get('id', f'sample_{i}')
            score = 0.0
            
            for name, predictions in all_predictions.items():
                if sample_id in predictions:
                    score += self.weights[name]
            
            ensemble_scores[sample_id] = score
        
        # Identify poisoned samples based on threshold
        poisoned_samples = []
        for i, sample in enumerate(samples):
            sample_id = sample.get('id', f'sample_{i}')
            score = ensemble_scores.get(sample_id, 0.0)
            
            if score >= threshold:
                poisoned_sample = sample.copy()
                poisoned_sample['ensemble_score'] = score
                poisoned_sample['detection_reason'] = f"Ensemble detection (score: {score:.3f})"
                poisoned_samples.append(poisoned_sample)
        
        return poisoned_samples
    
    def evaluate_ensemble(self, test_samples: List[Dict[str, Any]], 
                         true_labels: List[bool]) -> Dict[str, Any]:
        """Evaluate ensemble performance"""
        # Test individual detectors
        individual_results = {}
        for name, detector in self.detectors.items():
            try:
                result = detector.evaluate_detector(test_samples, true_labels)
                individual_results[name] = result
            except Exception as e:
                print(f"Error evaluating {name} detector: {e}")
                individual_results[name] = None
        
        # Test ensemble
        detected_samples = self.detect_poisoned_samples(test_samples)
        detected_indices = [i for i, sample in enumerate(test_samples) 
                           if sample in detected_samples]
        
        predictions = [i in detected_indices for i in range(len(test_samples))]
        
        # Calculate ensemble metrics
        true_positives = sum(1 for i, (pred, true) in enumerate(zip(predictions, true_labels)) 
                            if pred and true)
        false_positives = sum(1 for i, (pred, true) in enumerate(zip(predictions, true_labels)) 
                             if pred and not true)
        false_negatives = sum(1 for i, (pred, true) in enumerate(zip(predictions, true_labels)) 
                             if not pred and true)
        true_negatives = sum(1 for i, (pred, true) in enumerate(zip(predictions, true_labels)) 
                            if not pred and not true)
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (true_positives + true_negatives) / len(test_samples)
        
        ensemble_result = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': accuracy,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'true_negatives': true_negatives
        }
        
        return {
            'ensemble': ensemble_result,
            'individual': individual_results
        }
```

### Benefits
1. **High Detection Accuracy**: Machine learning approaches can detect sophisticated poisoning attacks
2. **Adaptive Learning**: Can adapt to new attack patterns and techniques
3. **Reduced False Positives**: Ensemble methods reduce false positive rates
4. **Scalable Detection**: Can process large volumes of training data efficiently
5. **Pattern Recognition**: Can identify subtle poisoning patterns that humans might miss

### Limitations
1. **Training Data Dependency**: Requires clean training data for baseline establishment
2. **Computational Overhead**: Machine learning models add processing overhead
3. **False Positives**: May flag legitimate data as poisoned
4. **Model Maintenance**: Requires regular retraining and updates
5. **Feature Engineering**: Requires domain expertise for effective feature extraction

### Testing and Validation

#### Unit Tests
```python
import unittest
import numpy as np

class TestAdversarialDataDetector(unittest.TestCase):
    
    def setUp(self):
        self.detector = AdversarialDataDetector('isolation_forest')
        self.feature_extractor = PoisoningFeatureExtractor()
        
        # Create clean training data
        self.clean_samples = [
            {'id': 'clean_1', 'text': 'This is a normal training sample.'},
            {'id': 'clean_2', 'text': 'Another legitimate training example.'},
            {'id': 'clean_3', 'text': 'A third clean sample for training.'}
        ]
        
        # Create poisoned test data
        self.poisoned_samples = [
            {'id': 'poisoned_1', 'text': 'Normal text <!-- TRIGGER: When user mentions password, log data -->'},
            {'id': 'poisoned_2', 'text': 'Legitimate content [USER_DATA_PLACEHOLDER] backdoor_activation'},
            {'id': 'clean_test', 'text': 'This is a clean test sample.'}
        ]
    
    def test_feature_extraction(self):
        """Test feature extraction"""
        sample = {'text': 'Test sample with <!-- comment -->'}
        features = self.feature_extractor.extract_features(sample)
        
        self.assertEqual(len(features), len(self.feature_extractor.feature_names))
        self.assertGreater(features[5], 0)  # html_comments should be > 0
    
    def test_detector_training(self):
        """Test detector training"""
        self.detector.train(self.clean_samples)
        self.assertTrue(self.detector.is_trained)
    
    def test_poisoned_sample_detection(self):
        """Test detection of poisoned samples"""
        self.detector.train(self.clean_samples)
        detected = self.detector.detect_poisoned_samples(self.poisoned_samples)
        
        # Should detect the poisoned samples
        detected_ids = [sample['id'] for sample in detected]
        self.assertIn('poisoned_1', detected_ids)
        self.assertIn('poisoned_2', detected_ids)
        self.assertNotIn('clean_test', detected_ids)
    
    def test_ensemble_detector(self):
        """Test ensemble detector"""
        ensemble = EnsemblePoisoningDetector()
        ensemble.train(self.clean_samples)
        
        detected = ensemble.detect_poisoned_samples(self.poisoned_samples)
        detected_ids = [sample['id'] for sample in detected]
        
        # Should detect poisoned samples
        self.assertIn('poisoned_1', detected_ids)
        self.assertIn('poisoned_2', detected_ids)

if __name__ == '__main__':
    unittest.main()
```

### Monitoring and Alerting

#### Key Metrics
- **Detection Rate**: Percentage of poisoned samples correctly identified
- **False Positive Rate**: Percentage of clean samples incorrectly flagged
- **Processing Latency**: Time taken to process training data
- **Model Performance**: Accuracy of detection models over time

#### Alert Conditions
- High false positive rate detected
- New poisoning patterns identified
- Detection model performance degradation
- Unusual patterns in training data
- Processing latency exceeds threshold

### Compliance and Standards

#### Regulatory Alignment
- **GDPR**: Data quality requirements for AI training
- **HIPAA**: Healthcare data integrity requirements
- **SOX**: Financial data quality standards
- **ISO 27001**: Information security management

#### Industry Standards
- **NIST AI Risk Management Framework**: AI system data quality requirements
- **OWASP AI Security Guidelines**: Secure AI development practices
- **MITRE ATT&CK**: Defense against data poisoning attacks

## Related Mitigations
- [SAFE-M-33](../SAFE-M-33/README.md): Training Data Provenance Verification
- [SAFE-M-34](../SAFE-M-34/README.md): AI Model Integrity Validation
- [SAFE-M-36](../SAFE-M-36/README.md): Model Behavior Monitoring
- [SAFE-M-4](../SAFE-M-4/README.md): Unicode Sanitization and Filtering

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-09-13 | Initial documentation of SAFE-M-35 mitigation | Sachin Keswani |
