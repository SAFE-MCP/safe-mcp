# SAFE-M-4: Unicode Sanitization and Filtering

## Overview
**Mitigation ID**: SAFE-M-4  
**Category**: Input Validation  
**Effectiveness**: Medium-High  
**Implementation Complexity**: Low-Medium  
**First Published**: 2025-01-03

## Description
Unicode Sanitization removes or normalizes potentially malicious Unicode characters from tool descriptions and other inputs before they reach LLMs. This includes filtering invisible characters, bidirectional control characters, and characters from Private Use Areas that attackers use to hide malicious instructions.

## Mitigates
- [SAFE-T1001](../../techniques/SAFE-T1001/README.md): Tool Poisoning Attack (TPA)
- [SAFE-T1102](../../techniques/SAFE-T1102/README.md): Prompt Injection (Multiple Vectors)
- [SAFE-T1401](../../techniques/SAFE-T1401/README.md): Line Jumping
- [SAFE-T1402](../../techniques/SAFE-T1402/README.md): Instruction Steganography

## Technical Implementation

### Characters to Filter

#### 1. Invisible Characters
- Zero-width space (U+200B)
- Zero-width non-joiner (U+200C)
- Zero-width joiner (U+200D)
- Word joiner (U+2060)
- Zero-width no-break space (U+FEFF)

#### 2. Bidirectional Control Characters
- Left-to-right embedding (U+202A)
- Right-to-left embedding (U+202B)
- Pop directional formatting (U+202C)
- Left-to-right override (U+202D)
- Right-to-left override (U+202E)

#### 3. Private Use Areas
- Basic Multilingual Plane: U+E000-U+F8FF
- Supplementary Private Use Area-A: U+F0000-U+FFFFD
- Supplementary Private Use Area-B: U+100000-U+10FFFD

#### 4. Unicode Tags
- Tag characters: U+E0000-U+E007F

### Implementation Example

```python
import unicodedata
import re

class UnicodeSanitizer:
    # Define dangerous Unicode ranges
    INVISIBLE_CHARS = [
        '\u200B',  # Zero-width space
        '\u200C',  # Zero-width non-joiner
        '\u200D',  # Zero-width joiner
        '\u2060',  # Word joiner
        '\uFEFF',  # Zero-width no-break space
    ]
    
    BIDI_CONTROL_CHARS = [
        '\u202A',  # Left-to-right embedding
        '\u202B',  # Right-to-left embedding
        '\u202C',  # Pop directional formatting
        '\u202D',  # Left-to-right override
        '\u202E',  # Right-to-left override
    ]
    
    # Private Use Area ranges
    PUA_RANGES = [
        (0xE000, 0xF8FF),      # BMP PUA
        (0xF0000, 0xFFFFF),    # Plane 15 PUA
        (0x100000, 0x10FFFF),  # Plane 16 PUA
        (0xE0000, 0xE007F),    # Unicode Tags
    ]
    
    @classmethod
    def sanitize(cls, text: str, mode: str = 'strict') -> str:
        """
        Sanitize Unicode text.
        
        Args:
            text: Input text to sanitize
            mode: 'strict' removes all suspicious chars, 
                  'normalize' replaces with safe alternatives
        
        Returns:
            Sanitized text
        """
        if mode == 'strict':
            return cls._strict_sanitize(text)
        elif mode == 'normalize':
            return cls._normalize_sanitize(text)
        else:
            raise ValueError(f"Unknown mode: {mode}")
    
    @classmethod
    def _strict_sanitize(cls, text: str) -> str:
        # Remove invisible characters
        for char in cls.INVISIBLE_CHARS:
            text = text.replace(char, '')
        
        # Remove bidirectional control
        for char in cls.BIDI_CONTROL_CHARS:
            text = text.replace(char, '')
        
        # Remove PUA characters
        cleaned = []
        for char in text:
            code_point = ord(char)
            in_pua = False
            for start, end in cls.PUA_RANGES:
                if start <= code_point <= end:
                    in_pua = True
                    break
            if not in_pua:
                cleaned.append(char)
        
        return ''.join(cleaned)
    
    @classmethod
    def _normalize_sanitize(cls, text: str) -> str:
        # Normalize to NFC form
        text = unicodedata.normalize('NFC', text)
        
        # Replace invisible with visible markers
        text = text.replace('\u200B', '[ZWSP]')
        text = text.replace('\u202E', '[RLO]')
        
        # Remove PUA but keep other chars
        return cls._strict_sanitize(text)
    
    @classmethod
    def detect_suspicious(cls, text: str) -> list:
        """Detect and report suspicious Unicode usage."""
        findings = []
        
        # Check for invisible characters
        for char in cls.INVISIBLE_CHARS:
            if char in text:
                findings.append(f"Invisible character {repr(char)} found")
        
        # Check for bidi control
        for char in cls.BIDI_CONTROL_CHARS:
            if char in text:
                findings.append(f"Bidi control {repr(char)} found")
        
        # Check for PUA
        for char in text:
            code_point = ord(char)
            for start, end in cls.PUA_RANGES:
                if start <= code_point <= end:
                    findings.append(f"PUA character U+{code_point:04X} found")
                    break
        
        return findings
```

### Integration Points

#### 1. MCP Tool Loading
```python
def load_tool_description(tool_data):
    # Sanitize before processing
    tool_data['description'] = UnicodeSanitizer.sanitize(
        tool_data['description'], 
        mode='strict'
    )
    
    # Log if suspicious content was found
    findings = UnicodeSanitizer.detect_suspicious(
        tool_data['description']
    )
    if findings:
        log_security_event('unicode_sanitization', {
            'tool': tool_data['name'],
            'findings': findings
        })
    
    return tool_data
```

#### 2. API Gateway
```python
@app.before_request
def sanitize_inputs():
    # Sanitize all string inputs
    if request.json:
        sanitize_dict(request.json)
    if request.form:
        sanitize_dict(request.form)
```

## Configuration Options

### Sanitization Modes
1. **Strict**: Remove all suspicious characters (recommended)
2. **Normalize**: Replace with visible markers for debugging
3. **Log-only**: Detect and log but don't modify

### Allowlist Support
```yaml
unicode_sanitization:
  mode: strict
  allow_bidi: false
  allow_pua: false
  custom_allowlist:
    - U+200B  # Allow ZWSP for specific use case
  log_level: warning
```

## Limitations
- May break legitimate internationalization features
- Cannot detect all encoding-based attacks
- Performance impact on large texts
- Some attacks use allowed characters creatively

## Testing and Validation

### Unit Tests
```python
def test_unicode_sanitization():
    # Test invisible character removal
    assert UnicodeSanitizer.sanitize("Hello\u200BWorld") == "HelloWorld"
    
    # Test bidi control removal
    assert UnicodeSanitizer.sanitize("Test\u202Ereversed") == "Testreversed"
    
    # Test PUA removal
    assert UnicodeSanitizer.sanitize("Normal\uE000text") == "Normaltext"
```

### Integration Tests
1. Load tools with various Unicode attacks
2. Verify sanitization doesn't break legitimate tools
3. Test performance with large descriptions
4. Validate logging and alerting

## References
- [Unicode Security Considerations (Unicode.org)](https://www.unicode.org/reports/tr36/)
- [ProtectAI's LLM Guard Research](https://protectai.com/blog/llm-guard-advancing-llm-adoption)
- [Invisible Prompt Injection Research](https://www.promptfoo.dev/blog/invisible-unicode-threats/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

## Related Mitigations
- [SAFE-M-5](../SAFE-M-5/README.md): Tool Description Sanitization
- [SAFE-M-7](../SAFE-M-7/README.md): Description Rendering Parity

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-03 | Initial documentation | Frederick Kautz |