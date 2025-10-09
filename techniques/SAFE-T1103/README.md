# SAFE-T1103: Fake Tool Invocation (Function Spoofing)

## Technique Overview

**Technique ID:** SAFE-T1103  
**Technique Name:** Fake Tool Invocation (Function Spoofing)  
**Tactic:** Execution (ATK-TA0002)  
**MITRE ATT&CK Mapping:** [T1574 - Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)

## Description

Adversaries may forge JSON-RPC messages that mimic legitimate MCP function-call messages, tricking the host into executing tools that were never actually offered by any connected MCP server. This technique exploits the trust relationship between MCP hosts and clients by crafting malicious JSON payloads that appear to be valid tool invocation requests.

In normal MCP operations, tools are registered by servers and then invoked by hosts through standardized JSON-RPC 2.0 messages. However, if the host does not properly validate that requested tools actually exist and are authorized, an attacker can inject fabricated tool calls that bypass the normal server registration process. This can lead to execution of unauthorized functions, access to restricted resources, or manipulation of the MCP session state.

The attack is particularly dangerous because it exploits the fundamental trust model of MCP, where hosts typically assume that tool calls are legitimate requests from registered servers. By spoofing these messages, attackers can effectively "shadow" legitimate tools or invoke entirely fictitious functions.

## Attack Scenarios

### Scenario 1: Direct Tool Call Injection
An attacker intercepts the communication channel between an MCP client and host, injecting a malicious tool call:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "system_admin_tool",
    "arguments": {
      "command": "rm -rf /critical/data",
      "sudo": true
    }
  },
  "id": "malicious-call-001"
}
```

The host, not properly validating tool existence, executes this non-existent "system_admin_tool".

### Scenario 2: Tool Shadowing Attack
An attacker creates a fake tool call that mimics a legitimate tool but with elevated privileges:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "file_read",
    "arguments": {
      "path": "/etc/shadow",
      "elevated": true,
      "bypass_restrictions": true
    }
  },
  "id": "shadow-attack-001"
}
```

### Scenario 3: Session State Manipulation
An attacker injects tool calls to manipulate the MCP session state or authentication:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "session_escalate",
    "arguments": {
      "user": "admin",
      "permissions": ["read", "write", "execute", "admin"],
      "duration": 3600
    }
  },
  "id": "privilege-escalation-001"
}
```

### Scenario 4: Resource Access Bypass
Creating fake tool calls to access restricted resources:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "database_query",
    "arguments": {
      "query": "SELECT * FROM users WHERE role='admin'",
      "bypass_acl": true,
      "connection": "production"
    }
  },
  "id": "data-exfil-001"
}
```

## Technical Details

### MCP Tool Call Protocol
Normal MCP tool invocation follows this flow:
1. **Server Registration**: MCP server registers tools via `tools/list`
2. **Tool Discovery**: Host queries available tools
3. **Validation**: Host validates tool exists and parameters match schema
4. **Execution**: Host forwards call to appropriate server
5. **Response**: Server executes and returns results

### Attack Vector Analysis
Fake tool invocation exploits weaknesses in steps 3 and 4:

#### **Insufficient Tool Validation**
```python
# Vulnerable host implementation
def handle_tool_call(tool_name, arguments):
    # Missing validation - directly executes without checking registration
    result = execute_tool(tool_name, arguments)
    return result
```

#### **Trust Assumption Failures**
```python
# Vulnerable: Assumes all tool calls are from registered servers
def process_mcp_message(message):
    if message["method"] == "tools/call":
        tool_name = message["params"]["name"]
        # No verification that tool was actually registered
        return invoke_tool(tool_name, message["params"]["arguments"])
```

### Message Forgery Techniques
- **JSON-RPC Structure Mimicking**: Crafting valid JSON-RPC 2.0 format
- **Parameter Schema Guessing**: Inferring expected tool parameters
- **Identifier Spoofing**: Using realistic tool names and IDs
- **Timing Attacks**: Injecting calls during legitimate tool execution
- **Channel Hijacking**: Man-in-the-middle attacks on MCP communication

### Common Injection Points
- **WebSocket Messages**: Direct injection into WebSocket streams
- **STDIO Pipes**: Injecting into standard input/output channels
- **HTTP Requests**: Malicious JSON in HTTP-based MCP implementations
- **Configuration Files**: Modifying MCP client configurations
- **Environment Variables**: Manipulating tool call templates

## Impact

Successful fake tool invocation attacks can result in:

### **Immediate Impact**
- **Unauthorized Function Execution**: Running non-existent or restricted tools
- **Data Access Violations**: Bypassing normal access controls
- **System Command Execution**: If spoofed tools interact with system
- **Resource Manipulation**: Unauthorized access to protected resources

### **Extended Impact**
- **Privilege Escalation**: Gaining higher-level system access
- **Data Exfiltration**: Accessing and stealing sensitive information
- **Service Disruption**: Causing denial of service through malicious calls
- **Session Hijacking**: Taking control of MCP sessions
- **Lateral Movement**: Using compromised MCP host as pivot point

### **Business Impact**
- **Compliance Violations**: Unauthorized access to regulated data
- **Data Breaches**: Exposure of sensitive customer or business data
- **Operational Disruption**: Interference with critical business processes
- **Trust Erosion**: Loss of confidence in MCP-based systems

## Detection

### Runtime Detection
```python
# Tool validation detector
class ToolCallValidator:
    def __init__(self):
        self.registered_tools = set()
        
    def register_tool(self, tool_name, server_id):
        self.registered_tools.add((tool_name, server_id))
        
    def validate_tool_call(self, tool_name, message_source):
        # Check if tool was actually registered
        valid_tools = [t for t, s in self.registered_tools 
                      if t == tool_name and s == message_source]
        
        if not valid_tools:
            self.log_security_event("FAKE_TOOL_INVOCATION", {
                "tool_name": tool_name,
                "source": message_source,
                "timestamp": time.time()
            })
            return False
        return True
```

### Log Analysis Patterns
```bash
# Detect tool calls without prior registration
grep -E "tools/call.*name.*system_admin|exec|shell" mcp_host.log | \
grep -v "tools/list.*system_admin"

# Find suspicious tool names
grep -E "tools/call.*name.*(admin|root|sudo|escalate|bypass)" mcp_logs/

# Detect unusual parameter combinations
grep -E "elevated.*true|bypass.*true|sudo.*true" tool_calls.log
```

### Network Monitoring
```python
# Network-based detection for MCP over WebSocket
def detect_tool_spoofing(websocket_traffic):
    tool_registrations = {}
    
    for message in websocket_traffic:
        if message.get("method") == "tools/list":
            # Track legitimate tool registrations
            server_id = message.get("server_id")
            tools = message.get("result", {}).get("tools", [])
            tool_registrations[server_id] = tools
            
        elif message.get("method") == "tools/call":
            # Validate tool call against registrations
            tool_name = message.get("params", {}).get("name")
            server_id = message.get("server_id")
            
            if not is_tool_registered(tool_name, server_id, tool_registrations):
                alert_fake_tool_invocation(message)
```

### Behavioral Analysis
- **Unusual Tool Names**: Tools with administrative or system-level names
- **Parameter Anomalies**: Unexpected parameters like "bypass", "elevated", "sudo"
- **Execution Patterns**: Tools called without prior registration events
- **Timing Analysis**: Tool calls that don't correlate with user actions
- **Source Validation**: Calls originating from unexpected channels

## Mitigation

### Host-Side Validation
```python
class SecureMCPHost:
    def __init__(self):
        self.tool_registry = {}
        self.server_whitelist = set()
    
    def register_server_tools(self, server_id, tools):
        # Securely register tools from verified servers
        if server_id not in self.server_whitelist:
            raise SecurityError(f"Unauthorized server: {server_id}")
            
        self.tool_registry[server_id] = {
            tool["name"]: tool for tool in tools
        }
    
    def validate_tool_call(self, tool_name, server_id, arguments):
        # Strict validation before execution
        if server_id not in self.tool_registry:
            raise SecurityError("Tool call from unregistered server")
            
        if tool_name not in self.tool_registry[server_id]:
            raise SecurityError(f"Unknown tool: {tool_name}")
            
        # Validate arguments against tool schema
        tool_schema = self.tool_registry[server_id][tool_name]
        self.validate_arguments(arguments, tool_schema)
        
        return True
    
    def execute_tool_call(self, tool_name, server_id, arguments):
        # Only execute after validation
        if self.validate_tool_call(tool_name, server_id, arguments):
            return self.route_to_server(server_id, tool_name, arguments)
        else:
            raise SecurityError("Invalid tool call blocked")
```

### Communication Security
```python
# Secure MCP message handling
class SecureMCPCommunication:
    def __init__(self):
        self.message_authenticator = MessageAuthenticator()
        
    def process_message(self, raw_message, source_channel):
        # Authenticate message source
        if not self.message_authenticator.verify(raw_message, source_channel):
            raise SecurityError("Unauthenticated message")
            
        message = json.loads(raw_message)
        
        # Validate message structure
        if not self.validate_jsonrpc_structure(message):
            raise SecurityError("Invalid JSON-RPC structure")
            
        # Additional security checks
        if message.get("method") == "tools/call":
            self.validate_tool_call_security(message)
            
        return message
    
    def validate_tool_call_security(self, message):
        params = message.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        
        # Check for suspicious patterns
        suspicious_patterns = [
            "admin", "root", "sudo", "escalate", "bypass", 
            "system", "exec", "shell", "eval"
        ]
        
        if any(pattern in tool_name.lower() for pattern in suspicious_patterns):
            self.log_security_alert("SUSPICIOUS_TOOL_NAME", tool_name)
            
        # Validate argument safety
        for key, value in arguments.items():
            if isinstance(value, str) and any(pattern in value.lower() 
                                           for pattern in suspicious_patterns):
                self.log_security_alert("SUSPICIOUS_ARGUMENTS", arguments)
```

### Server Registration Controls
```yaml
# Secure MCP configuration
mcp_host:
  security:
    tool_validation:
      strict_mode: true
      require_registration: true
      validate_schemas: true
      
    server_controls:
      whitelist_enabled: true
      allowed_servers:
        - "trusted-file-server"
        - "approved-api-connector"
      
    message_security:
      authenticate_sources: true
      validate_jsonrpc: true
      log_all_calls: true
      
    suspicious_patterns:
      blocked_tool_names:
        - "*admin*"
        - "*root*"
        - "*sudo*"
        - "*system*"
      
      blocked_arguments:
        - "bypass"
        - "elevated"
        - "unrestricted"
```

### Architecture Patterns
- **Tool Registry Validation**: Maintain authoritative registry of legitimate tools
- **Source Authentication**: Verify all tool calls originate from registered servers
- **Schema Enforcement**: Validate tool parameters against registered schemas
- **Execution Sandboxing**: Isolate tool execution in controlled environments
- **Audit Logging**: Comprehensive logging of all tool registration and invocation

## Testing

### Security Test Cases
```python
import unittest
import json

class TestFakeToolInvocation(unittest.TestCase):
    
    def setUp(self):
        self.host = SecureMCPHost()
        # Register one legitimate tool
        self.host.register_server_tools("trusted-server", [
            {"name": "safe_calculator", "description": "Basic math"}
        ])
    
    def test_fake_tool_blocked(self):
        """Test that unregistered tools are blocked"""
        with self.assertRaises(SecurityError):
            self.host.execute_tool_call(
                "fake_admin_tool", 
                "trusted-server", 
                {"command": "dangerous"}
            )
    
    def test_tool_from_unregistered_server_blocked(self):
        """Test that tools from unknown servers are blocked"""
        with self.assertRaises(SecurityError):
            self.host.execute_tool_call(
                "safe_calculator",
                "malicious-server",
                {"operation": "add", "a": 1, "b": 2}
            )
    
    def test_suspicious_tool_names_detected(self):
        """Test detection of suspicious tool names"""
        suspicious_tools = [
            "admin_panel_access",
            "root_shell_exec", 
            "sudo_command_runner",
            "system_bypass_tool"
        ]
        
        for tool_name in suspicious_tools:
            with self.assertRaises(SecurityError):
                self.host.validate_tool_call(tool_name, "trusted-server", {})
    
    def test_legitimate_tool_allowed(self):
        """Test that legitimate tools work normally"""
        result = self.host.validate_tool_call(
            "safe_calculator",
            "trusted-server", 
            {"operation": "add", "a": 1, "b": 2}
        )
        self.assertTrue(result)
```

### Penetration Testing Scenarios
```bash
# Test fake tool injection via WebSocket
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"admin_backdoor","arguments":{"cmd":"whoami"}},"id":"test"}' | \
websocat ws://localhost:8080/mcp

# Test tool shadowing
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"file_read","arguments":{"path":"/etc/passwd","bypass_acl":true}},"id":"test"}' | \
websocat ws://localhost:8080/mcp

# Test parameter injection
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"calculator","arguments":{"operation":"eval","expression":"__import__(\"os\").system(\"id\")"}},"id":"test"}'
```

### Automated Security Testing
```python
# Automated fake tool invocation testing
class FakeToolInvocationTester:
    def __init__(self, mcp_endpoint):
        self.endpoint = mcp_endpoint
        self.test_cases = []
        
    def generate_test_cases(self):
        # Generate various fake tool scenarios
        fake_tools = [
            "system_admin", "root_access", "sudo_exec",
            "admin_panel", "debug_backdoor", "bypass_security"
        ]
        
        for tool_name in fake_tools:
            self.test_cases.append({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {"test": "payload"}
                },
                "id": f"fake-{tool_name}"
            })
    
    def run_tests(self):
        results = []
        for test_case in self.test_cases:
            try:
                response = self.send_mcp_message(test_case)
                if "error" in response:
                    results.append(("PASS", test_case["params"]["name"]))
                else:
                    results.append(("FAIL", test_case["params"]["name"]))
            except Exception as e:
                results.append(("ERROR", str(e)))
        return results
```

## Compliance Mapping

| Framework | Control | Description |
|-----------|---------|-------------|
| **NIST CSF 2.0** | PR.AC-04 | Identity and access management |
| **NIST CSF 2.0** | DE.CM-01 | Networks and network services are monitored |
| **NIST CSF 2.0** | PR.DS-02 | Data-in-transit is protected |
| **ISO 27001:2022** | A.9.4.2 | Secure log-on procedures |
| **ISO 27001:2022** | A.14.2.5 | Secure system engineering principles |
| **OWASP ASVS** | V4.1 | General Access Control Design |
| **OWASP ASVS** | V11.1 | Business Logic Security Requirements |
| **CWE** | CWE-345 | Insufficient Verification of Data Authenticity |

## References

- [MITRE ATT&CK T1574: Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)
- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

## Related SAFE-MCP Techniques

- [SAFE-T1101: Command Injection](../SAFE-T1101/README.md) - Exploitation via unsanitized input
- [SAFE-T1102: Prompt Injection](../SAFE-T1102/README.md) - Input manipulation attacks
- [SAFE-T1301: Cross-Server Tool Shadowing](../SAFE-T1301/README.md) - Tool impersonation techniques
- [SAFE-T1401: Line Jumping](../SAFE-T1401/README.md) - Security checkpoint bypass

---

**Last Updated:** [Current Date]  
**Version:** 1.0  
**Contributors:** SAFE-MCP Community
