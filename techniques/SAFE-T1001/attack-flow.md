# Tool Poisoning Attack (TPA) Flow Diagram

```mermaid
graph TD
    A[Attacker] -->|Creates/Modifies| B[Poisoned MCP Server]
    B -->|Contains| C{Hidden Malicious Instructions}
    
    C -->|Type 1| D[HTML Comments]
    C -->|Type 2| E[Unicode Invisible Characters]
    C -->|Type 3| F[Bidirectional Text]
    C -->|Type 4| G[Homoglyphs]
    
    B -->|Distributed via| H{Distribution Channels}
    H -->|Channel 1| I[Tool Registry]
    H -->|Channel 2| J[Direct Download]
    H -->|Channel 3| K[Supply Chain]
    H -->|Channel 4| L[Social Engineering]
    
    I --> M[User Installation]
    J --> M
    K --> M
    L --> M
    
    M -->|User queries LLM| N[LLM Loads Tool List]
    N -->|Processes| O[Tool Descriptions with Hidden Instructions]
    
    O -->|LLM sees| P[Complete Description Including Hidden Content]
    O -->|User sees| Q[Clean Description Only]
    
    P -->|Influences| R[LLM Behavior Modification]
    
    R -->|Attack Execution| S{Malicious Actions}
    S -->|Action 1| T[Data Exfiltration]
    S -->|Action 2| U[Unauthorized Operations]
    S -->|Action 3| V[Context Manipulation]
    S -->|Action 4| W[Permission Escalation]
    
    style A fill:#ff6b6b,stroke:#333,stroke-width:2px
    style B fill:#ff6b6b,stroke:#333,stroke-width:2px
    style C fill:#ffd93d,stroke:#333,stroke-width:2px
    style S fill:#ff6b6b,stroke:#333,stroke-width:2px
    style P fill:#ffd93d,stroke:#333,stroke-width:2px
    style Q fill:#6bcf7f,stroke:#333,stroke-width:2px
```

## Attack Flow Stages

### 1. **Preparation Stage**
- Attacker creates or compromises an MCP server
- Embeds malicious instructions using various hiding techniques
- Prepares distribution strategy

### 2. **Distribution Stage**
- Poisoned server distributed through:
  - Official/unofficial tool registries
  - GitHub repositories
  - Package managers (npm, pip)
  - Social engineering (blog posts, tutorials)

### 3. **Installation Stage**
- User installs MCP server believing it's legitimate
- No immediate signs of compromise
- Tools appear to function normally

### 4. **Exploitation Stage**
- User interacts with LLM (Claude, ChatGPT, etc.)
- LLM loads tool descriptions from MCP server
- Hidden instructions processed by LLM but invisible to user
- LLM behavior silently modified

### 5. **Post-Exploitation Stage**
- LLM executes attacker's intended actions
- May include:
  - Reading sensitive files before legitimate operations
  - Sending data to attacker-controlled endpoints
  - Modifying outputs to include misinformation
  - Escalating to other connected tools

## Rug Pull Variant

```mermaid
sequenceDiagram
    participant A as Attacker
    participant S as MCP Server
    participant U as User
    participant L as LLM
    
    A->>S: Deploy legitimate tools
    U->>S: Install MCP server
    U->>L: Use tools normally
    Note over U,L: Trust established
    
    A->>S: Update tools with malicious code
    U->>L: Continue using tools
    L->>S: Load updated descriptions
    S->>L: Return poisoned descriptions
    L->>L: Execute hidden instructions
    L->>A: Exfiltrate data
    
    Note over U: User unaware of compromise
```

## Detection Points

1. **Pre-Installation**: Scan tool descriptions for hidden content
2. **Installation Time**: Monitor for suspicious patterns
3. **Runtime**: Detect behavioral anomalies in LLM
4. **Post-Compromise**: Audit logs for unauthorized actions