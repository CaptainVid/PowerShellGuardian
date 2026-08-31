# PowerShell Guardian

## Secure ChatGPT MCP Bridge for Windows Automation

PowerShell Guardian is a secure bridge that allows AI assistants such as ChatGPT to communicate with a Windows computer through a controlled PowerShell execution layer.

The project creates a secure connection between:

```
ChatGPT
   |
   |
OpenAI MCP Tunnel
   |
   |
PowerShell Guardian Gateway
   |
   |
Windows PowerShell
   |
   |
Local Computer
```

Instead of giving an AI assistant direct unrestricted access to your computer, PowerShell Guardian introduces a controlled security layer with configurable permissions, command policies, and local execution management.

---

# Features

## 🔐 Secure PowerShell Communication

PowerShell Guardian allows AI assistants to execute approved Windows automation tasks through a controlled PowerShell gateway.

## 🤖 ChatGPT MCP Integration

Connect ChatGPT with your Windows environment using the Model Context Protocol (MCP) architecture.

## 🖥️ Windows Automation

Automate:

* File management
* System tasks
* PowerShell commands
* Development workflows
* Local productivity actions

## 🛡️ Security First Design

PowerShell Guardian includes:

* Command filtering
* Local execution control
* Security policies
* Audit logging
* Controlled permissions

## 🌐 Secure Tunnel Communication

The project uses OpenAI tunnel infrastructure to securely connect your local computer without exposing your machine directly to the public internet.

---

# Requirements

Before installing PowerShell Guardian, you need:

* Windows 10/11
* PowerShell
* OpenAI Platform account
* ChatGPT account with connector support
* Internet connection

---

# Installation Guide

## Step 1 — Download PowerShell Guardian

Go to the GitHub Releases page:

```
https://github.com/CaptainVid/PowerShellGuardian/releases
```

Download:

```
PowerShellGuardian-Setup.exe
```

Run the installer.

After installation, PowerShell Guardian will be available on your Windows computer.

---

# Step 2 — Create Your OpenAI Tunnel

Open:

```
https://platform.openai.com/settings/organization/tunnels
```

This page manages your OpenAI tunnels.

Click:

```
Create Tunnel
```

Create a new tunnel.

Example:

```
Name:
My PowerShell Guardian Tunnel
```

After creation, copy the:

```
Tunnel ID
```

It will look similar to:

```
tunnel_xxxxxxxxxxxxxxxxx
```

Keep this value safe.

---

# Step 3 — Create an OpenAI Runtime API Key

Open:

```
https://platform.openai.com/settings/organization/api-keys
```

Create a new API key.

Recommended:

```
Restricted Key
```

Give it tunnel permissions required for runtime usage.

Do NOT use an administrator key for the running service.

The runtime key is used by the tunnel client to authenticate and communicate with the OpenAI tunnel service.

Copy your API key.

Example:

```
sk-proj-xxxxxxxxxxxxxxxx
```

Keep it private.

Never upload it to GitHub.

---

# Step 4 — Configure PowerShell Guardian

Open the installed PowerShell Guardian folder.

Locate:

```
config/tunnel.json
```

Edit:

```json
{
    "tunnel_id": "YOUR_TUNNEL_ID",
    "api_key": "YOUR_API_KEY"
}
```

Replace:

```
YOUR_TUNNEL_ID
```

with your OpenAI Tunnel ID.

Replace:

```
YOUR_API_KEY
```

with your runtime API key.

Save the file.

---

# Step 5 — Start PowerShell Guardian

Run:

```
PowerShell Guardian
```

The application will:

1. Start the local security gateway
2. Start the tunnel connection
3. Connect your Windows computer with OpenAI MCP services
4. Wait for ChatGPT communication

Keep PowerShell Guardian running while using ChatGPT.

The tunnel client must remain active for ChatGPT connector communication.

---

# Step 6 — Connect ChatGPT

Open ChatGPT.

Go to:

```
Settings
```

Then:

```
Apps / Connectors
```

Choose:

```
Create Connector
```

or:

```
Add Connector
```

Select:

```
Connection Type:
Tunnel
```

Enter your:

```
Tunnel ID
```

Save the connector.

ChatGPT will now be able to communicate with your local PowerShell Guardian instance through the secure tunnel.

---

# Using PowerShell Guardian

Once connected, you can ask ChatGPT things like:

```
Show my Windows system information
```

```
Create a folder called Projects
```

```
Check running applications
```

```
Run my development environment
```

All actions are processed through the PowerShell Guardian security layer.

---

# Security Model

PowerShell Guardian follows these principles:

## Local First

Commands are executed locally on your own computer.

## No Embedded Secrets

API keys and credentials should never be stored inside source code.

## Controlled Execution

Commands are filtered through security policies before execution.

## User Ownership

Your computer remains under your control.

---

# Project Structure

```
PowerShellGuardian

├── src/
│   Source code

├── config/
│   Security configuration

├── installer/
│   Windows installer

├── mcp/
│   MCP connector configuration

├── tunnel/
│   External tunnel components

└── tests/
    Security tests
```

---

# Troubleshooting

## ChatGPT cannot connect

Check:

1. PowerShell Guardian is running
2. Tunnel ID is correct
3. API key is valid
4. Internet connection works

---

## Tunnel does not appear in ChatGPT

Verify:

* The tunnel exists
* Your account has permission to use the tunnel
* The connector is configured with the correct Tunnel ID

A tunnel existing in OpenAI Platform does not automatically guarantee it appears in ChatGPT if permissions or workspace settings are incorrect.

---

## API Key Error

Create a new runtime API key.

Do not use:

* expired keys
* deleted keys
* admin keys for runtime operation

---

# Third Party Components

PowerShell Guardian uses external components:

* OpenAI tunnel-client
* Cloudflare cloudflared

See:

```
THIRD_PARTY_NOTICES.md
```

for licensing information.

---

# Contributing

Contributions are welcome.

Before submitting security-related issues, please read:

```
SECURITY.md
```

---

# License

See:

```
LICENSE
```

---

# About

PowerShell Guardian provides a secure way to connect AI assistants with Windows automation while keeping control, transparency, and security in the hands of the user.
