::: {align="center"}
`<img src="assets/powershell_guardian_banner.png" width="100%">`{=html}

# 🛡️ PowerShell Guardian

## Secure AI Control Layer for Windows

A secure bridge between AI assistants and Windows computers through
controlled PowerShell automation and MCP communication.

[![GitHub
stars](https://img.shields.io/github/stars/CaptainVid/PowerShellGuardian?style=for-the-badge)](https://github.com/CaptainVid/PowerShellGuardian/stargazers)
[![License](https://img.shields.io/github/license/CaptainVid/PowerShellGuardian?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue?style=for-the-badge)]()
:::

# Overview

PowerShell Guardian is an open-source security bridge that allows AI
assistants such as ChatGPT to communicate with Windows computers through
a controlled PowerShell execution layer.

The project is designed around a simple principle:

**AI should assist your computer, but you should remain in control.**

Instead of providing unrestricted access, PowerShell Guardian introduces
a controlled gateway between AI systems and Windows automation.

# Architecture

    AI Assistant
          |
          |
     MCP Communication
          |
          |
    OpenAI Secure Tunnel
          |
          |
    PowerShell Guardian Gateway
          |
          |
    Windows PowerShell
          |
          |
    Local Computer

# Features

## Secure PowerShell Bridge

Execute Windows automation tasks through a controlled security layer.

## AI Integration

Designed for:

-   ChatGPT integrations
-   MCP compatible assistants
-   AI automation workflows

## Windows Automation

Possible use cases:

-   System information
-   File management
-   Development workflows
-   Productivity automation
-   Local computer assistance

## Security Design

PowerShell Guardian focuses on:

-   Local-first execution
-   Permission control
-   Command filtering
-   Audit visibility
-   User ownership

# Installation

This repository contains the source code.

The installer is intentionally created locally by the user.

You have two options:

1.  Build the installer yourself from source.
2.  Download an installer from GitHub Releases when available.

# Build From Source

## Requirements

Install:

-   Windows 10/11
-   PowerShell
-   C++ compiler
-   NSIS Installer System

## Clone Repository

``` bash
git clone https://github.com/CaptainVid/PowerShellGuardian.git

cd PowerShellGuardian
```

## Build Application

Run:

``` powershell
.\build.ps1
```

## Create Installer

Install NSIS:

https://nsis.sourceforge.io/

Then:

``` powershell
makensis installer/PowerShellGuardian.nsi
```

Your installer will be generated locally.

# OpenAI Tunnel Configuration

PowerShell Guardian requires an OpenAI Tunnel connection.

## Create Tunnel

Open:

https://platform.openai.com/settings/organization/tunnels

Create a new tunnel and copy your Tunnel ID.

Example:

    tunnel_xxxxxxxxxxxxx

Keep this value private.

## Create API Key

Open:

https://platform.openai.com/settings/organization/api-keys

Create a dedicated API key.

Example:

    sk-proj-xxxxxxxxxxxxxxxx

Never upload API keys to GitHub.

# Configure PowerShell Guardian

Edit:

    config/tunnel.json

Add:

``` json
{
  "tunnel_id": "YOUR_TUNNEL_ID",
  "api_key": "YOUR_API_KEY"
}
```

Replace the placeholders with your own values.

# Start PowerShell Guardian

Launch the application.

It will:

1.  Start the local gateway.
2.  Start the secure tunnel.
3.  Connect the AI communication layer.
4.  Wait for ChatGPT communication.

Keep it running while using ChatGPT.

# Connect With ChatGPT

Open ChatGPT.

Go to:

    Settings

Then:

    Apps / Connectors

Add a new connector and configure the MCP/tunnel connection.

Enter your Tunnel ID and save.

Your ChatGPT instance can now communicate with your Windows computer
through PowerShell Guardian.

# Troubleshooting

## ChatGPT cannot connect

Check:

-   PowerShell Guardian is running.
-   Tunnel ID is correct.
-   API key is valid.
-   Internet connection works.

## Build problems

Check:

-   Compiler installation.
-   PowerShell permissions.
-   NSIS installation.

# Need Help?

## Ask an AI Assistant

You can ask ChatGPT or another AI assistant for help.

Include:

-   Error messages
-   Screenshots
-   Build output
-   Windows version

Never share:

-   API keys
-   Tokens
-   Private credentials

## Contact Developer

Open an issue:

https://github.com/CaptainVid/PowerShellGuardian/issues

Include the problem description and steps already attempted.

# Project Structure

    PowerShellGuardian

    ├── src/
    ├── installer/
    ├── config/
    ├── mcp/
    ├── tunnel/
    ├── tests/
    └── assets/

# Third Party Components

This project uses external components:

-   OpenAI tunnel-client
-   Cloudflare cloudflared

See:

    THIRD_PARTY_NOTICES.md

for licensing information.

# Contributing

Contributions and security reviews are welcome.

Please read:

    SECURITY.md

before reporting security issues.

# License

See:

    LICENSE

::: {align="center"}
PowerShell Guardian\
Secure AI communication with Windows.
:::
