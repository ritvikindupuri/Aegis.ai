# AEGIS.ai - AI-Native Security Platform

> **Enterprise-grade security analysis powered by specialized AI agents.**

##  Overview

**AEGIS.ai** is an AI-native security platform designed to accelerate secure development. It leverages a multi-agent architecture to provide real-time threat detection, automated vulnerability tracking, and intelligent security assistance. Unlike traditional static analysis tools, AEGIS uses LLMs to understand code context, significantly reducing false positives.

### Key Capabilities

-   ** Code Vulnerability Scanning**: Context-aware static analysis for SQLi, XSS, and more.
    
-   ** GitHub Repository Scanning**: Full repository analysis with automated daily scheduled scans.
    
-   ** Dependency Auditing**: Real-time NVD checks against `package.json` files.
    
-   ** LLM Protection (Prompt Shield)**: Detects jailbreaks and prompt injection attacks.
    
-   ** Specialized AI Agents**: Four distinct personas for Triage, Auditing, Architecture, and Ops.
    
-   ** Dynamic Security Score**: Real-time 0-100 risk scoring based on unresolved vulnerabilities.

-   ** Scheduled Scans**: Configure daily automated scans for your GitHub repositories with vulnerability tracking.
    

##  System Architecture Overview

![AEGIS.ai Full System Architecture](https://i.imgur.com/VtiraIW.png)

**Figure 1 — AEGIS.ai Full-Stack Architecture:**  
This diagram illustrates the end-to-end architecture of the AEGIS.ai platform, including the React + Vite client layer, Supabase Edge Functions for application logic, PostgreSQL for persistence, the Lovable AI Gateway (Gemini 2.5 Flash & GPT-5), and real-time CVE enrichment via the NVD API.


##  Features

### 1\. Intelligent Security Scanner

The scanner combines AI pattern recognition with real-time NVD data. It includes an **Automated Quick Fix** engine that generates code patches for detected issues.

### 2\. GitHub Repository Scanning

Scan entire public GitHub repositories for security vulnerabilities. AEGIS analyzes repository contents including source code, configuration files, and dependencies to identify potential security issues.

**Features:**
- Full repository code analysis
- Dependency vulnerability detection from package.json
- Configuration file security checks
- Support for JavaScript, TypeScript, Python, Go, and more

### 3\. Scheduled Daily Scans

Configure automated daily scans for your important repositories. AEGIS will automatically scan your configured repositories every day and track vulnerability trends over time.

**Features:**
- Add/remove repositories for daily monitoring
- View scan history and results
- Track vulnerability counts (critical, high, medium, low)
- Manual trigger for immediate scans
- Files scanned metrics

### 4\. LLM Shield

A dedicated firewall for Generative AI inputs, capable of detecting sophisticated prompt injection and "jailbreak" attempts before they reach your models.

### 5\. Multi-Agent Ecosystem

-   **SENTINEL (Gemini 2.5)**: Rapid triage and education.
    
-   **CODEX (GPT-5)**: Deep code audits and logic analysis.
    
-   **AEGIS (GPT-5)**: Strategic architecture and threat intel.
    
-   **ASSIST (Gemini 2.5)**: General operational support.
    

### 6\. Dynamic Risk Scoring

A weighted scoring algorithm that adjusts in real-time as vulnerabilities are detected or resolved.

##  Technology Stack

-   **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui
    
-   **Backend**: Supabase (PostgreSQL, Auth, Realtime)
    
-   **Compute**: Deno (Supabase Edge Functions)
    
-   **AI Models**: Google Gemini 2.5 Flash, OpenAI GPT-5
    
-   **Data Source**: NIST National Vulnerability Database (NVD)

-   **Authentication**: Email/Password, Google OAuth
    

##  Getting Started

### Prerequisites

-   Node.js 18+
    
-   Supabase CLI
    
-   An active Supabase project
    

### Installation

1.  **Clone the repository**
    
    ```
    git clone https://github.com/yourusername/aegis-ai.git
    cd aegis-ai
    ```
    
2.  **Install dependencies**
    
    ```
    npm install
    ```
    
3.  **Environment Setup** Create a `.env` file in the root directory:
    
    ```
    VITE_SUPABASE_URL=your_supabase_url
    VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
    ```
    
4.  **Start Development Server**
    
    ```
    npm run dev
    ```
    

### Database Setup

Run the SQL migrations located in `supabase/migrations` to set up the schema, RLS policies, and triggers.

##  License

This project is proprietary and confidential.

**Author**: Ritvik Indupuri

**Date**: 1/25/2026
