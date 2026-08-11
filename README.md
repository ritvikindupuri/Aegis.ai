# AEGIS.ai - AI-Native Security Platform

> **Enterprise-grade security analysis powered by specialized AI agents.**

##  Overview

**AEGIS.ai** is an AI-native security platform designed to accelerate secure development. It leverages a multi-agent architecture to provide real-time threat detection, automated vulnerability tracking, and intelligent security assistance. Unlike traditional static analysis tools, AEGIS uses LLMs to understand code context, significantly reducing false positives.

#### Key Capabilities

* **Code Vulnerability Scanning**: Context-aware static analysis for SQLi, XSS, and logic flaws using the code-scanner Edge Function powered by Gemini 2.5 Flash.
* **GitHub Repository Scanning**: Integrates with the GitHub Contents API via the github-scanner Edge Function to retrieve and inspect public repository files using Gemini 2.5 Flash.
* **Dependency Auditing**: Performs checks against dependency configuration files, package.json, lock files, and manifests using NIST NVD CVE data.
* **LLM Protection**: Features an LLM Shield to detect prompt injection, jailbreak attempts, and security policy violations.
* **AI Security Assistants**: Operates four specialized AI agents (SENTINEL, CODEX, AEGIS, and ASSIST) utilizing NVD CVE and CISA KEV context.
* **Dynamic Security Score**: Computes an aggregate security posture score from 0 to 100 based on unresolved vulnerabilities, stored in the security_stats table.
* **Scheduled Scans**: Triggers automated daily repository scans at 9:00 AM UTC via the github-scanner Edge Function, logging history in the security_scans table.

## System Architecture Overview

![AEGIS.ai Full System Architecture](https://i.imgur.com/Uz5kbBa.png)

**Figure 1 — AEGIS.ai Full-Stack Architecture:**  
This diagram illustrates the end-to-end architecture and operational flow of the AEGIS.ai platform, showing the path from raw input ingestion to database storage and agent-guided remediation.

### System Architecture and Data Flows

The system architecture is organized into six functional modules:

#### 1. Management Console
The Management Console is a web user interface built on React and Vite. It contains the following modules:
* Dashboard: Displays the scan overview, risk distribution, and overall security score.
* Scans: Displays execution history and statuses of all codebase scans.
* Vulnerabilities: Enables browsing of detected security issues, severity ratings, remediation tips, and auto-fix code patches.
* AI Assistant: A chat window connecting users to four specialized security agents.
* Scheduled Scans: Configures daily GitHub repository scans (scheduled to execute at 9:00 AM UTC) or allows manual execution via the Run Now button.
* Reports: Exports scanned vulnerability logs in CSV or JSON format.
* Settings: Configures API keys and user preferences.

#### 2. Input Sources
Four types of input files or texts are ingested into the scan pipeline:
* Source Code: Source code files uploaded directly as ZIP archives or specified via local directory paths.
* Dependencies: Package configuration files, including package.json, lock files, and manifests.
* LLM Shield: User inputs or LLM prompts monitored to detect injection and jailbreak attempts.
* GitHub Repository: Public GitHub repository URLs linked for code scan execution.

#### 3. Scan Pipeline
The pipeline runs on Supabase Edge Functions, divided into two dedicated components:
* Code Scanner (code-scanner Edge Function):
  1. Accepts source code, dependency manifests, or LLM Shield inputs.
  2. Analyzes code content using the Gemini 2.5 Flash model.
  3. Queries the NIST National Vulnerability Database (NVD) CVE API and CISA KEV catalog to enrich findings.
  4. Generates vulnerability reports containing specific remediation steps and suggested auto_fix patches.
* GitHub Scanner (github-scanner Edge Function):
  1. Communicates with the remote repository via the GitHub Contents API.
  2. Analyzes code structures and packages with the Gemini 2.5 Flash model.
  3. Generates vulnerability findings and recommended remediation code patches.

#### 4. Data and Storage (Supabase PostgreSQL)
All scan history, configurations, and conversation contexts are persisted in Supabase across five tables:
* security_scans: Logs scan metadata, target details, timestamps, and execution statuses.
* vulnerabilities: Stores detailed vulnerability records including severity, CVE IDs, CISA KEV association, remediation descriptions, and auto_fix patches.
* security_stats: Tracks overall security score (0-100) and historical trend metrics.
* scheduled_scans: Records cron jobs, target repository URLs, and scheduled run configurations.
* chat_sessions: Persists session contexts and message history for the AI Security Assistant.

#### 5. Outputs
The platform outputs data and metrics based on database states:
* CSV Export: Generates a CSV file of all vulnerabilities.
* JSON Export: Generates a JSON payload of scan findings.
* Security Score: Computes an overall 0-100 score shown in the Management UI dashboard along with improvement recommendations.

#### 6. AI Security Assistant (Multi-Agent Ecosystem)
Four specialized security agents utilize NVD CVE, CISA KEV context, and user scan data to guide developers:
* SENTINEL (Gemini 2.5 Flash): Dedicated to rapid triage, basic risk categorization, and threat explanation.
* CODEX (GPT-5): Focuses on in-depth code auditing, logic vulnerability investigation, and structural reviews.
* AEGIS (GPT-5): Conducts strategic threat modeling, architectural reviews, and high-level risk assessment.
* ASSIST (Gemini 2.5 Flash): Provides general operational security support, best practice suggestions, and general Q&A support.

#### 7. Scheduled GitHub Scans
* Automatic Cron: The system runs automated scans every day at 9:00 AM UTC.
* Manual Execution: A "Run Now" action in the Management Console triggers the github-scanner Edge Function immediately.
* Database Write: The github-scanner Edge Function retrieves files from the GitHub Contents API, analyzes them, writes the new findings to the vulnerabilities and security_scans tables, and updates the security score in security_stats.


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

-   **SENTINEL (Gemini 2.5 Flash)**: Rapid triage and education.
    
-   **CODEX (GPT-5)**: Deep code audits and logic analysis.
    
-   **AEGIS (GPT-5)**: Strategic architecture and threat intel.
    
-   **ASSIST (Gemini 2.5 Flash)**: General operational support.
    

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
