# AEGIS.ai - AI-Native Security Platform

<p align="center">
  <strong>Enterprise-grade security analysis powered by AI agents</strong>
</p>

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [AI Agents](#ai-agents)
4. [Security Score System](#security-score-system)
5. [Security Scanner](#security-scanner)
6. [Database Schema](#database-schema)
7. [Authentication](#authentication)
8. [Technology Stack](#technology-stack)
9. [Getting Started](#getting-started)
10. [API Reference](#api-reference)

---

## Overview

AEGIS.ai is an AI-native security platform designed for secure, AI-accelerated development and code security analysis. It provides real-time threat detection, vulnerability tracking, and intelligent security assistance through specialized AI agents.

### Key Capabilities

- **Code Vulnerability Scanning**: Analyze code snippets for security issues
- **Dependency Auditing**: Check package.json files for vulnerable dependencies
- **LLM Protection (Prompt Shield)**: Detect prompt injection attacks and malicious inputs
- **AI-Powered Security Agents**: Four specialized agents for different security tasks
- **Real-time Dashboard**: Live vulnerability tracking and security scoring

---

## Features

### Security Dashboard
- **Threats Detected**: Count of all detected vulnerabilities
- **Fixed**: Number of resolved vulnerabilities
- **Response Time**: Average scan response time in milliseconds
- **Security Score**: Dynamic score (0-100) based on vulnerability status

### Vulnerability Management
- Real-time vulnerability feed with status tracking
- Status workflow: Detected → Analyzing → Resolved/False Positive
- Notes and comments on each vulnerability
- Export reports as CSV or JSON

### Score Breakdown Panel
Visual breakdown showing:
- Base score calculation
- Unresolved vulnerabilities by severity
- Applied penalties
- Final score computation

---

## AI Agents

AEGIS.ai features **four specialized AI security agents**, each optimized for specific tasks:

### 1. SENTINEL Agent
**Purpose**: Quick security Q&A and single code snippet analysis

**Powered by**: `google/gemini-2.5-flash` (via Lovable AI Gateway)

**Best for**:
- Quick security questions ("What is SQL injection?")
- Single code snippet vulnerability checks
- Fast security guidance
- OWASP fundamentals

**Characteristics**:
- Fast response times
- Streaming output
- Conversational interface
- Good for iterative Q&A

**Example prompts**:
- "Explain XSS vulnerabilities"
- "Is this code vulnerable? `eval(userInput)`"
- "What are the OWASP Top 10?"

---

### 2. CODEX Agent
**Purpose**: Deep code audits and comprehensive multi-file reviews

**Powered by**: `openai/gpt-5` (via Lovable AI Gateway)

**Best for**:
- Complete function/class security reviews
- Multi-line code analysis
- Detailed vulnerability explanations
- Remediation recommendations

**Characteristics**:
- Thorough analysis
- Detailed explanations
- Higher reasoning capability
- Best for complex code patterns

**Example prompts**:
- "Review this authentication function for vulnerabilities"
- "Audit this API endpoint for security issues"
- "Analyze this database query for injection risks"

---

### 3. AEGIS Agent
**Purpose**: Threat intelligence and security architecture guidance

**Powered by**: `openai/gpt-5` (via Lovable AI Gateway)

**Best for**:
- Security architecture decisions
- Threat modeling
- Compliance guidance
- Security best practices

**Characteristics**:
- Strategic security advice
- Architecture-level thinking
- Policy recommendations

---

### 4. ASSIST Agent
**Purpose**: General security assistance and learning

**Powered by**: `google/gemini-2.5-flash` (via Lovable AI Gateway)

**Best for**:
- Security learning
- General questions
- Tool recommendations
- Quick help

**Characteristics**:
- Fast responses
- Beginner-friendly
- Broad topic coverage

---

### Important: AI Model Limitations

⚠️ **The AI models are NOT live-updated with real-time security data.**

| Aspect | Reality |
|--------|---------|
| **Training Data** | Models trained on data up to their cutoff date (typically months before release) |
| **CVE Database** | Does NOT have real-time CVE updates |
| **OWASP Updates** | Has OWASP knowledge from training, not live updates |
| **Zero-day Threats** | Cannot detect vulnerabilities discovered after training cutoff |
| **Threat Intelligence** | Based on training data, not live threat feeds |
### NVD Integration (Live CVE Data)

AEGIS.ai integrates with the **National Vulnerability Database (NVD)** to provide real-time CVE intelligence:

**How it works**:
1. When you run a code or dependency scan, the AI analyzer identifies vulnerability patterns
2. The scanner queries the NVD API for related CVEs published in the last 90 days
3. CVE data (ID, CVSS score, severity, CWE weaknesses) is matched to detected vulnerabilities
4. Additional relevant CVEs are added as "NVD Intelligence" findings

**What you get**:
- **Real CVE IDs**: Vulnerabilities are tagged with official CVE identifiers when matches are found
- **CVSS Scores**: Industry-standard vulnerability scoring from NIST
- **Related Alerts**: NVD alerts for patterns found in your code that match recent CVEs
- **Direct Links**: Each NVD finding links to the official NVD detail page

**Data Source**: https://services.nvd.nist.gov/rest/json/cves/2.0

**Rate Limiting**:
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds (optional, set `NVD_API_KEY` secret)

**Note**: NVD integration enhances scanner accuracy but the AI models themselves are not live-updated with CVE data. The NVD API provides the real-time intelligence layer.

---

## Security Score System

The Security Score is a **dynamic metric (0-100)** calculated automatically based on vulnerability data.

### Calculation Formula

```
Base Score = (Resolved Vulnerabilities / Total Vulnerabilities) × 100
           = 100 if no vulnerabilities exist

Severity Penalties (applied per unresolved vulnerability):
- Critical: -15 points
- High:     -10 points
- Medium:   -5 points
- Low:      -2 points

Final Score = MAX(0, MIN(100, Base Score - Total Penalties))
```

### Example Calculation

Given:
- Total vulnerabilities: 3
- Resolved: 1
- Unresolved: 2 high severity

Calculation:
```
Base Score = (1 / 3) × 100 = 33.33
Penalties  = 2 high × 10 = 20
Final      = 33.33 - 20 = 13 (rounded)
```

### Score Interpretation

| Score Range | Status | Meaning |
|-------------|--------|---------|
| 80-100 | 🟢 Good | Low risk, most issues resolved |
| 50-79 | 🟡 Warning | Moderate risk, action needed |
| 0-49 | 🔴 Critical | High risk, immediate action required |

### Automatic Updates

The score recalculates automatically via database triggers when:
- A new vulnerability is detected (INSERT)
- A vulnerability status changes (UPDATE)
- A vulnerability is removed (DELETE)

---

## Security Scanner

The scanner combines AI analysis with **real-time NVD CVE data** for enhanced accuracy:

### How NVD Integration Works

1. **AI Analysis**: The scanner uses Gemini 2.5 Flash to identify vulnerability patterns in your code
2. **NVD Lookup**: Detected patterns trigger queries to the National Vulnerability Database API
3. **CVE Matching**: NVD results are matched to your findings using CWE weaknesses and keywords
4. **Enhancement**: Matched vulnerabilities get real CVE IDs, CVSS scores, and severity ratings
5. **Intelligence**: Additional relevant CVEs are added as "NVD Intelligence" alerts

### 1. Code Scanner
Analyzes code snippets for vulnerabilities.

**AI Detection**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Insecure Deserialization
- Hardcoded Secrets
- Weak Cryptography

**NVD Enhancement**: Detected patterns are cross-referenced with recent CVEs (last 90 days).

**Usage**: Paste code into the scanner with "Code" tab selected.

### 2. Dependency Scanner
Analyzes package.json or dependency lists.

**AI Detection**:
- Known vulnerable packages
- Outdated dependencies
- Deprecated packages
- License issues

**NVD Enhancement**: Package vulnerability patterns trigger NVD lookups for relevant CVEs.

**Usage**: Paste package.json content with "Dependencies" tab selected.

### 3. LLM Shield (Prompt Protection)
Detects prompt injection and malicious inputs.

**Detects**:
- Prompt injection attempts
- Jailbreak patterns
- Role manipulation
- Instruction override attempts
- Data exfiltration attempts

**NVD**: No NVD integration (prompt injection lacks established CVE patterns).

**Usage**: Paste prompts/inputs with "LLM Shield" tab selected.

---

## Database Schema

### Tables

#### `vulnerabilities`
Stores all detected security issues.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| name | TEXT | Vulnerability name |
| description | TEXT | Detailed description |
| severity | TEXT | critical, high, medium, low, info |
| category | TEXT | Vulnerability category (XSS, SQLi, etc.) |
| status | TEXT | detected, analyzing, resolved, false_positive |
| location | TEXT | Where the vulnerability was found |
| remediation | TEXT | How to fix it |
| cve_id | TEXT | CVE identifier if applicable |
| cvss_score | NUMERIC | CVSS score if applicable |
| notes | TEXT | User notes/comments |
| scan_id | UUID | Reference to the scan that found it |
| created_at | TIMESTAMP | When detected |
| resolved_at | TIMESTAMP | When resolved |

#### `security_stats`
Stores dashboard metrics.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| metric_name | TEXT | threats_blocked, vulnerabilities_fixed, avg_response_time_ms, security_score |
| metric_value | NUMERIC | Current value |
| previous_value | NUMERIC | Previous value (for % change) |
| updated_at | TIMESTAMP | Last update time |

#### `security_scans`
Stores scan history.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| scan_type | TEXT | code, dependency, llm_protection |
| target | TEXT | What was scanned |
| status | TEXT | pending, running, completed, failed |
| metadata | JSONB | Additional scan data |
| created_at | TIMESTAMP | Scan start time |
| completed_at | TIMESTAMP | Scan end time |

#### `chat_sessions`
Stores agent conversation history.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| user_id | UUID | Owner of the session |
| agent_mode | TEXT | sentinel, codex, aegis, assist |
| messages | JSONB | Full conversation history |
| preview | TEXT | Last message preview |
| created_at | TIMESTAMP | Session creation time |
| updated_at | TIMESTAMP | Last activity |

#### `profiles`
Stores user profile data.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| user_id | UUID | Auth user reference |
| email | TEXT | User email |
| display_name | TEXT | Display name |
| avatar_url | TEXT | Profile image URL |

### Database Functions

#### `recalculate_security_score()`
Automatically recalculates the security score based on current vulnerability data.

Triggered by:
- INSERT on vulnerabilities
- UPDATE on vulnerabilities  
- DELETE on vulnerabilities

---

## Authentication

### Authentication Flow

1. **Sign Up**: Email/password registration
2. **Email Confirmation**: Auto-confirmed (no email verification required in development)
3. **Sign In**: Email/password login
4. **Session**: JWT-based session management via Supabase Auth

### Protected Routes

- `/dashboard` - Requires authentication
- `/agent` - Requires authentication
- All agent features require login

### Profile Creation

User profiles are automatically created on signup via database trigger (`handle_new_user`).

---

## Technology Stack

### Frontend
| Technology | Purpose |
|------------|---------|
| React 18 | UI framework |
| TypeScript | Type safety |
| Vite | Build tool |
| Tailwind CSS | Styling |
| shadcn/ui | Component library |
| React Router | Navigation |
| TanStack Query | Data fetching |
| Recharts | Charts/visualization |

### Backend
| Technology | Purpose |
|------------|---------|
| Supabase (Lovable Cloud) | Backend-as-a-Service |
| PostgreSQL | Database |
| Edge Functions (Deno) | Serverless functions |
| Row Level Security | Data protection |

### AI Integration
| Model | Provider | Used By |
|-------|----------|---------|
| gemini-2.5-flash | Google (via Lovable AI) | SENTINEL, ASSIST agents |
| gpt-5 | OpenAI (via Lovable AI) | CODEX, AEGIS agents |

### AI Gateway
All AI requests go through the Lovable AI Gateway:
```
https://ai.gateway.lovable.dev/v1/chat/completions
```

This provides:
- Unified API for multiple models
- Automatic key management
- Rate limiting
- Usage tracking

---

## Getting Started

### Prerequisites
- Node.js 18+
- npm or bun

### Installation

```bash
# Clone the repository
git clone <repository-url>

# Install dependencies
npm install

# Start development server
npm run dev
```

### Environment Variables

The following are auto-configured by Lovable Cloud:
- `VITE_SUPABASE_URL` - Supabase project URL
- `VITE_SUPABASE_PUBLISHABLE_KEY` - Public API key

For edge functions (auto-configured):
- `LOVABLE_API_KEY` - AI Gateway authentication
- `SUPABASE_URL` - Internal Supabase URL
- `SUPABASE_SERVICE_ROLE_KEY` - Service role key

Optional for enhanced NVD rate limits:
- `NVD_API_KEY` - National Vulnerability Database API key (get free at https://nvd.nist.gov/developers/request-an-api-key)

---

## API Reference

### Edge Functions

#### `POST /functions/v1/code-scanner`
Scans code, dependencies, or prompts for security issues.

**Request Body**:
```json
{
  "scanType": "code" | "dependency" | "llm_protection",
  "code": "string (for code scans)",
  "dependencies": "string (for dependency scans)",
  "prompt": "string (for LLM protection scans)"
}
```

**Response**:
```json
{
  "success": true,
  "vulnerabilities": 5,
  "nvdCVEsAdded": 3,
  "analysisTime": 4523,
  "results": [
    {
      "name": "SQL Injection",
      "severity": "critical",
      "description": "User input directly concatenated into SQL query [Related: CVE-2024-12345]",
      "cve_id": "CVE-2024-12345",
      "cvss_score": 9.8,
      "auto_fix": "...",
      "source": "ai_analysis"
    },
    {
      "name": "NVD Alert: CVE-2024-67890",
      "severity": "high",
      "description": "SQL injection vulnerability in...",
      "cve_id": "CVE-2024-67890",
      "cvss_score": 8.1,
      "source": "nvd_intelligence"
    }
  ]
}
```

#### `POST /functions/v1/nvd-cve-lookup`
Direct CVE lookup from National Vulnerability Database.

**Request Body**:
```json
{
  "keyword": "SQL injection",
  "severity": "critical",
  "limit": 10
}
```

**Response**:
```json
{
  "success": true,
  "cves": [
    {
      "cve_id": "CVE-2024-12345",
      "description": "...",
      "severity": "critical",
      "cvss_score": 9.8,
      "weaknesses": ["CWE-89"],
      "references": ["https://..."]
    }
  ],
  "total": 42
}
```

#### `POST /functions/v1/security-agent`
Streams AI agent responses.

**Request Body**:
```json
{
  "messages": [
    { "role": "user", "content": "..." }
  ],
  "agentMode": "sentinel" | "codex" | "aegis" | "assist"
}
```

**Response**: Server-Sent Events (SSE) stream

---

## Export Features

### CSV Export
Exports vulnerability data as comma-separated values with columns:
- Name, Severity, Category, Status, Description, Location, CVE ID, CVSS Score, Remediation, Notes, Created At, Resolved At

### JSON Export
Exports full report including:
- Generation timestamp
- Summary statistics (by severity, by status)
- Current security score
- Complete vulnerability details

---

## Security Considerations

### Row Level Security (RLS)
All tables have RLS policies:
- `profiles`: Users can only access their own profile
- `chat_sessions`: Users can only access their own sessions
- `vulnerabilities`: Public read/write for demo purposes
- `security_stats`: Public read/write for demo purposes
- `security_scans`: Public read/write for demo purposes

### Production Recommendations
1. Restrict vulnerability/scan tables to authenticated users
2. Add rate limiting on scanner endpoints
3. Implement API key rotation
4. Add audit logging
5. Integrate real-time threat intelligence feeds

---

## How can I edit this code?

**Use Lovable**

Simply visit the [Lovable Project](https://lovable.dev/projects/REPLACE_WITH_PROJECT_ID) and start prompting.

**Use your preferred IDE**

```sh
# Clone the repository
git clone <YOUR_GIT_URL>

# Navigate to the project directory
cd <YOUR_PROJECT_NAME>

# Install dependencies
npm i

# Start the development server
npm run dev
```

## How can I deploy this project?

Simply open [Lovable](https://lovable.dev/projects/REPLACE_WITH_PROJECT_ID) and click on Share -> Publish.

---

## License

MIT License - See LICENSE file for details.

---

<p align="center">
  Built with ❤️ using Lovable
</p>
