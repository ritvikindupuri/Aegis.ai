# AEGIS.ai - AI-Native Security Platform

<p align="center">
  <strong>Enterprise-grade security analysis powered by specialized AI agents and real-time NVD intelligence.</strong>
</p>

---

## Overview

**AEGIS.ai** is an AI-native security platform designed to accelerate secure development. It combines the reasoning capabilities of generative AI with real-time threat intelligence to detect vulnerabilities, audit dependencies, and protect against LLM-based attacks (such as prompt injection).

Unlike static analysis tools, AEGIS.ai uses a multi-agent architecture to understand context, reducing false positives and providing actionable remediation steps.

### Key Capabilities
* **Context-Aware Code Scanning:** Detects logic flaws, XSS, SQLi, and insecure patterns using Gemini 2.5 Flash.
* **Real-Time NVD Integration:** Enriches findings with live CVE data, CVSS scores, and severity ratings from the National Vulnerability Database.
* **LLM Shield:** Specialized analysis to detect prompt injections, jailbreaks, and malicious inputs targeting AI models.
* **Dynamic Security Score:** Real-time scoring system (0-100) that penalizes for unresolved vulnerabilities and updates automatically.
* **Multi-Agent Support:** Four specialized AI agents for different security operations.

---

## 🏗️ Architecture & Data Flow

AEGIS.ai utilizes a modern, serverless architecture built on Supabase Edge Functions and the Lovable AI Gateway.

```mermaid
flowchart TB
    subgraph Frontend
        UI[User Interface]
        Dashboard[Security Dashboard]
        Scanner[Security Scanner]
    end

    subgraph Backend
        Edge[Edge Functions]
        DB[(PostgreSQL Database)]
    end

    subgraph Intelligence
        Gemini[Gemini 2.5 Flash]
        GPT5[GPT-5]
        NVD[NVD API Live CVEs]
    end

    UI --> Edge
    Scanner --> Edge
    Edge --> Gemini
    Edge --> GPT5
    Edge --> NVD
    Edge --> DB
    DB -.-> UI


### Data Flow

1. **User Scans Code** → `code-scanner` edge function
2. **AI Analysis** → Gemini 2.5 Flash identifies vulnerabilities
3. **NVD Enhancement** → Real CVE data fetched from National Vulnerability Database
4. **Database Update** → Vulnerabilities stored, triggers recalculate security score
5. **Dashboard Refresh** → Real-time updates via Supabase subscriptions

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
---

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

</p>
