# AEGIS.ai - AI-Native Security Platform

<p align="center">
  <strong>Enterprise-grade security analysis powered by specialized AI agents and real-time NVD intelligence.</strong>
</p>

---

## 🛡️ Overview

**AEGIS.ai** is an AI-native security platform designed to accelerate secure development. It combines the reasoning capabilities of generative AI with real-time threat intelligence to detect vulnerabilities, audit dependencies, and protect against LLM-based attacks (such as prompt injection).

Unlike static analysis tools, AEGIS.ai uses a multi-agent architecture to understand context, reducing false positives and providing actionable remediation steps.

### Key Capabilities
* **Context-Aware Code Scanning:** Detects logic flaws, XSS, SQLi, and insecure patterns using Gemini 2.5 Flash.
* **Real-Time NVD Integration:** Enriches findings with live CVE data, CVSS scores, and severity ratings from the National Vulnerability Database.
* **LLM Shield:** Specialized analysis to detect prompt injections, jailbreaks, and malicious inputs targeting AI models.
* **Dynamic Security Score:** Real-time scoring system (0-100) that penalizes for unresolved vulnerabilities and updates automatically.
* **Multi-Agent Support:** Four specialized AI agents for different security operations.

---

## 🏗️ Architecture

AEGIS.ai utilizes a modern, serverless architecture built on Supabase Edge Functions and the Lovable AI Gateway.

```mermaid
graph TB
    subgraph "Frontend (React + Vite)"
        UI[User Interface]
        Dashboard[Security Dashboard]
        Scanner[Security Scanner]
    end

    subgraph "Backend (Supabase)"
        Edge[Edge Functions]
        DB[(PostgreSQL Database)]
    end

    subgraph "Intelligence Layer"
        Gemini[Gemini 2.5 Flash]
        GPT5[GPT-5]
        NVD[NVD API (Live CVEs)]
    end

    UI --> Edge
    Edge --> Gemini
    Edge --> GPT5
    Edge --> NVD
    Edge --> DB
    DB -.->|Realtime Subscriptions| UI
