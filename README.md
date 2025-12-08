**AEGIS**.ai - AI-Native Security Platform

Enterprise-grade security analysis powered by specialized AI agents.

📋 Overview

**AEGIS**.ai is an AI-native security platform designed to accelerate secure development. It leverages a multi-agent architecture to provide real-time threat detection, automated vulnerability tracking, and intelligent security assistance. unlike traditional static analysis tools, **AEGIS** uses LLMs to understand code context, significantly reducing false positives.

### Key Capabilities

🛡️ Code Vulnerability Scanning: Context-aware static analysis for SQLi, **XSS**, and more.

📦 Dependency Auditing: Real-time **NVD** checks against package.json files.

🤖 **LLM** Protection (Prompt Shield): Detects jailbreaks and prompt injection attacks.

🧠 Specialized AI Agents: Four distinct personas for Triage, Auditing, Architecture, and Ops.

pw Dynamic Security Score: Real-time 0-**100** risk scoring based on unresolved vulnerabilities.

🏗️ Architecture

**AEGIS**.ai relies on a serverless, event-driven architecture powered by Supabase and Edge Functions.

graph TB
    subgraph *Frontend*
    UI[React + Vite UI]
    end

    subgraph *Backend (Supabase)*
    Auth[Authentication]
    DB[(PostgreSQL)]
    Edge[Edge Functions]
    end

    subgraph *AI Intelligence*
    Gateway[Lovable AI Gateway]
    Gemini[Gemini 2.5 Flash]
    **GPT5**[**GPT**-5]
    **NVD**[**NVD** **API**]
    end

    UI --> Edge
    Edge --> Gateway
    Gateway --> Gemini & **GPT5**
    Edge --> **NVD**
    Edge --> DB

✨ Features

## Intelligent Security Scanner

The scanner combines AI pattern recognition with real-time **NVD** data. It includes an Automated Quick Fix engine that generates code patches for detected issues.

## LLM Shield

A dedicated firewall for Generative AI inputs, capable of detecting sophisticated prompt injection and *jailbreak* attempts before they reach your models.

## Multi-Agent Ecosystem

**SENTINEL** (Gemini 2.5): Rapid triage and education.

**CODEX** (**GPT**-5): Deep code audits and logic analysis.

**AEGIS** (**GPT**-5): Strategic architecture and threat intel.

**ASSIST** (Gemini 2.5): General operational support.

## Dynamic Risk Scoring

A weighted scoring algorithm that adjusts in real-time as vulnerabilities are detected or resolved.

🛠️ Technology Stack

Frontend: React 18, TypeScript, Vite, Tailwind **CSS**, shadcn/ui

Backend: Supabase (PostgreSQL, Auth, Realtime)

Compute: Deno (Supabase Edge Functions)

AI Models: Google Gemini 2.5 Flash, OpenAI **GPT**-5

Data Source: **NIST** National Vulnerability Database (**NVD**)

🚀 Getting Started

Prerequisites

Node.js 18+

Supabase **CLI**

An active Supabase project

Installation

Clone the repository

git clone [https://github.com/yourusername/aegis-ai.git](https://github.com/yourusername/aegis-ai.git) cd aegis-ai

Install dependencies

npm install

### Environment Setup

Create a .env file in the root directory:

VITE_SUPABASE_URL=your_supabase_url VITE_SUPABASE_ANON_KEY=your_supabase_anon_key

### Start Development Server

npm run dev

### Database Setup

Run the **SQL** migrations located in supabase/migrations to set up the schema, **RLS** policies, and triggers.

📄 License

This project is proprietary and confidential.

Author: Ritvik Indupuri

Date: 12/8/**2025**
