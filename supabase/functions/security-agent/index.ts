import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");

// OWASP Top 10 2021 Summary for quick reference
const OWASP_TOP_10_SUMMARY = `
OWASP Top 10 (2021):
A01: Broken Access Control - Enforce permissions, deny by default
A02: Cryptographic Failures - Encrypt sensitive data, use strong algorithms
A03: Injection - Use parameterized queries, validate input
A04: Insecure Design - Threat modeling, secure architecture
A05: Security Misconfiguration - Minimal platform, update configs
A06: Vulnerable Components - Monitor dependencies, update regularly
A07: Auth Failures - MFA, strong sessions, no default creds
A08: Data Integrity Failures - Verify sources, sign code
A09: Logging Failures - Log security events, monitor actively
A10: SSRF - Validate URLs, segment networks`;

// OWASP LLM Top 10 2025 Summary
const OWASP_LLM_TOP_10_SUMMARY = `
OWASP LLM Top 10 (2025):
LLM01: Prompt Injection - Validate inputs, segregate content
LLM02: Sensitive Info Disclosure - Sanitize data, least privilege
LLM03: Supply Chain - Vet sources, scan for vulnerabilities
LLM04: Data Poisoning - Verify integrity, sandbox training
LLM05: Improper Output Handling - Validate LLM outputs, encode
LLM06: Excessive Agency - Minimize permissions, require approval
LLM07: System Prompt Leakage - Separate sensitive data
LLM08: Vector Weaknesses - Access controls on embeddings
LLM09: Misinformation - Use RAG, cross-verify
LLM10: Unbounded Consumption - Rate limit, monitor resources`;

// Critical CWEs for reference
const CRITICAL_CWES_SUMMARY = `
Critical CWE Categories:
CWE-79: XSS | CWE-89: SQL Injection | CWE-78: Command Injection
CWE-22: Path Traversal | CWE-352: CSRF | CWE-287: Auth Bypass
CWE-862: Missing AuthZ | CWE-798: Hardcoded Creds | CWE-434: File Upload
CWE-918: SSRF | CWE-502: Deserialization | CWE-611: XXE
CWE-94: Code Injection | CWE-1321: Prototype Pollution`;

// Fetch real-time threat intelligence
async function fetchThreatIntelligence(): Promise<string> {
  try {
    const response = await fetch(`${SUPABASE_URL}/functions/v1/threat-intelligence`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: 'full', limit: 15 })
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.success && data.threatContext) {
        return data.threatContext;
      }
    }
  } catch (error) {
    console.error("Failed to fetch threat intelligence:", error);
  }
  
  // Fallback to static context if fetch fails
  return `\n\n=== SECURITY INTELLIGENCE CONTEXT ===\n${OWASP_TOP_10_SUMMARY}\n${OWASP_LLM_TOP_10_SUMMARY}\n${CRITICAL_CWES_SUMMARY}`;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { messages, mode } = await req.json();
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    
    if (!LOVABLE_API_KEY) {
      throw new Error("LOVABLE_API_KEY is not configured");
    }

    // Fetch real-time threat intelligence for all agents
    console.log(`Fetching threat intelligence for mode: ${mode}`);
    const threatContext = await fetchThreatIntelligence();

    const systemPrompts: Record<string, string> = {
      security: `You are SENTINEL, an elite AI security analyst specializing in application security, threat detection, and vulnerability assessment. You have REAL-TIME access to the latest security intelligence.

Your expertise includes:
- OWASP Top 10 (2021) vulnerabilities and prevention
- OWASP LLM Top 10 (2025) for AI/ML security risks
- Current CVEs from the National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV) - actively exploited in the wild
- CWE (Common Weakness Enumeration) patterns
- Supply chain attacks and dependency scanning
- Container and cloud security
- Penetration testing methodologies

When analyzing security:
1. Identify vulnerabilities with severity ratings (Critical/High/Medium/Low)
2. Reference specific CVE IDs, CWE categories, or OWASP categories when applicable
3. Provide actionable remediation steps with code examples
4. Flag if a vulnerability matches a currently exploited CVE (KEV list)
5. Consider both AI-specific and traditional security vectors

${threatContext}

Respond professionally with markdown formatting. Be thorough but concise.`,

      code_review: `You are CODEX, an AI code security reviewer with REAL-TIME vulnerability intelligence. Analyze code for security issues using the latest CVE, CWE, and OWASP data.

Check for:
- Injection vulnerabilities (SQL, XSS, Command, NoSQL, LDAP)
- Authentication/Authorization flaws (CWE-287, CWE-862, CWE-863)
- Sensitive data exposure (CWE-200, CWE-312, CWE-319)
- Security misconfigurations (CWE-16, CWE-756)
- Insecure dependencies (match against recent CVEs)
- AI-specific vulnerabilities (prompt injection, model manipulation)
- Cryptographic failures (CWE-327, CWE-328, CWE-330)
- SSRF, XXE, deserialization issues

Format findings as:
**[SEVERITY]** Finding Title
- **CWE/CVE**: Reference if applicable
- **Description**: What the vulnerability is
- **Location**: Where in the code
- **Impact**: What could happen if exploited
- **Remediation**: Specific fix with code example

${threatContext}

Be precise and actionable. Flag any code patterns matching recent CVEs.`,

      threat_intel: `You are AEGIS, a threat intelligence AI with REAL-TIME access to:
- CISA Known Exploited Vulnerabilities (actively being attacked NOW)
- Latest CVEs from the National Vulnerability Database
- OWASP Top 10 (2021) and LLM Top 10 (2025) attack patterns
- Critical CWE categories and exploitation techniques

Provide insights on:
- Emerging attack vectors and techniques
- AI-powered threats and LLM vulnerabilities
- Supply chain risks and compromised packages
- Industry-specific threat actors and campaigns
- Practical mitigation strategies
- Zero-day and recently disclosed vulnerabilities

When discussing threats:
1. Reference specific CVE IDs when applicable
2. Note if threats are on the CISA KEV list (actively exploited)
3. Map threats to OWASP categories
4. Provide CVSS scores when available
5. Suggest immediate defensive actions

${threatContext}

Provide actionable intelligence with current threat data.`,

      general: `You are an AI security assistant for an AI-native AppSec platform with access to real-time security intelligence.

You can help users understand:
- Current CVEs and vulnerabilities from NVD
- CISA Known Exploited Vulnerabilities (what's being attacked now)
- OWASP Top 10 (2021) for web applications
- OWASP LLM Top 10 (2025) for AI security
- CWE categories and patterns
- Security best practices and remediation

${threatContext}

Be helpful, professional, and reference specific security standards when relevant.`
    };

    const systemPrompt = systemPrompts[mode] || systemPrompts.general;

    // Use GPT-5 for deep analysis (CODEX, AEGIS), Gemini Flash for fast responses (SENTINEL, ASSIST)
    const modelMap: Record<string, string> = {
      security: "google/gemini-2.5-flash",      // SENTINEL - fast threat detection
      code_review: "openai/gpt-5",              // CODEX - deep code analysis
      threat_intel: "openai/gpt-5",             // AEGIS - comprehensive threat intel
      general: "google/gemini-2.5-flash",       // ASSIST - quick responses
    };

    const model = modelMap[mode] || "google/gemini-2.5-flash";
    console.log(`Using model: ${model} for mode: ${mode}`);

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          ...messages,
        ],
        stream: true,
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limit exceeded. Please try again later." }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (response.status === 402) {
        return new Response(JSON.stringify({ error: "Payment required. Please add credits to continue." }), {
          status: 402,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const errorText = await response.text();
      console.error("AI gateway error:", response.status, errorText);
      return new Response(JSON.stringify({ error: "AI service error" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(response.body, {
      headers: { ...corsHeaders, "Content-Type": "text/event-stream" },
    });
  } catch (error) {
    console.error("Security agent error:", error);
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
