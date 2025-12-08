import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { messages, mode } = await req.json();
    const AI_API_KEY = Deno.env.get("AI_API_KEY");
    const AI_API_URL = Deno.env.get("AI_API_URL") || "https://api.openai.com/v1/chat/completions";
    
    if (!AI_API_KEY) {
      throw new Error("AI_API_KEY is not configured");
    }

    const systemPrompts: Record<string, string> = {
      security: `You are SENTINEL, an elite AI security analyst specializing in application security, threat detection, and vulnerability assessment. You have extensive knowledge of:
- OWASP Top 10 vulnerabilities
- AI/ML security risks and LLM vulnerabilities
- Supply chain attacks and dependency scanning
- Container and cloud security
- Code review and static analysis
- Penetration testing methodologies

When analyzing security:
1. Identify potential vulnerabilities with severity ratings (Critical/High/Medium/Low)
2. Provide specific remediation steps
3. Reference relevant CVEs or security standards when applicable
4. Consider both AI-specific and traditional security vectors

Respond in a professional but accessible manner. Use markdown formatting with code blocks when showing examples. Be thorough but concise.`,

      code_review: `You are CODEX, an AI code security reviewer. Analyze code for:
- Injection vulnerabilities (SQL, XSS, Command)
- Authentication/Authorization flaws
- Sensitive data exposure
- Security misconfigurations
- Insecure dependencies
- AI-specific vulnerabilities (prompt injection, model manipulation)

Format findings as:
**[SEVERITY]** Finding Title
- Description
- Location/Impact
- Remediation

Be precise and actionable.`,

      threat_intel: `You are AEGIS, a threat intelligence AI. Provide insights on:
- Emerging attack vectors
- AI-powered threats
- Supply chain risks
- Industry-specific threats
- Mitigation strategies

Stay current with security trends and provide actionable intelligence.`,

      general: `You are an AI security assistant for an AI-native AppSec platform. Help users understand security concepts, analyze threats, and improve their security posture. Be helpful, professional, and thorough.`
    };

    const systemPrompt = systemPrompts[mode] || systemPrompts.general;

    // Use powerful model for deep analysis (CODEX, AEGIS), fast model for quick responses (SENTINEL, ASSIST)
    const modelMap: Record<string, string> = {
      security: Deno.env.get("AI_MODEL_FAST") || "gpt-4o-mini",      // SENTINEL - fast threat detection
      code_review: Deno.env.get("AI_MODEL_POWER") || "gpt-4o",       // CODEX - deep code analysis
      threat_intel: Deno.env.get("AI_MODEL_POWER") || "gpt-4o",      // AEGIS - comprehensive threat intel
      general: Deno.env.get("AI_MODEL_FAST") || "gpt-4o-mini",       // ASSIST - quick responses
    };

    const model = modelMap[mode] || (Deno.env.get("AI_MODEL_FAST") || "gpt-4o-mini");
    console.log(`Using model: ${model} for mode: ${mode}`);

    const response = await fetch(AI_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${AI_API_KEY}`,
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
      console.error("AI service error:", response.status, errorText);
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
