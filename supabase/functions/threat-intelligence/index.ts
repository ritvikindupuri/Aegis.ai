import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface ThreatIntelRequest {
  type: 'full' | 'cves' | 'kev' | 'owasp' | 'cwe';
  keywords?: string[];
  limit?: number;
}

interface CVEData {
  cve_id: string;
  description: string;
  severity: string;
  cvss_score: number | null;
  published: string;
  weaknesses: string[];
}

interface KEVEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

// OWASP Top 10 2021 - Latest version
const OWASP_TOP_10_2021 = [
  {
    id: "A01:2021",
    name: "Broken Access Control",
    description: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.",
    cwe_list: ["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"],
    prevention: ["Deny by default", "Implement access control mechanisms once and reuse", "Enforce record ownership", "Disable web server directory listing", "Log access control failures and alert admins", "Rate limit API access", "Invalidate JWT tokens on logout"]
  },
  {
    id: "A02:2021",
    name: "Cryptographic Failures",
    description: "Failures related to cryptography which often lead to exposure of sensitive data. Previously known as Sensitive Data Exposure.",
    cwe_list: ["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916"],
    prevention: ["Classify data processed/stored/transmitted", "Don't store sensitive data unnecessarily", "Encrypt all sensitive data at rest", "Use strong standard algorithms and keys", "Encrypt data in transit with TLS", "Disable caching for sensitive data", "Store passwords using strong salted hashing functions"]
  },
  {
    id: "A03:2021",
    name: "Injection",
    description: "Injection flaws such as SQL, NoSQL, OS, LDAP, and XPath injection occur when untrusted data is sent to an interpreter as part of a command or query.",
    cwe_list: ["CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917"],
    prevention: ["Use parameterized queries", "Use positive server-side input validation", "Escape special characters", "Use LIMIT and other SQL controls to prevent mass disclosure", "Use ORMs carefully - they can still be vulnerable"]
  },
  {
    id: "A04:2021",
    name: "Insecure Design",
    description: "Insecure design is a broad category representing different weaknesses, expressed as missing or ineffective control design.",
    cwe_list: ["CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"],
    prevention: ["Establish secure development lifecycle", "Use threat modeling", "Integrate security in all phases of development", "Implement unit and integration tests for critical flows", "Segregate tenant data", "Limit resource consumption per user"]
  },
  {
    id: "A05:2021",
    name: "Security Misconfiguration",
    description: "The application might be vulnerable if it is missing appropriate security hardening across any part of the application stack or has improperly configured permissions.",
    cwe_list: ["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"],
    prevention: ["Minimal platform without unnecessary features", "Review and update configurations", "Segmented application architecture", "Send security directives to clients", "Automated verification of configurations"]
  },
  {
    id: "A06:2021",
    name: "Vulnerable and Outdated Components",
    description: "Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, it can facilitate serious data loss or server takeover.",
    cwe_list: ["CWE-829", "CWE-1035", "CWE-1104"],
    prevention: ["Remove unused dependencies", "Continuously inventory component versions", "Monitor CVE and NVD for vulnerabilities", "Only obtain components from official sources", "Monitor for unmaintained libraries"]
  },
  {
    id: "A07:2021",
    name: "Identification and Authentication Failures",
    description: "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
    cwe_list: ["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"],
    prevention: ["Implement multi-factor authentication", "Don't ship with default credentials", "Implement weak password checks", "Use server-side session manager", "Invalidate sessions on logout"]
  },
  {
    id: "A08:2021",
    name: "Software and Data Integrity Failures",
    description: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
    cwe_list: ["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-913"],
    prevention: ["Verify software/data is from expected source", "Use digital signatures", "Review code and configuration changes", "Ensure CI/CD pipeline has proper segregation", "Don't deserialize untrusted data"]
  },
  {
    id: "A09:2021",
    name: "Security Logging and Monitoring Failures",
    description: "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time.",
    cwe_list: ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
    prevention: ["Log all login, access control, and server-side input validation failures", "Ensure logs are in format consumable by log management solutions", "Ensure high-value transactions have audit trail", "Establish effective monitoring and alerting"]
  },
  {
    id: "A10:2021",
    name: "Server-Side Request Forgery (SSRF)",
    description: "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL.",
    cwe_list: ["CWE-918"],
    prevention: ["Segment remote resource access functionality", "Enforce URL schema, port, and destination", "Disable HTTP redirections", "Don't send raw responses to clients"]
  }
];

// OWASP LLM Top 10 2025 - Latest for AI applications
const OWASP_LLM_TOP_10_2025 = [
  {
    id: "LLM01:2025",
    name: "Prompt Injection",
    description: "Manipulating LLMs through crafted inputs to cause unintended actions. Direct injections overwrite system prompts, while indirect ones manipulate inputs from external sources.",
    prevention: ["Privilege control on LLM access", "Human approval for high-risk actions", "Segregate external content", "Define trust boundaries"]
  },
  {
    id: "LLM02:2025",
    name: "Sensitive Information Disclosure",
    description: "LLMs may inadvertently reveal confidential data through responses, leading to unauthorized data access, privacy violations, and security breaches.",
    prevention: ["Data sanitization", "Robust input validation", "Apply principle of least privilege", "User awareness training"]
  },
  {
    id: "LLM03:2025",
    name: "Supply Chain Vulnerabilities",
    description: "LLM supply chain vulnerabilities can affect training data, models, and deployment platforms. Risks include biased outcomes, security breaches, and system failures.",
    prevention: ["Vet data sources and suppliers", "Use vulnerability scanning", "Apply MLOps best practices", "Maintain updated inventory"]
  },
  {
    id: "LLM04:2025",
    name: "Data and Model Poisoning",
    description: "Occurs when pre-training, fine-tuning, or embedding data is manipulated to introduce vulnerabilities, backdoors, or biases.",
    prevention: ["Verify data source integrity", "Use sandboxing", "Implement adversarial robustness", "Continuous monitoring"]
  },
  {
    id: "LLM05:2025",
    name: "Improper Output Handling",
    description: "Occurs when LLM output is accepted without scrutiny, exposing backend systems. Misuse may lead to XSS, CSRF, SSRF, privilege escalation, or remote code execution.",
    prevention: ["Treat model as untrusted user", "Input validation on responses", "Follow OWASP guidelines for output encoding"]
  },
  {
    id: "LLM06:2025",
    name: "Excessive Agency",
    description: "LLM systems may undertake actions leading to unintended consequences. The issue arises from excessive functionality, permissions, or autonomy granted to the LLM.",
    prevention: ["Minimize LLM plugin/tool functions", "Minimize permissions", "Avoid open-ended functions", "Require human approval"]
  },
  {
    id: "LLM07:2025",
    name: "System Prompt Leakage",
    description: "LLM system prompts can contain sensitive information not intended for user exposure. Attackers can extract prompts to reveal internal logic or sensitive configurations.",
    prevention: ["Separate sensitive data from system prompts", "Apply defense in depth", "Rate limiting and monitoring", "Avoid sensitive info in prompts"]
  },
  {
    id: "LLM08:2025",
    name: "Vector and Embedding Weaknesses",
    description: "Vulnerabilities in how vectors and embeddings are generated, stored, or retrieved. Includes unauthorized access, manipulation, or inference attacks on RAG systems.",
    prevention: ["Access controls on vector databases", "Input validation for embeddings", "Monitor for anomalous queries", "Encryption at rest"]
  },
  {
    id: "LLM09:2025",
    name: "Misinformation",
    description: "LLMs can generate false or misleading information that appears credible, leading to security risks, reputational damage, and legal liability.",
    prevention: ["Use RAG for grounding", "Cross-verification", "Implement confidence scoring", "Risk communication to users"]
  },
  {
    id: "LLM10:2025",
    name: "Unbounded Consumption",
    description: "LLMs are vulnerable to attacks that consume excessive resources, leading to denial of service, economic impact, or degraded performance.",
    prevention: ["Rate limiting", "Input size limits", "Resource quotas", "Monitoring and alerting"]
  }
];

// Critical CWE categories for web application security
const CRITICAL_CWES = [
  { id: "CWE-79", name: "Cross-site Scripting (XSS)", severity: "high" },
  { id: "CWE-89", name: "SQL Injection", severity: "critical" },
  { id: "CWE-78", name: "OS Command Injection", severity: "critical" },
  { id: "CWE-22", name: "Path Traversal", severity: "high" },
  { id: "CWE-352", name: "Cross-Site Request Forgery (CSRF)", severity: "high" },
  { id: "CWE-287", name: "Improper Authentication", severity: "critical" },
  { id: "CWE-862", name: "Missing Authorization", severity: "high" },
  { id: "CWE-798", name: "Hardcoded Credentials", severity: "critical" },
  { id: "CWE-434", name: "Unrestricted Upload of Dangerous File Type", severity: "high" },
  { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)", severity: "high" },
  { id: "CWE-502", name: "Deserialization of Untrusted Data", severity: "critical" },
  { id: "CWE-611", name: "XXE (XML External Entity)", severity: "high" },
  { id: "CWE-94", name: "Code Injection", severity: "critical" },
  { id: "CWE-1321", name: "Prototype Pollution", severity: "high" },
  { id: "CWE-400", name: "Uncontrolled Resource Consumption", severity: "medium" },
  { id: "CWE-601", name: "Open Redirect", severity: "medium" },
  { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key", severity: "high" },
  { id: "CWE-732", name: "Incorrect Permission Assignment", severity: "high" },
  { id: "CWE-1236", name: "CSV Injection", severity: "medium" },
  { id: "CWE-942", name: "Overly Permissive CORS Policy", severity: "medium" }
];

// Fetch latest CVEs from NVD
async function fetchLatestCVEs(limit: number = 20): Promise<CVEData[]> {
  const cves: CVEData[] = [];
  const NVD_API_KEY = Deno.env.get("NVD_API_KEY");
  
  try {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const urlParams = new URLSearchParams({
      pubStartDate: sevenDaysAgo.toISOString(),
      pubEndDate: new Date().toISOString(),
      resultsPerPage: String(limit)
    });
    
    const headers: Record<string, string> = {
      "Accept": "application/json",
      "User-Agent": "AEGIS-Security-Platform/1.0"
    };
    
    if (NVD_API_KEY) {
      headers["apiKey"] = NVD_API_KEY;
    }
    
    const response = await fetch(`${NVD_API_BASE}?${urlParams.toString()}`, { headers });
    
    if (response.ok) {
      const data = await response.json();
      
      for (const vuln of (data.vulnerabilities || []).slice(0, limit)) {
        const cve = vuln.cve;
        const description = cve.descriptions?.find((d: { lang: string }) => d.lang === 'en')?.value || '';
        
        let cvssScore: number | null = null;
        let severity = 'medium';
        
        if (cve.metrics?.cvssMetricV31?.[0]) {
          cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
          severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity.toLowerCase();
        }
        
        const weaknesses: string[] = [];
        cve.weaknesses?.forEach((w: { description: Array<{ value: string }> }) => {
          w.description?.forEach((d: { value: string }) => {
            if (d.value && !d.value.includes('NVD-CWE')) {
              weaknesses.push(d.value);
            }
          });
        });
        
        cves.push({
          cve_id: cve.id,
          description: description.substring(0, 400),
          severity,
          cvss_score: cvssScore,
          published: cve.published,
          weaknesses
        });
      }
    }
  } catch (error) {
    console.error("Failed to fetch CVEs from NVD:", error);
  }
  
  return cves;
}

// Fetch Critical CVEs from NVD
async function fetchCriticalCVEs(limit: number = 10): Promise<CVEData[]> {
  const cves: CVEData[] = [];
  const NVD_API_KEY = Deno.env.get("NVD_API_KEY");
  
  try {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const urlParams = new URLSearchParams({
      pubStartDate: thirtyDaysAgo.toISOString(),
      pubEndDate: new Date().toISOString(),
      cvssV3Severity: 'CRITICAL',
      resultsPerPage: String(limit)
    });
    
    const headers: Record<string, string> = {
      "Accept": "application/json",
      "User-Agent": "AEGIS-Security-Platform/1.0"
    };
    
    if (NVD_API_KEY) {
      headers["apiKey"] = NVD_API_KEY;
    }
    
    const response = await fetch(`${NVD_API_BASE}?${urlParams.toString()}`, { headers });
    
    if (response.ok) {
      const data = await response.json();
      
      for (const vuln of (data.vulnerabilities || []).slice(0, limit)) {
        const cve = vuln.cve;
        const description = cve.descriptions?.find((d: { lang: string }) => d.lang === 'en')?.value || '';
        
        let cvssScore: number | null = null;
        
        if (cve.metrics?.cvssMetricV31?.[0]) {
          cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
        }
        
        const weaknesses: string[] = [];
        cve.weaknesses?.forEach((w: { description: Array<{ value: string }> }) => {
          w.description?.forEach((d: { value: string }) => {
            if (d.value && !d.value.includes('NVD-CWE')) {
              weaknesses.push(d.value);
            }
          });
        });
        
        cves.push({
          cve_id: cve.id,
          description: description.substring(0, 400),
          severity: 'critical',
          cvss_score: cvssScore,
          published: cve.published,
          weaknesses
        });
      }
    }
  } catch (error) {
    console.error("Failed to fetch critical CVEs:", error);
  }
  
  return cves;
}

// Fetch CISA Known Exploited Vulnerabilities
async function fetchCISAKEV(): Promise<KEVEntry[]> {
  try {
    const response = await fetch(CISA_KEV_URL, {
      headers: { "Accept": "application/json" }
    });
    
    if (response.ok) {
      const data = await response.json();
      // Get most recent 25 entries
      return (data.vulnerabilities || [])
        .sort((a: KEVEntry, b: KEVEntry) => new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime())
        .slice(0, 25);
    }
  } catch (error) {
    console.error("Failed to fetch CISA KEV:", error);
  }
  
  return [];
}

// Build comprehensive threat context for AI prompts
function buildThreatContext(
  latestCVEs: CVEData[],
  criticalCVEs: CVEData[],
  kevEntries: KEVEntry[]
): string {
  let context = `\n\n=== REAL-TIME THREAT INTELLIGENCE (Updated: ${new Date().toISOString()}) ===\n\n`;
  
  // CISA Known Exploited Vulnerabilities
  if (kevEntries.length > 0) {
    context += `## CISA Known Exploited Vulnerabilities (Actively Exploited in the Wild)\n`;
    context += `These CVEs are currently being exploited by threat actors:\n`;
    kevEntries.slice(0, 10).forEach(kev => {
      context += `- **${kev.cveID}**: ${kev.vulnerabilityName} (${kev.vendorProject} ${kev.product})\n`;
      context += `  Added: ${kev.dateAdded} | Ransomware: ${kev.knownRansomwareCampaignUse}\n`;
      context += `  Action: ${kev.requiredAction}\n`;
    });
    context += '\n';
  }
  
  // Critical CVEs
  if (criticalCVEs.length > 0) {
    context += `## Critical CVEs (Last 30 Days, CVSS >= 9.0)\n`;
    criticalCVEs.forEach(cve => {
      context += `- **${cve.cve_id}** (CVSS: ${cve.cvss_score}): ${cve.description.substring(0, 200)}...\n`;
      if (cve.weaknesses.length > 0) {
        context += `  CWEs: ${cve.weaknesses.join(', ')}\n`;
      }
    });
    context += '\n';
  }
  
  // Latest CVEs
  if (latestCVEs.length > 0) {
    context += `## Latest CVEs (Last 7 Days)\n`;
    latestCVEs.slice(0, 10).forEach(cve => {
      context += `- **${cve.cve_id}** [${cve.severity.toUpperCase()}]: ${cve.description.substring(0, 150)}...\n`;
    });
    context += '\n';
  }
  
  // OWASP Top 10 2021
  context += `## OWASP Top 10 (2021)\n`;
  OWASP_TOP_10_2021.forEach(item => {
    context += `- **${item.id} - ${item.name}**: ${item.description.substring(0, 100)}...\n`;
  });
  context += '\n';
  
  // OWASP LLM Top 10 2025
  context += `## OWASP LLM Top 10 (2025) - AI/ML Security\n`;
  OWASP_LLM_TOP_10_2025.forEach(item => {
    context += `- **${item.id} - ${item.name}**: ${item.description.substring(0, 100)}...\n`;
  });
  context += '\n';
  
  // Critical CWEs
  context += `## Critical CWE Categories\n`;
  CRITICAL_CWES.slice(0, 15).forEach(cwe => {
    context += `- **${cwe.id}** [${cwe.severity.toUpperCase()}]: ${cwe.name}\n`;
  });
  
  return context;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { type = 'full', keywords = [], limit = 20 } = await req.json() as ThreatIntelRequest;
    
    console.log(`Threat intelligence request: ${type}, limit: ${limit}`);
    
    let response: any = {};
    
    if (type === 'full' || type === 'cves') {
      const [latestCVEs, criticalCVEs] = await Promise.all([
        fetchLatestCVEs(limit),
        fetchCriticalCVEs(Math.floor(limit / 2))
      ]);
      response.latestCVEs = latestCVEs;
      response.criticalCVEs = criticalCVEs;
    }
    
    if (type === 'full' || type === 'kev') {
      response.kevEntries = await fetchCISAKEV();
    }
    
    if (type === 'full' || type === 'owasp') {
      response.owaspTop10 = OWASP_TOP_10_2021;
      response.owaspLLMTop10 = OWASP_LLM_TOP_10_2025;
    }
    
    if (type === 'full' || type === 'cwe') {
      response.criticalCWEs = CRITICAL_CWES;
    }
    
    // Build context string for AI prompts
    if (type === 'full') {
      response.threatContext = buildThreatContext(
        response.latestCVEs || [],
        response.criticalCVEs || [],
        response.kevEntries || []
      );
    }
    
    response.timestamp = new Date().toISOString();
    response.success = true;
    
    console.log(`Threat intelligence gathered: ${response.latestCVEs?.length || 0} latest CVEs, ${response.criticalCVEs?.length || 0} critical CVEs, ${response.kevEntries?.length || 0} KEV entries`);
    
    return new Response(JSON.stringify(response), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
    
  } catch (error) {
    console.error("Threat intelligence error:", error);
    return new Response(JSON.stringify({ 
      success: false,
      error: error instanceof Error ? error.message : "Unknown error"
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
