import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface GitHubFile {
  name: string;
  path: string;
  type: 'file' | 'dir';
  download_url: string | null;
  size: number;
}

interface ScanResult {
  file: string;
  vulnerabilities: Array<{
    name: string;
    description: string;
    severity: string;
    category: string;
    location: string;
    remediation: string;
    cve_id?: string;
    cvss_score?: number;
  }>;
}

// Supported file extensions for scanning
const SCANNABLE_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.c', '.cpp', '.cs', '.go',
  '.rb', '.php', '.rs', '.swift', '.kt', '.vue', '.svelte', '.html', '.sql',
  '.sh', '.yml', '.yaml', '.json', '.xml', '.env', '.config', '.conf'
];

// Helper to extract user_id from JWT token
async function getUserIdFromRequest(req: Request): Promise<string | null> {
  const authHeader = req.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  const token = authHeader.replace('Bearer ', '');
  const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY') || '';
  
  if (token === supabaseAnonKey) {
    return null;
  }
  
  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, serviceKey);
    
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) {
      return null;
    }
    return user.id;
  } catch (e) {
    console.error("Error validating user token:", e);
    return null;
  }
}

// Parse GitHub repo URL to extract owner and repo
function parseGitHubUrl(url: string): { owner: string; repo: string; branch?: string } | null {
  try {
    // Handle various GitHub URL formats
    const patterns = [
      /github\.com\/([^\/]+)\/([^\/\#\?]+)/,
      /github\.com:([^\/]+)\/([^\/\#\?]+)/,
    ];
    
    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) {
        const owner = match[1];
        let repo = match[2].replace('.git', '');
        
        // Extract branch if present in URL
        const branchMatch = url.match(/\/tree\/([^\/]+)/);
        const branch = branchMatch ? branchMatch[1] : undefined;
        
        return { owner, repo, branch };
      }
    }
    
    return null;
  } catch (e) {
    console.error("Error parsing GitHub URL:", e);
    return null;
  }
}

// Fetch repository files recursively
async function fetchRepoFiles(
  owner: string, 
  repo: string, 
  path: string = '', 
  branch: string = 'main',
  maxFiles: number = 50
): Promise<GitHubFile[]> {
  const files: GitHubFile[] = [];
  const GITHUB_TOKEN = Deno.env.get('GITHUB_TOKEN');
  
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'AEGIS-Security-Scanner/1.0',
  };
  
  if (GITHUB_TOKEN) {
    headers['Authorization'] = `token ${GITHUB_TOKEN}`;
  }
  
  try {
    // Try main first, then master
    const branches = branch ? [branch] : ['main', 'master'];
    let response: Response | null = null;
    
    for (const b of branches) {
      const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${b}`;
      console.log(`Fetching: ${url}`);
      
      response = await fetch(url, { headers });
      
      if (response.ok) {
        break;
      }
    }
    
    if (!response || !response.ok) {
      console.error(`Failed to fetch repo contents: ${response?.status}`);
      return files;
    }
    
    const contents = await response.json();
    
    if (!Array.isArray(contents)) {
      // Single file
      if (contents.type === 'file' && contents.download_url) {
        files.push(contents);
      }
      return files;
    }
    
    for (const item of contents) {
      if (files.length >= maxFiles) break;
      
      if (item.type === 'file') {
        // Check if file is scannable
        const ext = '.' + item.name.split('.').pop()?.toLowerCase();
        if (SCANNABLE_EXTENSIONS.includes(ext) && item.size < 100000) { // 100KB max
          files.push(item);
        }
      } else if (item.type === 'dir') {
        // Skip common non-code directories
        const skipDirs = ['node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__', '.next', '.venv'];
        if (!skipDirs.includes(item.name)) {
          const subFiles = await fetchRepoFiles(owner, repo, item.path, branch, maxFiles - files.length);
          files.push(...subFiles);
        }
      }
    }
    
    return files;
  } catch (error) {
    console.error("Error fetching repo files:", error);
    return files;
  }
}

// Fetch file content
async function fetchFileContent(downloadUrl: string): Promise<string | null> {
  try {
    const response = await fetch(downloadUrl);
    if (response.ok) {
      return await response.text();
    }
    return null;
  } catch (error) {
    console.error("Error fetching file content:", error);
    return null;
  }
}

// Analyze code with AI
async function analyzeCode(
  code: string, 
  filename: string,
  apiKey: string
): Promise<Array<{
  name: string;
  description: string;
  severity: string;
  category: string;
  location: string;
  remediation: string;
  cve_id?: string;
  cvss_score?: number;
}>> {
  const prompt = `You are an expert security code analyzer. Analyze the following code file for security vulnerabilities.

FILE: ${filename}
CODE:
\`\`\`
${code.substring(0, 15000)}
\`\`\`

Check for:
- SQL Injection, XSS, Command Injection
- Hardcoded credentials/secrets
- Path traversal, SSRF
- Authentication/Authorization issues
- Insecure configurations
- Dependency vulnerabilities (if package files)
- Any other security issues

Respond with ONLY a valid JSON array. If no vulnerabilities, return [].
Format:
[
  {
    "name": "Vulnerability Name",
    "description": "Brief description",
    "severity": "critical|high|medium|low|info",
    "category": "OWASP Category",
    "location": "Line or function",
    "remediation": "How to fix"
  }
]`;

  try {
    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "You are a security code analyzer. Respond with only valid JSON arrays." },
          { role: "user", content: prompt }
        ],
        temperature: 0.3,
      }),
    });

    if (!response.ok) {
      console.error(`AI analysis failed for ${filename}: ${response.status}`);
      return [];
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content || '[]';
    
    // Extract JSON from response
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    
    return [];
  } catch (error) {
    console.error(`Error analyzing ${filename}:`, error);
    return [];
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const userId = await getUserIdFromRequest(req);
    const isAuthenticated = !!userId;
    console.log(`GitHub scan - Authenticated: ${isAuthenticated}`);

    const { repoUrl, maxFiles = 30 } = await req.json();
    
    if (!repoUrl) {
      return new Response(
        JSON.stringify({ success: false, error: "Repository URL is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      throw new Error("LOVABLE_API_KEY is not configured");
    }

    // Parse GitHub URL
    const parsed = parseGitHubUrl(repoUrl);
    if (!parsed) {
      return new Response(
        JSON.stringify({ success: false, error: "Invalid GitHub repository URL" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`Scanning repository: ${parsed.owner}/${parsed.repo}`);

    // Fetch repository files
    const files = await fetchRepoFiles(parsed.owner, parsed.repo, '', parsed.branch, Math.min(maxFiles, 50));
    
    if (files.length === 0) {
      return new Response(
        JSON.stringify({ 
          success: false, 
          error: "No scannable files found in repository. Make sure the repository is public or provide a GitHub token." 
        }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`Found ${files.length} scannable files`);

    // Analyze each file
    const results: ScanResult[] = [];
    const allVulnerabilities: Array<{
      name: string;
      description: string;
      severity: string;
      category: string;
      location: string;
      remediation: string;
      cve_id?: string;
      cvss_score?: number;
    }> = [];

    for (const file of files) {
      if (!file.download_url) continue;
      
      console.log(`Analyzing: ${file.path}`);
      
      const content = await fetchFileContent(file.download_url);
      if (!content) continue;
      
      const vulnerabilities = await analyzeCode(content, file.path, LOVABLE_API_KEY);
      
      if (vulnerabilities.length > 0) {
        // Add file path to location
        const vulnsWithPath = vulnerabilities.map(v => ({
          ...v,
          location: `${file.path}: ${v.location}`,
        }));
        
        results.push({
          file: file.path,
          vulnerabilities: vulnsWithPath,
        });
        
        allVulnerabilities.push(...vulnsWithPath);
      }
      
      // Small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 200));
    }

    // Store vulnerabilities in database if authenticated
    if (isAuthenticated && allVulnerabilities.length > 0) {
      const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
      const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
      const supabase = createClient(supabaseUrl, serviceKey);
      
      // Create scan record
      const { data: scanData } = await supabase
        .from('security_scans')
        .insert({
          scan_type: 'code',
          target: `github:${parsed.owner}/${parsed.repo}`,
          status: 'completed',
          user_id: userId,
          metadata: {
            repository: repoUrl,
            filesScanned: files.length,
            vulnerabilitiesFound: allVulnerabilities.length,
          }
        })
        .select()
        .single();

      // Insert vulnerabilities
      if (scanData) {
        const vulnRecords = allVulnerabilities.map(v => ({
          name: v.name,
          description: v.description,
          severity: v.severity,
          category: v.category || 'Code Analysis',
          location: v.location,
          remediation: v.remediation,
          cve_id: v.cve_id || null,
          cvss_score: v.cvss_score || null,
          status: 'detected',
          scan_id: scanData.id,
          user_id: userId,
        }));

        await supabase.from('vulnerabilities').insert(vulnRecords);
      }
    }

    // Summary by severity
    const summary = {
      critical: allVulnerabilities.filter(v => v.severity === 'critical').length,
      high: allVulnerabilities.filter(v => v.severity === 'high').length,
      medium: allVulnerabilities.filter(v => v.severity === 'medium').length,
      low: allVulnerabilities.filter(v => v.severity === 'low').length,
      info: allVulnerabilities.filter(v => v.severity === 'info').length,
    };

    return new Response(
      JSON.stringify({
        success: true,
        repository: `${parsed.owner}/${parsed.repo}`,
        filesScanned: files.length,
        totalVulnerabilities: allVulnerabilities.length,
        summary,
        results,
        isDemo: !isAuthenticated,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error("GitHub scanner error:", error);
    return new Response(
      JSON.stringify({ success: false, error: error instanceof Error ? error.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
