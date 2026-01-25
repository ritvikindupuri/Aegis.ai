import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const supabase = createClient(supabaseUrl, serviceKey);

  try {
    console.log("Starting scheduled GitHub scan job...");

    // Get all active scheduled scans
    const { data: scheduledScans, error: scanError } = await supabase
      .from('scheduled_scans')
      .select('*')
      .eq('is_active', true);

    if (scanError) {
      console.error("Error fetching scheduled scans:", scanError);
      throw scanError;
    }

    if (!scheduledScans || scheduledScans.length === 0) {
      console.log("No active scheduled scans configured");
      return new Response(
        JSON.stringify({ success: true, message: "No scheduled scans to run", scansRun: 0 }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`Found ${scheduledScans.length} active scheduled scans`);

    const scanResults = [];

    for (const scheduledScan of scheduledScans) {
      console.log(`Running scheduled scan for ${scheduledScan.repo_name} (user: ${scheduledScan.user_id})`);

      try {
        // Call the GitHub scanner
        const scanResponse = await fetch(`${supabaseUrl}/functions/v1/github-scanner`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${serviceKey}`,
          },
          body: JSON.stringify({ 
            repoUrl: scheduledScan.repo_url, 
            maxFiles: 50,
          }),
        });

        const scanData = await scanResponse.json();

        if (scanData.success) {
          console.log(`Scan completed for ${scheduledScan.repo_name}: ${scanData.totalVulnerabilities} vulnerabilities found`);

          // Update the scheduled scan with results
          await supabase
            .from('scheduled_scans')
            .update({
              last_scan_at: new Date().toISOString(),
              last_scan_result: {
                totalVulnerabilities: scanData.totalVulnerabilities,
                summary: scanData.summary,
                filesScanned: scanData.filesScanned,
              },
            })
            .eq('id', scheduledScan.id);

          // Also insert vulnerabilities for the user
          if (scanData.results && scanData.results.length > 0) {
            // Create a scan record
            const { data: newScanRecord } = await supabase
              .from('security_scans')
              .insert({
                scan_type: 'code',
                target: `github:${scheduledScan.repo_name}`,
                status: 'completed',
                user_id: scheduledScan.user_id,
                metadata: {
                  repository: scheduledScan.repo_url,
                  filesScanned: scanData.filesScanned,
                  vulnerabilitiesFound: scanData.totalVulnerabilities,
                  isScheduledScan: true,
                }
              })
              .select()
              .single();

            // Insert vulnerabilities
            if (newScanRecord) {
              const allVulns = scanData.results.flatMap((r: any) => 
                r.vulnerabilities.map((v: any) => ({
                  name: v.name,
                  description: v.description,
                  severity: v.severity,
                  category: v.category || 'Code Analysis',
                  location: v.location,
                  remediation: v.remediation,
                  cve_id: v.cve_id || null,
                  cvss_score: v.cvss_score || null,
                  status: 'detected',
                  scan_id: newScanRecord.id,
                  user_id: scheduledScan.user_id,
                }))
              );

              if (allVulns.length > 0) {
                await supabase.from('vulnerabilities').insert(allVulns);
              }
            }
          }

          scanResults.push({
            id: scheduledScan.id,
            repoName: scheduledScan.repo_name,
            vulnerabilities: scanData.totalVulnerabilities,
            success: true,
          });
        } else {
          console.error(`Scan failed for ${scheduledScan.repo_name}:`, scanData.error);
          scanResults.push({
            id: scheduledScan.id,
            repoName: scheduledScan.repo_name,
            error: scanData.error,
            success: false,
          });
        }
      } catch (scanErr) {
        console.error(`Error scanning ${scheduledScan.repo_name}:`, scanErr);
        scanResults.push({
          id: scheduledScan.id,
          repoName: scheduledScan.repo_name,
          error: scanErr instanceof Error ? scanErr.message : 'Unknown error',
          success: false,
        });
      }

      // Small delay between scans to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    const successCount = scanResults.filter(r => r.success).length;
    console.log(`Scheduled scan job completed. ${successCount}/${scanResults.length} scans successful.`);

    return new Response(
      JSON.stringify({ 
        success: true, 
        scansRun: scanResults.length,
        successCount,
        results: scanResults,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error("Scheduled scan error:", error);
    return new Response(
      JSON.stringify({ success: false, error: error instanceof Error ? error.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
