import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface ScheduledRepo {
  id: string;
  user_id: string;
  repo_url: string;
  email: string;
  last_scanned_at: string | null;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const supabase = createClient(supabaseUrl, serviceKey);

  try {
    console.log("Starting scheduled GitHub scan job...");

    // Get all notification preferences that have email configured
    const { data: preferences, error: prefError } = await supabase
      .from('notification_preferences')
      .select('user_id, email, notify_critical, notify_high')
      .or('notify_critical.eq.true,notify_high.eq.true');

    if (prefError) {
      console.error("Error fetching notification preferences:", prefError);
      throw prefError;
    }

    if (!preferences || preferences.length === 0) {
      console.log("No users with notification preferences configured");
      return new Response(
        JSON.stringify({ success: true, message: "No scheduled scans to run", scansRun: 0 }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`Found ${preferences.length} users with notification preferences`);

    // Get the most recent GitHub scan for each user
    const scanResults = [];

    for (const pref of preferences) {
      // Get the user's most recent GitHub scan
      const { data: recentScans, error: scanError } = await supabase
        .from('security_scans')
        .select('target, metadata')
        .eq('user_id', pref.user_id)
        .eq('scan_type', 'code')
        .like('target', 'github:%')
        .order('created_at', { ascending: false })
        .limit(1);

      if (scanError) {
        console.error(`Error fetching scans for user ${pref.user_id}:`, scanError);
        continue;
      }

      if (!recentScans || recentScans.length === 0) {
        console.log(`No GitHub scans found for user ${pref.user_id}`);
        continue;
      }

      const lastScan = recentScans[0];
      const repoUrl = (lastScan.metadata as any)?.repository;

      if (!repoUrl) {
        console.log(`No repository URL found in scan metadata for user ${pref.user_id}`);
        continue;
      }

      console.log(`Running scheduled scan for ${repoUrl} (user: ${pref.user_id})`);

      // Call the GitHub scanner
      try {
        const scanResponse = await fetch(`${supabaseUrl}/functions/v1/github-scanner`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${serviceKey}`,
          },
          body: JSON.stringify({ 
            repoUrl, 
            maxFiles: 50,
            userId: pref.user_id // Pass user ID for attribution
          }),
        });

        const scanData = await scanResponse.json();

        if (scanData.success) {
          console.log(`Scan completed for ${repoUrl}: ${scanData.totalVulnerabilities} vulnerabilities found`);

          // Check if we need to send an alert
          const hasCritical = scanData.summary?.critical > 0;
          const hasHigh = scanData.summary?.high > 0;

          if ((pref.notify_critical && hasCritical) || (pref.notify_high && hasHigh)) {
            // Send alert email
            const alertResponse = await fetch(`${supabaseUrl}/functions/v1/send-vulnerability-alert`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${serviceKey}`,
              },
              body: JSON.stringify({
                email: pref.email,
                repository: scanData.repository,
                vulnerabilities: scanData.results?.flatMap((r: any) => r.vulnerabilities) || [],
                scanSummary: {
                  critical: scanData.summary?.critical || 0,
                  high: scanData.summary?.high || 0,
                  medium: scanData.summary?.medium || 0,
                  low: scanData.summary?.low || 0,
                  filesScanned: scanData.filesScanned || 0,
                },
                isScheduledScan: true,
              }),
            });

            const alertData = await alertResponse.json();
            console.log(`Alert sent to ${pref.email}: ${alertData.success ? 'success' : 'failed'}`);
          }

          scanResults.push({
            userId: pref.user_id,
            repository: repoUrl,
            vulnerabilities: scanData.totalVulnerabilities,
            alertSent: (pref.notify_critical && hasCritical) || (pref.notify_high && hasHigh),
          });
        } else {
          console.error(`Scan failed for ${repoUrl}:`, scanData.error);
        }
      } catch (scanErr) {
        console.error(`Error scanning ${repoUrl}:`, scanErr);
      }

      // Small delay between scans to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    console.log(`Scheduled scan job completed. ${scanResults.length} scans run.`);

    return new Response(
      JSON.stringify({ 
        success: true, 
        scansRun: scanResults.length,
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
