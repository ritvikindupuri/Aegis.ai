import { useState, useEffect } from 'react';
import { Github, Plus, Trash2, Clock, CheckCircle, AlertTriangle, Loader2, Calendar, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';

interface ScheduledScan {
  id: string;
  repo_url: string;
  repo_name: string;
  is_active: boolean;
  last_scan_at: string | null;
  last_scan_result: {
    totalVulnerabilities?: number;
    summary?: {
      critical?: number;
      high?: number;
      medium?: number;
      low?: number;
    };
    filesScanned?: number;
  } | null;
  created_at: string;
}

const ScheduledScans = () => {
  const { user } = useAuth();
  const [scans, setScans] = useState<ScheduledScan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [newRepoUrl, setNewRepoUrl] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [runningScans, setRunningScans] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (user) {
      fetchScheduledScans();
    }
  }, [user]);

  const fetchScheduledScans = async () => {
    try {
      const { data, error } = await supabase
        .from('scheduled_scans')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      setScans((data as ScheduledScan[]) || []);
    } catch (error) {
      console.error('Error fetching scheduled scans:', error);
      toast.error('Failed to load scheduled scans');
    } finally {
      setIsLoading(false);
    }
  };

  const parseGitHubUrl = (url: string): { owner: string; repo: string } | null => {
    const match = url.match(/github\.com\/([^\/]+)\/([^\/\#\?]+)/);
    if (match) {
      return { owner: match[1], repo: match[2].replace('.git', '') };
    }
    return null;
  };

  const addScheduledScan = async () => {
    if (!newRepoUrl.trim()) {
      toast.error('Please enter a GitHub repository URL');
      return;
    }

    const parsed = parseGitHubUrl(newRepoUrl);
    if (!parsed) {
      toast.error('Invalid GitHub URL. Use format: https://github.com/owner/repo');
      return;
    }

    setIsAdding(true);
    try {
      const { error } = await supabase
        .from('scheduled_scans')
        .insert({
          user_id: user?.id,
          repo_url: newRepoUrl.trim(),
          repo_name: `${parsed.owner}/${parsed.repo}`,
          is_active: true,
        });

      if (error) {
        if (error.code === '23505') {
          toast.error('This repository is already in your scheduled scans');
        } else {
          throw error;
        }
      } else {
        toast.success(`Added ${parsed.owner}/${parsed.repo} to scheduled scans`);
        setNewRepoUrl('');
        fetchScheduledScans();
      }
    } catch (error) {
      console.error('Error adding scheduled scan:', error);
      toast.error('Failed to add scheduled scan');
    } finally {
      setIsAdding(false);
    }
  };

  const removeScheduledScan = async (id: string, repoName: string) => {
    try {
      const { error } = await supabase
        .from('scheduled_scans')
        .delete()
        .eq('id', id);

      if (error) throw error;
      toast.success(`Removed ${repoName} from scheduled scans`);
      setScans(scans.filter(s => s.id !== id));
    } catch (error) {
      console.error('Error removing scheduled scan:', error);
      toast.error('Failed to remove scheduled scan');
    }
  };

  const runScanNow = async (scan: ScheduledScan) => {
    setRunningScans(prev => new Set(prev).add(scan.id));
    
    try {
      const { data: { session } } = await supabase.auth.getSession();
      
      const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/github-scanner`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${session?.access_token}`,
        },
        body: JSON.stringify({ repoUrl: scan.repo_url, maxFiles: 50 }),
      });

      const data = await response.json();

      if (data.success) {
        // Update the scan record with results
        await supabase
          .from('scheduled_scans')
          .update({
            last_scan_at: new Date().toISOString(),
            last_scan_result: {
              totalVulnerabilities: data.totalVulnerabilities,
              summary: data.summary,
              filesScanned: data.filesScanned,
            },
          })
          .eq('id', scan.id);

        toast.success(`Scan complete: ${data.totalVulnerabilities} vulnerabilities found`);
        fetchScheduledScans();
      } else {
        toast.error(data.error || 'Scan failed');
      }
    } catch (error) {
      console.error('Error running scan:', error);
      toast.error('Failed to run scan');
    } finally {
      setRunningScans(prev => {
        const next = new Set(prev);
        next.delete(scan.id);
        return next;
      });
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    
    if (diffHours < 1) return 'Less than an hour ago';
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    return date.toLocaleDateString();
  };

  if (!user) return null;

  return (
    <div className="rounded-lg border border-border bg-card p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-primary" />
          <h3 className="font-medium text-foreground text-sm">Scheduled Scans</h3>
        </div>
        <span className="text-[10px] text-muted-foreground">Daily at 9:00 AM UTC</span>
      </div>

      {/* Add new repo */}
      <div className="flex gap-2 mb-4">
        <Input
          value={newRepoUrl}
          onChange={(e) => setNewRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          className="text-xs font-mono flex-1"
          disabled={isAdding}
          onKeyDown={(e) => e.key === 'Enter' && addScheduledScan()}
        />
        <Button
          size="sm"
          onClick={addScheduledScan}
          disabled={isAdding || !newRepoUrl.trim()}
          className="shrink-0"
        >
          {isAdding ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Plus className="w-4 h-4" />
          )}
        </Button>
      </div>

      {/* Scan list */}
      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
        </div>
      ) : scans.length === 0 ? (
        <div className="text-center py-8">
          <Github className="w-8 h-8 text-muted-foreground/50 mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">No scheduled scans yet</p>
          <p className="text-xs text-muted-foreground/70 mt-1">
            Add a GitHub repository to start daily security monitoring
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="p-3 rounded-lg bg-muted/30 border border-border hover:border-primary/20 transition-colors"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Github className="w-4 h-4 text-muted-foreground shrink-0" />
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-foreground truncate">
                      {scan.repo_name}
                    </p>
                    <p className="text-[10px] text-muted-foreground flex items-center gap-1 mt-0.5">
                      <Clock className="w-3 h-3" />
                      Last scan: {formatDate(scan.last_scan_at)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    onClick={() => runScanNow(scan)}
                    disabled={runningScans.has(scan.id)}
                    className="p-1.5 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground disabled:opacity-50"
                    title="Run scan now"
                  >
                    {runningScans.has(scan.id) ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <RefreshCw className="w-3.5 h-3.5" />
                    )}
                  </button>
                  <button
                    onClick={() => removeScheduledScan(scan.id, scan.repo_name)}
                    className="p-1.5 rounded hover:bg-destructive/10 transition-colors text-muted-foreground hover:text-destructive"
                    title="Remove from scheduled scans"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Last scan results */}
              {scan.last_scan_result && (
                <div className="mt-2 pt-2 border-t border-border">
                  <div className="flex items-center gap-2 flex-wrap">
                    {scan.last_scan_result.totalVulnerabilities === 0 ? (
                      <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-success/10 text-success">
                        <CheckCircle className="w-3 h-3" />
                        No issues
                      </span>
                    ) : (
                      <>
                        {(scan.last_scan_result.summary?.critical ?? 0) > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-destructive/10 text-destructive">
                            {scan.last_scan_result.summary?.critical} critical
                          </span>
                        )}
                        {(scan.last_scan_result.summary?.high ?? 0) > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-500">
                            {scan.last_scan_result.summary?.high} high
                          </span>
                        )}
                        {(scan.last_scan_result.summary?.medium ?? 0) > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-500">
                            {scan.last_scan_result.summary?.medium} medium
                          </span>
                        )}
                        {(scan.last_scan_result.summary?.low ?? 0) > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                            {scan.last_scan_result.summary?.low} low
                          </span>
                        )}
                      </>
                    )}
                    <span className="text-[10px] text-muted-foreground ml-auto">
                      {scan.last_scan_result.filesScanned} files scanned
                    </span>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <p className="text-[10px] text-muted-foreground mt-3 pt-3 border-t border-border">
        Repositories are automatically scanned daily. Results appear here and in your vulnerability dashboard.
      </p>
    </div>
  );
};

export default ScheduledScans;
