import { useState } from 'react';
import { AlertTriangle, CheckCircle, Clock, TrendingUp, Activity, ChevronDown, ChevronRight, Loader2, Search, Code, FileJson, MessageSquare, Zap, X, Download, Shield, ExternalLink, RotateCcw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useSecurityData } from '@/hooks/useSecurityData';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { toast } from 'sonner';

type ScanType = 'code' | 'dependency' | 'llm_protection';
type StatusAction = 'resolved' | 'analyzing' | 'false_positive' | null;

interface StatusDialogState {
  isOpen: boolean;
  vulnId: string | null;
  vulnName: string | null;
  action: StatusAction;
  notes: string;
}

const ThreatDashboard = () => {
  const { stats, changes, scoreBreakdown, vulnerabilities, isLoading, updateVulnerabilityStatus, resetDashboard } = useSecurityData();
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [input, setInput] = useState('');
  const [scanType, setScanType] = useState<ScanType>('code');
  const [lastResults, setLastResults] = useState<any[]>([]);
  const [isUpdating, setIsUpdating] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [statusDialog, setStatusDialog] = useState<StatusDialogState>({
    isOpen: false,
    vulnId: null,
    vulnName: null,
    action: null,
    notes: ''
  });
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set());

  const handleReset = async () => {
    setIsResetting(true);
    const success = await resetDashboard();
    setIsResetting(false);
    if (success) {
      setLastResults([]);
      setExpandedVulns(new Set());
      toast.success('Dashboard reset successfully');
    } else {
      toast.error('Failed to reset dashboard');
    }
  };

  const toggleVulnExpanded = (id: string) => {
    setExpandedVulns(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const scanTypes = [
    { id: 'code' as const, label: 'Code', icon: Code, placeholder: 'Paste code to analyze for vulnerabilities...' },
    { id: 'dependency' as const, label: 'Dependencies', icon: FileJson, placeholder: 'Paste package.json or dependency list...' },
    { id: 'llm_protection' as const, label: 'LLM Shield', icon: MessageSquare, placeholder: 'Paste prompt or input to check for injection attacks...' },
  ];

  const runScan = async () => {
    if (!input.trim()) {
      toast.error('Please provide input to scan');
      return;
    }

    setIsScanning(true);
    setScanProgress(10);
    setLastResults([]);

    try {
      const progressInterval = setInterval(() => {
        setScanProgress(prev => Math.min(prev + Math.random() * 15, 85));
      }, 400);

      const body: any = { scanType };
      if (scanType === 'code') body.code = input;
      else if (scanType === 'dependency') body.dependencies = input;
      else if (scanType === 'llm_protection') body.prompt = input;

      const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/code-scanner`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        },
        body: JSON.stringify(body),
      });

      clearInterval(progressInterval);
      setScanProgress(100);

      const data = await response.json();

      if (data.success) {
        setLastResults(data.results || []);
        if (data.vulnerabilities === 0) {
          toast.success('No threats detected');
        } else {
          toast.warning(`Found ${data.vulnerabilities} potential issue${data.vulnerabilities > 1 ? 's' : ''}`);
        }
        setInput('');
      } else {
        toast.error(data.error || 'Scan failed');
      }
    } catch (error) {
      console.error('Scan error:', error);
      toast.error('Failed to run scan');
    } finally {
      setTimeout(() => {
        setIsScanning(false);
        setScanProgress(0);
      }, 500);
    }
  };

  const applyAutoFix = (fix: string) => {
    navigator.clipboard.writeText(fix);
    toast.success('Fix copied to clipboard');
  };

  const exportVulnerabilityReport = (format: 'csv' | 'json') => {
    if (vulnerabilities.length === 0) {
      toast.error('No vulnerabilities to export');
      return;
    }

    const timestamp = new Date().toISOString().split('T')[0];
    
    if (format === 'csv') {
      const headers = ['Name', 'Severity', 'Category', 'Status', 'Description', 'Location', 'CVE ID', 'CVSS Score', 'Remediation', 'Notes', 'Created At', 'Resolved At'];
      const rows = vulnerabilities.map(v => [
        v.name,
        v.severity,
        v.category,
        v.status,
        v.description || '',
        v.location || '',
        v.cve_id || '',
        v.cvss_score?.toString() || '',
        v.remediation || '',
        v.notes || '',
        v.created_at,
        v.resolved_at || ''
      ].map(field => `"${String(field).replace(/"/g, '""')}"`).join(','));
      
      const csv = [headers.join(','), ...rows].join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `vulnerability-report-${timestamp}.csv`;
      link.click();
      URL.revokeObjectURL(url);
      toast.success('CSV report downloaded');
    } else {
      const report = {
        generatedAt: new Date().toISOString(),
        summary: {
          total: vulnerabilities.length,
          bySeverity: {
            critical: vulnerabilities.filter(v => v.severity === 'critical').length,
            high: vulnerabilities.filter(v => v.severity === 'high').length,
            medium: vulnerabilities.filter(v => v.severity === 'medium').length,
            low: vulnerabilities.filter(v => v.severity === 'low').length,
          },
          byStatus: {
            detected: vulnerabilities.filter(v => v.status === 'detected').length,
            analyzing: vulnerabilities.filter(v => v.status === 'analyzing').length,
            resolved: vulnerabilities.filter(v => v.status === 'resolved').length,
            false_positive: vulnerabilities.filter(v => v.status === 'false_positive').length,
          },
          securityScore: stats.security_score,
        },
        vulnerabilities: vulnerabilities.map(v => ({
          name: v.name,
          severity: v.severity,
          category: v.category,
          status: v.status,
          description: v.description,
          location: v.location,
          cve_id: v.cve_id,
          cvss_score: v.cvss_score,
          remediation: v.remediation,
          notes: v.notes,
          created_at: v.created_at,
          resolved_at: v.resolved_at,
        })),
      };
      
      const json = JSON.stringify(report, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `vulnerability-report-${timestamp}.json`;
      link.click();
      URL.revokeObjectURL(url);
      toast.success('JSON report downloaded');
    }
  };

  const openStatusDialog = (vulnId: string, vulnName: string, action: StatusAction) => {
    setStatusDialog({
      isOpen: true,
      vulnId,
      vulnName,
      action,
      notes: ''
    });
  };

  const closeStatusDialog = () => {
    setStatusDialog({
      isOpen: false,
      vulnId: null,
      vulnName: null,
      action: null,
      notes: ''
    });
  };

  const handleStatusSubmit = async () => {
    if (!statusDialog.vulnId || !statusDialog.action) return;
    
    setIsUpdating(true);
    const success = await updateVulnerabilityStatus(statusDialog.vulnId, statusDialog.action, statusDialog.notes);
    setIsUpdating(false);
    
    if (success) {
      const statusLabels = { resolved: 'Resolved', analyzing: 'Analyzing', false_positive: 'False Positive' };
      toast.success(`Marked as ${statusLabels[statusDialog.action]}`, {
        description: statusDialog.notes || undefined
      });
      closeStatusDialog();
    } else {
      toast.error('Failed to update status');
    }
  };

  const getDialogContent = () => {
    switch (statusDialog.action) {
      case 'resolved':
        return {
          title: 'Mark as Resolved',
          description: 'Confirm that this vulnerability has been fixed.',
          placeholder: 'Describe what fix was applied (optional)...',
          buttonText: 'Confirm Resolved',
          buttonClass: 'bg-success hover:bg-success/90'
        };
      case 'analyzing':
        return {
          title: 'Mark as Analyzing',
          description: 'This vulnerability is currently being investigated.',
          placeholder: 'Add investigation notes (optional)...',
          buttonText: 'Start Analysis',
          buttonClass: 'bg-warning hover:bg-warning/90'
        };
      case 'false_positive':
        return {
          title: 'Mark as False Positive',
          description: 'Confirm this is not a real vulnerability.',
          placeholder: 'Explain why this is a false positive (required)...',
          buttonText: 'Confirm False Positive',
          buttonClass: ''
        };
      default:
        return { title: '', description: '', placeholder: '', buttonText: '', buttonClass: '' };
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return date.toLocaleDateString();
  };

  const severityConfig = {
    critical: { bg: 'bg-destructive/10', text: 'text-destructive', border: 'border-destructive/20' },
    high: { bg: 'bg-orange-500/10', text: 'text-orange-500', border: 'border-orange-500/20' },
    medium: { bg: 'bg-amber-500/10', text: 'text-amber-500', border: 'border-amber-500/20' },
    low: { bg: 'bg-primary/10', text: 'text-primary', border: 'border-primary/20' },
    info: { bg: 'bg-muted', text: 'text-muted-foreground', border: 'border-border' },
  };

  const statusIcons = {
    detected: AlertTriangle,
    analyzing: Activity,
    resolved: CheckCircle,
    false_positive: CheckCircle,
  };

  const statCards = [
    { label: 'Threats Detected', value: stats.threats_blocked.toLocaleString(), change: changes.threats_blocked, icon: AlertTriangle, color: 'text-destructive' },
    { label: 'Fixed', value: stats.vulnerabilities_fixed.toLocaleString(), change: changes.vulnerabilities_fixed, icon: CheckCircle, color: 'text-success' },
    { label: 'Response', value: `${stats.avg_response_time_ms}ms`, change: changes.avg_response_time_ms, icon: Clock, color: 'text-warning' },
    { label: 'Security Score', value: `${stats.security_score}`, change: changes.security_score, icon: TrendingUp, color: 'text-primary' },
  ];

  const currentScanType = scanTypes.find(s => s.id === scanType);

  const dialogContent = getDialogContent();

  return (
    <>
      {/* Status Action Dialog */}
      <Dialog open={statusDialog.isOpen} onOpenChange={(open) => !open && closeStatusDialog()}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{dialogContent.title}</DialogTitle>
            <DialogDescription>
              {statusDialog.vulnName && (
                <span className="font-medium text-foreground">{statusDialog.vulnName}</span>
              )}
              <br />
              {dialogContent.description}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="notes">Notes</Label>
              <Textarea
                id="notes"
                placeholder={dialogContent.placeholder}
                value={statusDialog.notes}
                onChange={(e) => setStatusDialog(prev => ({ ...prev, notes: e.target.value }))}
                className="min-h-[100px]"
              />
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={closeStatusDialog}>
              Cancel
            </Button>
            <Button 
              onClick={handleStatusSubmit}
              disabled={isUpdating || (statusDialog.action === 'false_positive' && !statusDialog.notes.trim())}
              className={dialogContent.buttonClass}
            >
              {isUpdating ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Updating...
                </>
              ) : (
                dialogContent.buttonText
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <section id="dashboard" className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h2 className="text-2xl font-semibold text-foreground mb-1">
            Security Dashboard
          </h2>
          <p className="text-sm text-muted-foreground">
            Real-time threat detection and vulnerability tracking
          </p>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-8">
          {statCards.map((stat) => (
            <div 
              key={stat.label} 
              className="p-4 rounded-lg border border-border bg-card"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5">
                  <stat.icon className={cn("w-4 h-4", stat.color)} />
                </div>
                <span className={cn(
                  'text-[10px] font-medium px-1.5 py-0.5 rounded',
                  stat.change.startsWith('+') ? 'text-success bg-success/10' : 
                  stat.change.startsWith('-') ? 'text-destructive bg-destructive/10' : 'text-muted-foreground bg-muted'
                )}>
                  {stat.change}
                </span>
              </div>
              <div className="text-xl font-semibold text-foreground">
                {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : stat.value}
              </div>
              <div className="text-xs text-muted-foreground">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Score Breakdown Panel */}
        <div className="mb-8 p-4 rounded-lg border border-border bg-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-medium text-foreground text-sm flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-primary" />
              Security Score Breakdown
            </h3>
            <span className={cn(
              'text-lg font-bold',
              stats.security_score >= 80 ? 'text-success' :
              stats.security_score >= 50 ? 'text-warning' : 'text-destructive'
            )}>
              {stats.security_score}/100
            </span>
          </div>
          
          {/* Visual progress bar */}
          <div className="mb-4">
            <div className="h-3 bg-muted rounded-full overflow-hidden">
              <div 
                className={cn(
                  "h-full transition-all duration-500 rounded-full",
                  stats.security_score >= 80 ? 'bg-success' :
                  stats.security_score >= 50 ? 'bg-warning' : 'bg-destructive'
                )}
                style={{ width: `${stats.security_score}%` }}
              />
            </div>
          </div>

          {/* Penalty Reference */}
          <div className="mb-4 p-3 rounded-lg bg-muted/30 border border-border">
            <div className="text-xs font-medium text-muted-foreground mb-2">Penalty Points Per Unresolved Vulnerability:</div>
            <div className="flex flex-wrap gap-3 text-xs font-mono">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-destructive"></span>
                <span className="text-destructive font-semibold">Critical: -15 pts</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                <span className="text-orange-500 font-semibold">High: -10 pts</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                <span className="text-amber-500 font-semibold">Medium: -5 pts</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-muted-foreground"></span>
                <span className="text-muted-foreground font-semibold">Low: -2 pts</span>
              </span>
            </div>
          </div>

          {/* Breakdown grid */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
            {/* Base calculation */}
            <div className="p-3 rounded-lg bg-muted/50">
              <div className="text-muted-foreground mb-1 font-medium">Step 1: Base Score</div>
              <div className="font-mono text-sm">
                <span className="text-foreground">(</span>
                <span className="text-success font-semibold">{scoreBreakdown.resolved}</span>
                <span className="text-muted-foreground"> / {scoreBreakdown.total}</span>
                <span className="text-foreground">) × 100</span>
              </div>
              <div className="text-[10px] text-muted-foreground mt-1">
                ({scoreBreakdown.resolved} resolved ÷ {scoreBreakdown.total} total)
              </div>
              <div className="text-primary font-bold text-lg mt-1">= {scoreBreakdown.baseScore.toFixed(1)}</div>
            </div>

            {/* Severity counts with multipliers */}
            <div className="p-3 rounded-lg bg-muted/50">
              <div className="text-muted-foreground mb-1 font-medium">Step 2: Count Unresolved</div>
              <div className="space-y-1 font-mono">
                <div className="flex justify-between items-center">
                  <span className="text-destructive">Critical:</span>
                  <span className="text-foreground font-semibold">{scoreBreakdown.critical} × 15 = <span className="text-destructive">-{scoreBreakdown.critical * 15}</span></span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-orange-500">High:</span>
                  <span className="text-foreground font-semibold">{scoreBreakdown.high} × 10 = <span className="text-destructive">-{scoreBreakdown.high * 10}</span></span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-amber-500">Medium:</span>
                  <span className="text-foreground font-semibold">{scoreBreakdown.medium} × 5 = <span className="text-destructive">-{scoreBreakdown.medium * 5}</span></span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-muted-foreground">Low:</span>
                  <span className="text-foreground font-semibold">{scoreBreakdown.low} × 2 = <span className="text-destructive">-{scoreBreakdown.low * 2}</span></span>
                </div>
              </div>
            </div>

            {/* Total Penalties */}
            <div className="p-3 rounded-lg bg-destructive/5 border border-destructive/20">
              <div className="text-muted-foreground mb-1 font-medium">Step 3: Sum Penalties</div>
              <div className="space-y-0.5 font-mono text-sm">
                {scoreBreakdown.critical > 0 && <div className="text-destructive">{scoreBreakdown.critical * 15}</div>}
                {scoreBreakdown.high > 0 && <div className="text-destructive">+ {scoreBreakdown.high * 10}</div>}
                {scoreBreakdown.medium > 0 && <div className="text-destructive">+ {scoreBreakdown.medium * 5}</div>}
                {scoreBreakdown.low > 0 && <div className="text-destructive">+ {scoreBreakdown.low * 2}</div>}
                {scoreBreakdown.penalty === 0 && <div className="text-success font-semibold">No penalties!</div>}
              </div>
              <div className="text-destructive font-bold text-lg mt-1 border-t border-destructive/20 pt-1">
                = -{scoreBreakdown.penalty} pts
              </div>
            </div>

            {/* Final calculation */}
            <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
              <div className="text-muted-foreground mb-1 font-medium">Step 4: Final Score</div>
              <div className="font-mono text-sm text-foreground space-y-1">
                <div>{scoreBreakdown.baseScore.toFixed(1)} − {scoreBreakdown.penalty} = {(scoreBreakdown.baseScore - scoreBreakdown.penalty).toFixed(1)}</div>
                {(scoreBreakdown.baseScore - scoreBreakdown.penalty) < 0 && (
                  <div className="text-xs text-muted-foreground">↳ Clamped to 0 (score cannot be negative)</div>
                )}
                {(scoreBreakdown.baseScore - scoreBreakdown.penalty) > 100 && (
                  <div className="text-xs text-muted-foreground">↳ Clamped to 100 (max score)</div>
                )}
              </div>
              <div className={cn(
                "text-2xl font-bold mt-1",
                stats.security_score >= 80 ? 'text-success' :
                stats.security_score >= 50 ? 'text-warning' : 'text-destructive'
              )}>
                = {Math.max(0, Math.min(100, Math.round(scoreBreakdown.baseScore - scoreBreakdown.penalty)))}
              </div>
              <div className="text-[10px] text-muted-foreground mt-1">
                {stats.security_score >= 80 ? '🟢 Good' : stats.security_score >= 50 ? '🟡 Warning' : '🔴 Critical'}
              </div>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Scanner panel */}
          <div className="rounded-lg border border-border bg-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-medium text-foreground text-sm">Security Scanner</h3>
              <span className={cn(
                'text-[10px] font-medium px-2 py-0.5 rounded',
                isScanning ? 'text-warning bg-warning/10' : 'text-success bg-success/10'
              )}>
                {isScanning ? 'Scanning' : 'Ready'}
              </span>
            </div>

            {/* Scan type selector */}
            <div className="flex gap-1 mb-4">
              {scanTypes.map((type) => (
                <button
                  key={type.id}
                  onClick={() => setScanType(type.id)}
                  disabled={isScanning}
                  className={cn(
                    'flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded text-xs font-medium transition-colors',
                    scanType === type.id
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted text-muted-foreground hover:text-foreground'
                  )}
                >
                  <type.icon className="w-3 h-3" />
                  {type.label}
                </button>
              ))}
            </div>

            {/* Input */}
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={currentScanType?.placeholder}
              className="w-full h-28 p-3 rounded-lg bg-muted border-0 text-foreground text-xs font-mono resize-none mb-3 focus:outline-none focus:ring-1 focus:ring-primary"
              disabled={isScanning}
            />

            {/* Progress */}
            {isScanning && (
              <div className="mb-3">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-muted-foreground">Analyzing...</span>
                  <span className="font-medium text-foreground">{Math.round(scanProgress)}%</span>
                </div>
                <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-primary transition-all duration-300 rounded-full"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
              </div>
            )}

            <Button
              onClick={runScan}
              disabled={isScanning || !input.trim()}
              size="sm"
              className="w-full"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-3 h-3 mr-1.5 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="w-3 h-3 mr-1.5" />
                  Run Scan
                </>
              )}
            </Button>

            {/* Auto-fix results */}
            {lastResults.length > 0 && (
              <div className="mt-4 pt-4 border-t border-border">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-xs font-medium text-foreground flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-warning" />
                    Quick Fixes Available
                  </h4>
                  <span className="text-[10px] text-muted-foreground bg-warning/10 text-warning px-1.5 py-0.5 rounded font-medium">
                    {lastResults.filter(r => r.auto_fix).length} fixes
                  </span>
                </div>
                <div className="space-y-3 max-h-48 overflow-y-auto">
                  {lastResults.filter(r => r.auto_fix).slice(0, 5).map((result, i) => (
                    <div
                      key={i}
                      className="rounded-lg border border-warning/30 bg-warning/5 overflow-hidden"
                    >
                      <div className="flex items-center justify-between px-3 py-2 bg-warning/10 border-b border-warning/20">
                        <div className="text-xs font-medium text-foreground truncate flex-1">{result.name}</div>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => applyAutoFix(result.auto_fix)}
                          className="h-6 px-2 text-[10px] text-warning hover:text-warning hover:bg-warning/20 ml-2"
                        >
                          Copy Fix
                        </Button>
                      </div>
                      <pre className="p-3 text-[10px] font-mono text-foreground/90 overflow-x-auto whitespace-pre-wrap break-all bg-muted/50">
                        {result.auto_fix}
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Vulnerability feed */}
          <div className="lg:col-span-2 rounded-lg border border-border bg-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-medium text-foreground text-sm">Vulnerability Feed</h3>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">
                  {vulnerabilities.length} total
                </span>
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="h-7 px-2 text-xs" 
                  onClick={handleReset}
                  disabled={isResetting || (vulnerabilities.length === 0 && stats.threats_blocked === 0)}
                >
                  {isResetting ? (
                    <Loader2 className="w-3 h-3 animate-spin" />
                  ) : (
                    <>
                      <RotateCcw className="w-3 h-3 mr-1" />
                      Reset
                    </>
                  )}
                </Button>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm" className="h-7 px-2 text-xs" disabled={vulnerabilities.length === 0}>
                      <Download className="w-3 h-3 mr-1" />
                      Export
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="bg-popover border border-border">
                    <DropdownMenuItem onClick={() => exportVulnerabilityReport('csv')}>
                      <FileJson className="w-3 h-3 mr-2" />
                      Export as CSV
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => exportVulnerabilityReport('json')}>
                      <Code className="w-3 h-3 mr-2" />
                      Export as JSON
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>

            <div className="space-y-2 max-h-[380px] overflow-y-auto">
              {isLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                </div>
              ) : vulnerabilities.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Search className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm font-medium">No vulnerabilities</p>
                  <p className="text-xs">Run a scan to analyze your code</p>
                </div>
              ) : (
                vulnerabilities.map((vuln) => {
                  const StatusIcon = statusIcons[vuln.status as keyof typeof statusIcons] || AlertTriangle;
                  const severity = severityConfig[vuln.severity as keyof typeof severityConfig] || severityConfig.info;
                  const statusLabels: Record<string, string> = { 
                    resolved: 'Resolved', 
                    analyzing: 'Analyzing', 
                    false_positive: 'False Positive',
                    detected: 'Detected'
                  };
                  const isExpanded = expandedVulns.has(vuln.id);
                  const hasDetails = vuln.description || vuln.remediation || vuln.location;
                  
                  return (
                    <div
                      key={vuln.id}
                      className="rounded-lg border border-border bg-background overflow-hidden"
                    >
                      {/* Main row */}
                      <div 
                        className={cn(
                          "p-3 flex items-center gap-3 transition-colors",
                          hasDetails && "cursor-pointer hover:bg-muted/30"
                        )}
                        onClick={() => hasDetails && toggleVulnExpanded(vuln.id)}
                      >
                        {/* Expand/collapse indicator */}
                        {hasDetails ? (
                          <div className="w-4 h-4 flex items-center justify-center flex-shrink-0">
                            {isExpanded ? (
                              <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
                            ) : (
                              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
                            )}
                          </div>
                        ) : (
                          <div className="w-4" />
                        )}
                        
                        <div className={cn(
                          'w-8 h-8 rounded flex items-center justify-center flex-shrink-0',
                          severity.bg
                        )}>
                          <AlertTriangle className={cn("w-4 h-4", severity.text)} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-foreground truncate">{vuln.name}</span>
                            {/* NVD Enriched Badge - only for real CVE IDs */}
                            {vuln.cve_id && vuln.cve_id !== 'N/A' && vuln.cve_id.startsWith('CVE-') && (
                              <span className="flex items-center gap-1 text-[9px] font-medium px-1.5 py-0.5 rounded bg-success/10 text-success border border-success/20">
                                <Shield className="w-2.5 h-2.5" />
                                NVD
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                            <span className={cn(
                              'text-[10px] font-medium px-1.5 py-0.5 rounded uppercase',
                              severity.bg, severity.text
                            )}>
                              {vuln.severity}
                            </span>
                            <span className="text-[10px] text-muted-foreground">{vuln.category}</span>
                            {vuln.cve_id && vuln.cve_id !== 'N/A' && (
                              vuln.cve_id.startsWith('CVE-') ? (
                                <a 
                                  href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  onClick={(e) => e.stopPropagation()}
                                  className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-primary/10 text-primary hover:bg-primary/20 transition-colors flex items-center gap-1"
                                >
                                  {vuln.cve_id}
                                  <ExternalLink className="w-2.5 h-2.5" />
                                </a>
                              ) : vuln.cve_id.startsWith('CWE-') ? (
                                <a 
                                  href={`https://cwe.mitre.org/data/definitions/${vuln.cve_id.replace('CWE-', '')}.html`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  onClick={(e) => e.stopPropagation()}
                                  className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 transition-colors flex items-center gap-1"
                                >
                                  {vuln.cve_id}
                                  <ExternalLink className="w-2.5 h-2.5" />
                                </a>
                              ) : (
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                                  {vuln.cve_id}
                                </span>
                              )
                            )}
                            {vuln.cvss_score !== null && (
                              <span className={cn(
                                'text-[10px] font-medium px-1.5 py-0.5 rounded',
                                vuln.cvss_score >= 9 ? 'bg-destructive/10 text-destructive' :
                                vuln.cvss_score >= 7 ? 'bg-warning/10 text-warning' :
                                vuln.cvss_score >= 4 ? 'bg-warning/10 text-warning/80' :
                                'bg-muted text-muted-foreground'
                              )}>
                                CVSS {vuln.cvss_score}
                              </span>
                            )}
                            <span className="text-[10px] text-muted-foreground">{formatTimestamp(vuln.created_at)}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                          {vuln.status !== 'detected' && (
                            <span className={cn(
                              'text-[10px] font-medium px-1.5 py-0.5 rounded',
                              vuln.status === 'resolved' ? 'bg-success/10 text-success' :
                              vuln.status === 'analyzing' ? 'bg-warning/10 text-warning' :
                              'bg-muted text-muted-foreground'
                            )}>
                              {statusLabels[vuln.status]}
                            </span>
                          )}
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-7 px-2">
                                <StatusIcon className={cn(
                                  "w-3 h-3",
                                  vuln.status === 'resolved' ? 'text-success' : 
                                  vuln.status === 'analyzing' ? 'text-warning' : 'text-muted-foreground'
                                )} />
                                <ChevronDown className="w-3 h-3 ml-1" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="bg-popover border border-border">
                              <DropdownMenuItem onClick={() => openStatusDialog(vuln.id, vuln.name, 'resolved')}>
                                <CheckCircle className="w-3 h-3 mr-2 text-success" />
                                Resolved
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => openStatusDialog(vuln.id, vuln.name, 'analyzing')}>
                                <Activity className="w-3 h-3 mr-2 text-warning" />
                                Analyzing
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => openStatusDialog(vuln.id, vuln.name, 'false_positive')}>
                                <CheckCircle className="w-3 h-3 mr-2 text-muted-foreground" />
                                False Positive
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </div>
                      
                      {/* Expandable details panel */}
                      {isExpanded && hasDetails && (
                        <div className="px-4 pb-4 pt-2 border-t border-border bg-muted/20 space-y-3">
                          {vuln.description && (
                            <div>
                              <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Description</div>
                              <p className="text-xs text-foreground leading-relaxed">{vuln.description}</p>
                            </div>
                          )}
                          
                          {vuln.location && (
                            <div>
                              <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Location</div>
                              <code className="text-xs font-mono text-foreground bg-muted px-2 py-1 rounded block">{vuln.location}</code>
                            </div>
                          )}
                          
                          {vuln.remediation && (
                            <div>
                              <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Remediation</div>
                              <div className="text-xs text-foreground leading-relaxed p-2 rounded bg-success/5 border border-success/20">
                                {vuln.remediation}
                              </div>
                            </div>
                          )}
                          
                          {vuln.cve_id && (
                            <div className="flex items-center gap-2 pt-1">
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline"
                              >
                                <Shield className="w-3 h-3" />
                                View full NVD details for {vuln.cve_id}
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            </div>
                          )}
                        </div>
                      )}
                      
                      {/* Show notes if present */}
                      {vuln.notes && !isExpanded && (
                        <div className="px-4 pb-3 text-xs text-muted-foreground italic border-t border-border pt-2">
                          "{vuln.notes}"
                        </div>
                      )}
                      {vuln.notes && isExpanded && (
                        <div className="px-4 pb-3 text-xs text-muted-foreground italic">
                          <span className="text-[10px] font-semibold uppercase tracking-wide block mb-1 not-italic">Notes</span>
                          "{vuln.notes}"
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>
      </section>
    </>
  );
};

export default ThreatDashboard;