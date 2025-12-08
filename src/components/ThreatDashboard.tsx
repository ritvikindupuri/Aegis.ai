import { useState } from 'react';
import { AlertTriangle, CheckCircle, Clock, TrendingUp, Activity, ChevronDown, Loader2, Search, Code, FileJson, MessageSquare, Zap, X, Info } from 'lucide-react';
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
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
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
  const { stats, changes, vulnerabilities, isLoading, updateVulnerabilityStatus } = useSecurityData();
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [input, setInput] = useState('');
  const [scanType, setScanType] = useState<ScanType>('code');
  const [lastResults, setLastResults] = useState<any[]>([]);
  const [isUpdating, setIsUpdating] = useState(false);
  const [statusDialog, setStatusDialog] = useState<StatusDialogState>({
    isOpen: false,
    vulnId: null,
    vulnName: null,
    action: null,
    notes: ''
  });

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
    high: { bg: 'bg-warning/10', text: 'text-warning', border: 'border-warning/20' },
    medium: { bg: 'bg-warning/10', text: 'text-warning', border: 'border-warning/20' },
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
    { label: 'Score', value: `${stats.security_score}`, change: changes.security_score, icon: TrendingUp, color: 'text-primary', hasTooltip: true },
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
          <TooltipProvider>
            {statCards.map((stat) => (
              <div 
                key={stat.label} 
                className="p-4 rounded-lg border border-border bg-card"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5">
                    <stat.icon className={cn("w-4 h-4", stat.color)} />
                    {stat.hasTooltip && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Info className="w-3 h-3 text-muted-foreground cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent className="max-w-[220px]">
                          <p className="text-xs">Calculated based on resolved vs detected vulnerabilities, severity weights, and response time. Higher is better (0-100).</p>
                        </TooltipContent>
                      </Tooltip>
                    )}
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
          </TooltipProvider>
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
                <h4 className="text-xs font-medium text-foreground mb-2 flex items-center gap-1.5">
                  <Zap className="w-3 h-3 text-warning" />
                  Quick Fixes Available
                </h4>
                <div className="space-y-2 max-h-32 overflow-y-auto">
                  {lastResults.filter(r => r.auto_fix).slice(0, 3).map((result, i) => (
                    <button
                      key={i}
                      onClick={() => applyAutoFix(result.auto_fix)}
                      className="w-full text-left p-2 rounded bg-muted hover:bg-muted/80 transition-colors"
                    >
                      <div className="text-xs font-medium text-foreground truncate">{result.name}</div>
                      <div className="text-[10px] text-primary">Click to copy fix</div>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Vulnerability feed */}
          <div className="lg:col-span-2 rounded-lg border border-border bg-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-medium text-foreground text-sm">Vulnerability Feed</h3>
              <span className="text-xs text-muted-foreground">
                {vulnerabilities.length} total
              </span>
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
                  return (
                    <div
                      key={vuln.id}
                      className="p-3 rounded-lg border border-border bg-background hover:bg-muted/30 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className={cn(
                          'w-8 h-8 rounded flex items-center justify-center flex-shrink-0',
                          severity.bg
                        )}>
                          <AlertTriangle className={cn("w-4 h-4", severity.text)} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium text-foreground truncate">{vuln.name}</div>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className={cn(
                              'text-[10px] font-medium px-1.5 py-0.5 rounded uppercase',
                              severity.bg, severity.text
                            )}>
                              {vuln.severity}
                            </span>
                            <span className="text-[10px] text-muted-foreground">{vuln.category}</span>
                            <span className="text-[10px] text-muted-foreground">{formatTimestamp(vuln.created_at)}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
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
                      {/* Show notes if present */}
                      {vuln.notes && (
                        <div className="mt-2 pl-11 text-xs text-muted-foreground italic border-l-2 border-border ml-4">
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