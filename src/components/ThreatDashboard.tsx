import { useState } from 'react';
import { AlertTriangle, CheckCircle, Clock, TrendingUp, Activity, ChevronDown, Loader2, Search } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useSecurityData } from '@/hooks/useSecurityData';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { toast } from 'sonner';

const ThreatDashboard = () => {
  const { stats, changes, vulnerabilities, isLoading, updateVulnerabilityStatus } = useSecurityData();
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [codeInput, setCodeInput] = useState('');

  const runScan = async () => {
    if (!codeInput.trim()) {
      toast.error('Please paste some code to scan');
      return;
    }

    setIsScanning(true);
    setScanProgress(10);

    try {
      const progressInterval = setInterval(() => {
        setScanProgress(prev => Math.min(prev + Math.random() * 20, 90));
      }, 500);

      const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/code-scanner`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        },
        body: JSON.stringify({
          code: codeInput,
          scanType: 'code'
        }),
      });

      clearInterval(progressInterval);
      setScanProgress(100);

      const data = await response.json();

      if (data.success) {
        toast.success(`Scan complete! Found ${data.vulnerabilities} vulnerabilities`);
        setCodeInput('');
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
      }, 1000);
    }
  };

  const handleStatusChange = async (id: string, newStatus: 'resolved' | 'analyzing' | 'false_positive') => {
    const success = await updateVulnerabilityStatus(id, newStatus);
    if (success) {
      toast.success(`Status updated to ${newStatus}`);
    } else {
      toast.error('Failed to update status');
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
    { label: 'Vulnerabilities Fixed', value: stats.vulnerabilities_fixed.toLocaleString(), change: changes.vulnerabilities_fixed, icon: CheckCircle, color: 'text-success' },
    { label: 'Avg Response Time', value: `${stats.avg_response_time_ms}ms`, change: changes.avg_response_time_ms, icon: Clock, color: 'text-warning' },
    { label: 'Security Score', value: `${stats.security_score}/100`, change: changes.security_score, icon: TrendingUp, color: 'text-primary' },
  ];

  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h2 className="text-3xl sm:text-4xl font-bold text-foreground mb-2">
            Security Dashboard
          </h2>
          <p className="text-muted-foreground">
            Real-time threat detection and vulnerability tracking
          </p>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {statCards.map((stat) => (
            <div 
              key={stat.label} 
              className="p-5 rounded-xl border border-border bg-card"
            >
              <div className="flex items-center justify-between mb-3">
                <stat.icon className={cn("w-5 h-5", stat.color)} />
                <span className={cn(
                  'text-xs font-medium px-2 py-0.5 rounded-full',
                  stat.change.startsWith('+') ? 'text-success bg-success/10' : 
                  stat.change.startsWith('-') ? 'text-destructive bg-destructive/10' : 'text-muted-foreground bg-muted'
                )}>
                  {stat.change}
                </span>
              </div>
              <div className="text-2xl font-bold text-foreground mb-0.5">
                {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : stat.value}
              </div>
              <div className="text-sm text-muted-foreground">{stat.label}</div>
            </div>
          ))}
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Scanner panel */}
          <div className="rounded-xl border border-border bg-card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-foreground">Code Scanner</h3>
              <span className={cn(
                'text-xs font-medium px-2 py-1 rounded-full',
                isScanning ? 'text-warning bg-warning/10' : 'text-success bg-success/10'
              )}>
                {isScanning ? 'Scanning' : 'Ready'}
              </span>
            </div>

            {/* Code input */}
            <textarea
              value={codeInput}
              onChange={(e) => setCodeInput(e.target.value)}
              placeholder="Paste code to scan for vulnerabilities..."
              className="w-full h-32 p-3 rounded-lg bg-muted border border-border text-foreground text-sm font-mono resize-none mb-4 focus:outline-none focus:ring-2 focus:ring-primary/50"
              disabled={isScanning}
            />

            {/* Progress bar */}
            {isScanning && (
              <div className="mb-4">
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="text-muted-foreground">Analyzing code...</span>
                  <span className="font-medium text-foreground">{Math.round(scanProgress)}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-primary transition-all duration-300 rounded-full"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
              </div>
            )}

            <Button
              onClick={runScan}
              disabled={isScanning || !codeInput.trim()}
              className="w-full"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 mr-2" />
                  Start Scan
                </>
              )}
            </Button>
          </div>

          {/* Vulnerability feed */}
          <div className="lg:col-span-2 rounded-xl border border-border bg-card p-6">
            <div className="flex items-center justify-between mb-5">
              <h3 className="font-semibold text-foreground">Vulnerability Feed</h3>
              <span className="text-xs text-muted-foreground">
                {vulnerabilities.length} total
              </span>
            </div>

            <div className="space-y-3 max-h-[400px] overflow-y-auto">
              {isLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                </div>
              ) : vulnerabilities.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Search className="w-10 h-10 mx-auto mb-3 opacity-50" />
                  <p className="font-medium">No vulnerabilities detected</p>
                  <p className="text-sm">Run a scan to analyze your code.</p>
                </div>
              ) : (
                vulnerabilities.map((vuln) => {
                  const StatusIcon = statusIcons[vuln.status];
                  const severity = severityConfig[vuln.severity] || severityConfig.info;
                  return (
                    <div
                      key={vuln.id}
                      className="flex items-center gap-4 p-4 rounded-lg border border-border bg-background hover:bg-muted/30 transition-colors"
                    >
                      <div className={cn(
                        'w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0',
                        severity.bg
                      )}>
                        <AlertTriangle className={cn("w-5 h-5", severity.text)} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-foreground truncate">{vuln.name}</div>
                        <div className="flex items-center gap-2 mt-1 flex-wrap">
                          <span className={cn(
                            'text-xs font-medium px-2 py-0.5 rounded uppercase',
                            severity.bg, severity.text
                          )}>
                            {vuln.severity}
                          </span>
                          <span className="text-xs text-muted-foreground">{vuln.category}</span>
                          <span className="text-xs text-muted-foreground">•</span>
                          <span className="text-xs text-muted-foreground">{formatTimestamp(vuln.created_at)}</span>
                        </div>
                      </div>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="flex items-center gap-1.5"
                          >
                            <StatusIcon className={cn(
                              "w-4 h-4",
                              vuln.status === 'resolved' ? 'text-success' : 
                              vuln.status === 'analyzing' ? 'text-warning' : 'text-muted-foreground'
                            )} />
                            <span className="capitalize text-sm">{vuln.status.replace('_', ' ')}</span>
                            <ChevronDown className="w-3 h-3" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="bg-popover border border-border">
                          <DropdownMenuItem onClick={() => handleStatusChange(vuln.id, 'resolved')}>
                            <CheckCircle className="w-4 h-4 mr-2 text-success" />
                            Mark Resolved
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleStatusChange(vuln.id, 'analyzing')}>
                            <Activity className="w-4 h-4 mr-2 text-warning" />
                            Analyzing
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleStatusChange(vuln.id, 'false_positive')}>
                            <CheckCircle className="w-4 h-4 mr-2 text-muted-foreground" />
                            False Positive
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ThreatDashboard;