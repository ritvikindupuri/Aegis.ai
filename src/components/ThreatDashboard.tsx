import { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, TrendingUp, Activity, ChevronDown, Loader2 } from 'lucide-react';
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
    if (diffMins < 60) return `${diffMins} min ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours} hr ago`;
    return date.toLocaleDateString();
  };

  const severityColors = {
    critical: 'text-red-400 bg-red-400/10',
    high: 'text-orange-400 bg-orange-400/10',
    medium: 'text-yellow-400 bg-yellow-400/10',
    low: 'text-blue-400 bg-blue-400/10',
    info: 'text-gray-400 bg-gray-400/10',
  };

  const statusIcons = {
    detected: AlertTriangle,
    analyzing: Activity,
    resolved: CheckCircle,
    false_positive: CheckCircle,
  };

  const statCards = [
    { label: 'Threats Detected', value: stats.threats_blocked.toLocaleString(), change: changes.threats_blocked, icon: Shield },
    { label: 'Vulnerabilities Fixed', value: stats.vulnerabilities_fixed.toLocaleString(), change: changes.vulnerabilities_fixed, icon: CheckCircle },
    { label: 'Avg Response Time', value: `${stats.avg_response_time_ms}ms`, change: changes.avg_response_time_ms, icon: Clock },
    { label: 'Security Score', value: `${stats.security_score}/100`, change: changes.security_score, icon: TrendingUp },
  ];

  return (
    <section className="relative py-24 px-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <h2 className="font-display text-3xl md:text-5xl font-bold text-foreground mb-4">
            Real-Time <span className="gradient-text">Threat Dashboard</span>
          </h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Monitor your security posture with AI-powered threat detection and live vulnerability tracking
          </p>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {statCards.map((stat, index) => (
            <div 
              key={stat.label} 
              className="glass rounded-xl p-5 animate-fade-in"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className="flex items-center justify-between mb-3">
                <stat.icon className="w-5 h-5 text-primary" />
                <span className={cn(
                  'text-xs font-medium px-2 py-0.5 rounded-full',
                  stat.change.startsWith('+') ? 'text-accent bg-accent/10' : 
                  stat.change.startsWith('-') ? 'text-primary bg-primary/10' : 'text-muted-foreground bg-muted/10'
                )}>
                  {stat.change}
                </span>
              </div>
              <div className="text-2xl font-display font-bold text-foreground mb-1">
                {isLoading ? <Loader2 className="w-6 h-6 animate-spin" /> : stat.value}
              </div>
              <div className="text-sm text-muted-foreground">{stat.label}</div>
            </div>
          ))}
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Scanner panel */}
          <div className="glass-strong rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-lg font-semibold text-foreground">Code Scanner</h3>
              <span className={cn(
                'text-xs font-medium px-2 py-1 rounded-full',
                isScanning ? 'text-primary bg-primary/10 animate-pulse' : 'text-accent bg-accent/10'
              )}>
                {isScanning ? 'Scanning...' : 'Ready'}
              </span>
            </div>

            {/* Code input */}
            <textarea
              value={codeInput}
              onChange={(e) => setCodeInput(e.target.value)}
              placeholder="Paste code to scan for vulnerabilities..."
              className="w-full h-32 p-3 rounded-xl bg-secondary/50 border border-border text-foreground text-sm font-mono resize-none mb-4 focus:outline-none focus:ring-2 focus:ring-primary/50"
              disabled={isScanning}
            />

            {/* Progress ring */}
            <div className="relative w-32 h-32 mx-auto mb-4">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="64"
                  cy="64"
                  r="56"
                  stroke="hsl(var(--secondary))"
                  strokeWidth="10"
                  fill="none"
                />
                <circle
                  cx="64"
                  cy="64"
                  r="56"
                  stroke="hsl(var(--primary))"
                  strokeWidth="10"
                  fill="none"
                  strokeLinecap="round"
                  strokeDasharray={`${2 * Math.PI * 56}`}
                  strokeDashoffset={`${2 * Math.PI * 56 * (1 - scanProgress / 100)}`}
                  className="transition-all duration-300"
                  style={{
                    filter: scanProgress > 0 ? 'drop-shadow(0 0 8px hsl(var(--primary)))' : 'none',
                  }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-display font-bold text-foreground">
                  {Math.round(scanProgress)}%
                </span>
                <span className="text-xs text-muted-foreground">Complete</span>
              </div>
            </div>

            <button
              onClick={runScan}
              disabled={isScanning || !codeInput.trim()}
              className={cn(
                'w-full py-3 rounded-xl font-medium transition-all duration-200',
                isScanning || !codeInput.trim()
                  ? 'bg-secondary text-muted-foreground cursor-not-allowed'
                  : 'bg-primary text-primary-foreground hover:bg-primary/90 glow-primary'
              )}
            >
              {isScanning ? 'Analyzing Code...' : 'Start Security Scan'}
            </button>
          </div>

          {/* Threat feed */}
          <div className="lg:col-span-2 glass-strong rounded-2xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-display text-lg font-semibold text-foreground">Live Vulnerability Feed</h3>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />
                <span className="text-xs text-muted-foreground">
                  {vulnerabilities.length} total
                </span>
              </div>
            </div>

            <div className="space-y-3 max-h-[400px] overflow-y-auto">
              {isLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-8 h-8 animate-spin text-primary" />
                </div>
              ) : vulnerabilities.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No vulnerabilities detected yet.</p>
                  <p className="text-sm">Run a scan to analyze your code.</p>
                </div>
              ) : (
                vulnerabilities.map((vuln, index) => {
                  const StatusIcon = statusIcons[vuln.status];
                  return (
                    <div
                      key={vuln.id}
                      className="flex items-center gap-4 p-4 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors animate-fade-in"
                      style={{ animationDelay: `${index * 0.05}s` }}
                    >
                      <div className={cn(
                        'w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0',
                        severityColors[vuln.severity]
                      )}>
                        <AlertTriangle className="w-5 h-5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-foreground truncate">{vuln.name}</div>
                        <div className="flex items-center gap-2 mt-1 flex-wrap">
                          <span className={cn(
                            'text-xs font-medium px-2 py-0.5 rounded uppercase',
                            severityColors[vuln.severity]
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
                            className={cn(
                              'flex items-center gap-1.5',
                              vuln.status === 'resolved' ? 'text-accent' : 
                              vuln.status === 'analyzing' ? 'text-primary' : 'text-muted-foreground'
                            )}
                          >
                            <StatusIcon className="w-4 h-4" />
                            <span className="capitalize text-sm">{vuln.status.replace('_', ' ')}</span>
                            <ChevronDown className="w-3 h-3" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => handleStatusChange(vuln.id, 'resolved')}>
                            <CheckCircle className="w-4 h-4 mr-2 text-accent" />
                            Mark Resolved
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleStatusChange(vuln.id, 'analyzing')}>
                            <Activity className="w-4 h-4 mr-2 text-primary" />
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
