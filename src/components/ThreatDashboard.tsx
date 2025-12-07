import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, TrendingUp, Activity } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ThreatItem {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'detected' | 'analyzing' | 'resolved';
  timestamp: string;
}

const ThreatDashboard = () => {
  const [threats, setThreats] = useState<ThreatItem[]>([
    { id: '1', name: 'SQL Injection Attempt', severity: 'critical', status: 'resolved', timestamp: '2 min ago' },
    { id: '2', name: 'Suspicious API Access Pattern', severity: 'high', status: 'analyzing', timestamp: '5 min ago' },
    { id: '3', name: 'Outdated Dependency Detected', severity: 'medium', status: 'detected', timestamp: '12 min ago' },
    { id: '4', name: 'Unusual Authentication Flow', severity: 'low', status: 'resolved', timestamp: '28 min ago' },
  ]);

  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    if (isScanning && scanProgress < 100) {
      const timer = setTimeout(() => {
        setScanProgress((prev) => Math.min(prev + Math.random() * 15, 100));
      }, 300);
      return () => clearTimeout(timer);
    }
    if (scanProgress >= 100) {
      setIsScanning(false);
    }
  }, [isScanning, scanProgress]);

  const startScan = () => {
    setScanProgress(0);
    setIsScanning(true);
  };

  const severityColors = {
    critical: 'text-red-400 bg-red-400/10',
    high: 'text-orange-400 bg-orange-400/10',
    medium: 'text-yellow-400 bg-yellow-400/10',
    low: 'text-blue-400 bg-blue-400/10',
  };

  const statusIcons = {
    detected: AlertTriangle,
    analyzing: Activity,
    resolved: CheckCircle,
  };

  const stats = [
    { label: 'Threats Blocked', value: '2,847', change: '+12%', icon: Shield },
    { label: 'Vulnerabilities Fixed', value: '156', change: '+8%', icon: CheckCircle },
    { label: 'Avg Response Time', value: '45ms', change: '-23%', icon: Clock },
    { label: 'Security Score', value: '94/100', change: '+5%', icon: TrendingUp },
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
            Monitor your security posture with AI-powered threat detection and automated response
          </p>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {stats.map((stat, index) => (
            <div 
              key={stat.label} 
              className="glass rounded-xl p-5 animate-fade-in"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className="flex items-center justify-between mb-3">
                <stat.icon className="w-5 h-5 text-primary" />
                <span className={cn(
                  'text-xs font-medium px-2 py-0.5 rounded-full',
                  stat.change.startsWith('+') ? 'text-accent bg-accent/10' : 'text-primary bg-primary/10'
                )}>
                  {stat.change}
                </span>
              </div>
              <div className="text-2xl font-display font-bold text-foreground mb-1">{stat.value}</div>
              <div className="text-sm text-muted-foreground">{stat.label}</div>
            </div>
          ))}
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Scanner panel */}
          <div className="glass-strong rounded-2xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-display text-lg font-semibold text-foreground">Security Scanner</h3>
              <span className={cn(
                'text-xs font-medium px-2 py-1 rounded-full',
                isScanning ? 'text-primary bg-primary/10 animate-pulse' : 'text-accent bg-accent/10'
              )}>
                {isScanning ? 'Scanning...' : 'Ready'}
              </span>
            </div>

            {/* Progress ring */}
            <div className="relative w-40 h-40 mx-auto mb-6">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="80"
                  cy="80"
                  r="70"
                  stroke="hsl(var(--secondary))"
                  strokeWidth="12"
                  fill="none"
                />
                <circle
                  cx="80"
                  cy="80"
                  r="70"
                  stroke="hsl(var(--primary))"
                  strokeWidth="12"
                  fill="none"
                  strokeLinecap="round"
                  strokeDasharray={`${2 * Math.PI * 70}`}
                  strokeDashoffset={`${2 * Math.PI * 70 * (1 - scanProgress / 100)}`}
                  className="transition-all duration-300"
                  style={{
                    filter: scanProgress > 0 ? 'drop-shadow(0 0 8px hsl(var(--primary)))' : 'none',
                  }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-display font-bold text-foreground">
                  {Math.round(scanProgress)}%
                </span>
                <span className="text-xs text-muted-foreground">Complete</span>
              </div>
            </div>

            <button
              onClick={startScan}
              disabled={isScanning}
              className={cn(
                'w-full py-3 rounded-xl font-medium transition-all duration-200',
                isScanning
                  ? 'bg-secondary text-muted-foreground cursor-not-allowed'
                  : 'bg-primary text-primary-foreground hover:bg-primary/90 glow-primary'
              )}
            >
              {isScanning ? 'Scanning in Progress...' : 'Start Full Scan'}
            </button>
          </div>

          {/* Threat feed */}
          <div className="lg:col-span-2 glass-strong rounded-2xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-display text-lg font-semibold text-foreground">Live Threat Feed</h3>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />
                <span className="text-xs text-muted-foreground">Live</span>
              </div>
            </div>

            <div className="space-y-3">
              {threats.map((threat, index) => {
                const StatusIcon = statusIcons[threat.status];
                return (
                  <div
                    key={threat.id}
                    className="flex items-center gap-4 p-4 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors animate-fade-in"
                    style={{ animationDelay: `${index * 0.1}s` }}
                  >
                    <div className={cn(
                      'w-10 h-10 rounded-lg flex items-center justify-center',
                      severityColors[threat.severity]
                    )}>
                      <AlertTriangle className="w-5 h-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-foreground truncate">{threat.name}</div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className={cn(
                          'text-xs font-medium px-2 py-0.5 rounded uppercase',
                          severityColors[threat.severity]
                        )}>
                          {threat.severity}
                        </span>
                        <span className="text-xs text-muted-foreground">{threat.timestamp}</span>
                      </div>
                    </div>
                    <div className={cn(
                      'flex items-center gap-1.5 text-sm',
                      threat.status === 'resolved' ? 'text-accent' : 
                      threat.status === 'analyzing' ? 'text-primary' : 'text-muted-foreground'
                    )}>
                      <StatusIcon className="w-4 h-4" />
                      <span className="capitalize">{threat.status}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ThreatDashboard;
