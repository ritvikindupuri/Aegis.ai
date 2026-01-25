import { Activity, Zap, TrendingDown, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useUserUsage } from '@/hooks/useUserUsage';
import { Progress } from '@/components/ui/progress';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';

interface UsageCounterProps {
  className?: string;
  variant?: 'compact' | 'full';
}

export function UsageCounter({ className, variant = 'compact' }: UsageCounterProps) {
  const { 
    usage, 
    isLoading, 
    hourlyLimit, 
    remainingAgentRequests, 
    remainingScanRequests,
    isAuthenticated 
  } = useUserUsage();

  const totalUsed = usage.agent_requests_today + usage.scan_requests_today;
  const totalLimit = hourlyLimit * 2; // Combined limit for both types
  const usagePercent = Math.min(100, (totalUsed / totalLimit) * 100);
  
  const isNearLimit = usagePercent >= 70;
  const isAtLimit = usagePercent >= 90;

  if (isLoading) {
    return (
      <div className={cn("animate-pulse bg-muted rounded-lg h-8 w-24", className)} />
    );
  }

  if (variant === 'compact') {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div 
              className={cn(
                "flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm transition-colors cursor-help",
                isAtLimit 
                  ? "border-destructive/50 bg-destructive/10 text-destructive" 
                  : isNearLimit 
                    ? "border-warning/50 bg-warning/10 text-warning" 
                    : "border-border bg-card text-muted-foreground",
                className
              )}
            >
              {isAtLimit ? (
                <AlertTriangle className="w-3.5 h-3.5" />
              ) : isNearLimit ? (
                <TrendingDown className="w-3.5 h-3.5" />
              ) : (
                <Activity className="w-3.5 h-3.5" />
              )}
              <span className="font-medium">
                {totalUsed}/{totalLimit}
              </span>
            </div>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-xs">
            <div className="space-y-2 text-xs">
              <p className="font-medium">Daily Usage</p>
              <div className="space-y-1">
                <div className="flex justify-between">
                  <span>Agent requests:</span>
                  <span>{usage.agent_requests_today}/{hourlyLimit}</span>
                </div>
                <div className="flex justify-between">
                  <span>Scan requests:</span>
                  <span>{usage.scan_requests_today}/{hourlyLimit}</span>
                </div>
              </div>
              {!isAuthenticated && (
                <p className="text-muted-foreground italic">
                  Sign in to track usage across sessions
                </p>
              )}
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  // Full variant
  return (
    <div className={cn("p-4 rounded-lg border border-border bg-card", className)}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Zap className={cn(
            "w-4 h-4",
            isAtLimit ? "text-destructive" : isNearLimit ? "text-warning" : "text-primary"
          )} />
          <span className="text-sm font-medium text-foreground">Daily Usage</span>
        </div>
        <span className={cn(
          "text-xs font-medium px-2 py-0.5 rounded",
          isAtLimit 
            ? "bg-destructive/10 text-destructive" 
            : isNearLimit 
              ? "bg-warning/10 text-warning" 
              : "bg-primary/10 text-primary"
        )}>
          {totalUsed}/{totalLimit} requests
        </span>
      </div>
      
      <Progress 
        value={usagePercent} 
        className={cn(
          "h-2 mb-3",
          isAtLimit ? "[&>div]:bg-destructive" : isNearLimit ? "[&>div]:bg-warning" : ""
        )} 
      />
      
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div className="space-y-1">
          <div className="flex items-center gap-1.5 text-muted-foreground">
            <Activity className="w-3 h-3" />
            <span>Agent</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-foreground font-medium">
              {remainingAgentRequests} left
            </span>
            <span className="text-muted-foreground">
              {usage.agent_requests_today}/{hourlyLimit}
            </span>
          </div>
        </div>
        
        <div className="space-y-1">
          <div className="flex items-center gap-1.5 text-muted-foreground">
            <Zap className="w-3 h-3" />
            <span>Scans</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-foreground font-medium">
              {remainingScanRequests} left
            </span>
            <span className="text-muted-foreground">
              {usage.scan_requests_today}/{hourlyLimit}
            </span>
          </div>
        </div>
      </div>
      
      {isAtLimit && (
        <div className="mt-3 p-2 rounded bg-destructive/10 border border-destructive/20">
          <p className="text-xs text-destructive flex items-center gap-1.5">
            <AlertTriangle className="w-3 h-3" />
            Daily limit reached. Limits reset at midnight.
          </p>
        </div>
      )}
      
      {!isAuthenticated && (
        <p className="mt-3 text-xs text-muted-foreground italic">
          Sign in to track usage across sessions
        </p>
      )}
    </div>
  );
}
