import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from './useAuth';

// Security data hook - authenticated users persist to DB, unauthenticated use local state

interface SecurityStats {
  threats_blocked: number;
  vulnerabilities_fixed: number;
  avg_response_time_ms: number;
  security_score: number;
  total_scans: number;
}

interface ScoreBreakdown {
  total: number;
  resolved: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  baseScore: number;
  penalty: number;
}

interface ScoreHistoryEntry {
  timestamp: string;
  score: number;
  penalty: number;
}

interface StatsChanges {
  threats_blocked: string;
  vulnerabilities_fixed: string;
  avg_response_time_ms: string;
  security_score: string;
}

export interface Vulnerability {
  id: string;
  name: string;
  description: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  location: string | null;
  remediation: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  status: 'detected' | 'analyzing' | 'resolved' | 'false_positive';
  created_at: string;
  scan_id: string | null;
  notes: string | null;
  resolved_at: string | null;
  user_id?: string | null;
}

interface SecurityScan {
  id: string;
  scan_type: 'code' | 'url' | 'dependency';
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  created_at: string;
  completed_at: string | null;
  metadata: Record<string, unknown>;
  user_id?: string | null;
}

const defaultStats: SecurityStats = {
  threats_blocked: 0,
  vulnerabilities_fixed: 0,
  avg_response_time_ms: 0,
  security_score: 100,
  total_scans: 0,
};

const defaultScoreBreakdown: ScoreBreakdown = {
  total: 0,
  resolved: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  baseScore: 100,
  penalty: 0,
};

const defaultChanges: StatsChanges = {
  threats_blocked: '+0%',
  vulnerabilities_fixed: '+0%',
  avg_response_time_ms: '0%',
  security_score: '+0%',
};

export function useSecurityData() {
  const { user } = useAuth();
  const isAuthenticated = !!user;

  const [stats, setStats] = useState<SecurityStats>(defaultStats);
  const [scoreBreakdown, setScoreBreakdown] = useState<ScoreBreakdown>(defaultScoreBreakdown);
  const [changes, setChanges] = useState<StatsChanges>(defaultChanges);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [scans, setScans] = useState<SecurityScan[]>([]);
  const [scoreHistory, setScoreHistory] = useState<ScoreHistoryEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const calculateChange = (current: number, previous: number): string => {
    if (previous === 0) return current > 0 ? '+100%' : '0%';
    const change = ((current - previous) / previous) * 100;
    return change >= 0 ? `+${Math.round(change)}%` : `${Math.round(change)}%`;
  };

  const calculateScoreFromVulnerabilities = useCallback((vulns: Vulnerability[]) => {
    const unresolvedStatuses = ['detected', 'analyzing'];
    const total = vulns.filter(v => v.status !== 'false_positive').length;
    const resolved = vulns.filter(v => v.status === 'resolved').length;
    const critical = vulns.filter(v => unresolvedStatuses.includes(v.status) && v.severity === 'critical').length;
    const high = vulns.filter(v => unresolvedStatuses.includes(v.status) && v.severity === 'high').length;
    const medium = vulns.filter(v => unresolvedStatuses.includes(v.status) && v.severity === 'medium').length;
    const low = vulns.filter(v => unresolvedStatuses.includes(v.status) && v.severity === 'low').length;
    
    const penalty = (critical * 15) + (high * 10) + (medium * 5) + (low * 2);
    const calculatedScore = Math.max(0, 100 - penalty);
    
    setScoreBreakdown({
      total,
      resolved,
      critical,
      high,
      medium,
      low,
      baseScore: 100,
      penalty,
    });
    
    setStats(prev => ({
      ...prev,
      security_score: calculatedScore
    }));

    // Add to score history
    if (vulns.length > 0) {
      setScoreHistory(prev => {
        const lastEntry = prev[prev.length - 1];
        if (!lastEntry || 
            lastEntry.score !== calculatedScore || 
            (Date.now() - new Date(lastEntry.timestamp).getTime() > 5 * 60 * 1000)) {
          const newEntry: ScoreHistoryEntry = {
            timestamp: new Date().toISOString(),
            score: calculatedScore,
            penalty,
          };
          return [...prev.slice(-19), newEntry];
        }
        return prev;
      });
    }

    return { calculatedScore, penalty };
  }, []);

  // === DATABASE FUNCTIONS (for authenticated users) ===
  const fetchStats = useCallback(async () => {
    if (!isAuthenticated) return;
    
    const { data, error } = await supabase
      .from('security_stats')
      .select('*');

    if (error) {
      console.error('Error fetching stats:', error);
      return;
    }

    if (data) {
      const newStats: SecurityStats = { ...defaultStats };
      const newChanges: StatsChanges = { ...defaultChanges };

      data.forEach((stat) => {
        const key = stat.metric_name as keyof SecurityStats;
        if (key in newStats) {
          newStats[key] = Number(stat.metric_value);
          if (key in newChanges) {
            const changeKey = key as keyof StatsChanges;
            newChanges[changeKey] = calculateChange(
              Number(stat.metric_value),
              Number(stat.previous_value || 0)
            );
          }
        }
      });

      setStats(newStats);
      setChanges(newChanges);
    }
  }, [isAuthenticated]);

  const fetchVulnerabilities = useCallback(async () => {
    if (!isAuthenticated) return;
    
    const { data, error } = await supabase
      .from('vulnerabilities')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) {
      console.error('Error fetching vulnerabilities:', error);
      return;
    }

    if (data) {
      setVulnerabilities(data as Vulnerability[]);
      calculateScoreFromVulnerabilities(data as Vulnerability[]);
    }
  }, [isAuthenticated, calculateScoreFromVulnerabilities]);

  const fetchScans = useCallback(async () => {
    if (!isAuthenticated) return;
    
    const { data, error } = await supabase
      .from('security_scans')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(20);

    if (error) {
      console.error('Error fetching scans:', error);
      return;
    }

    if (data) {
      setScans(data as SecurityScan[]);
    }
  }, [isAuthenticated]);

  // === LOCAL STATE FUNCTIONS (for unauthenticated users) ===
  const addLocalVulnerability = useCallback((vuln: Omit<Vulnerability, 'id' | 'created_at'>) => {
    const newVuln: Vulnerability = {
      ...vuln,
      id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
    };
    setVulnerabilities(prev => {
      const updated = [newVuln, ...prev];
      calculateScoreFromVulnerabilities(updated);
      return updated;
    });
    setStats(prev => ({
      ...prev,
      threats_blocked: prev.threats_blocked + 1
    }));
    return newVuln;
  }, [calculateScoreFromVulnerabilities]);

  const addLocalVulnerabilities = useCallback((vulns: Omit<Vulnerability, 'id' | 'created_at'>[]) => {
    const newVulns: Vulnerability[] = vulns.map(v => ({
      ...v,
      id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
    }));
    setVulnerabilities(prev => {
      const updated = [...newVulns, ...prev];
      calculateScoreFromVulnerabilities(updated);
      return updated;
    });
    setStats(prev => ({
      ...prev,
      threats_blocked: prev.threats_blocked + vulns.length
    }));
    return newVulns;
  }, [calculateScoreFromVulnerabilities]);

  const updateVulnerabilityStatus = useCallback(async (id: string, status: Vulnerability['status'], notes?: string) => {
    if (isAuthenticated) {
      // Update in database for authenticated users
      const updateData: Record<string, unknown> = { 
        status,
        notes: notes || null,
        resolved_at: status === 'resolved' ? new Date().toISOString() : null 
      };

      const { error } = await supabase
        .from('vulnerabilities')
        .update(updateData)
        .eq('id', id);

      if (error) {
        console.error('Error updating vulnerability:', error);
        return false;
      }

      // Update fixed count if resolved
      if (status === 'resolved') {
        const { data: currentStat } = await supabase
          .from('security_stats')
          .select('*')
          .eq('metric_name', 'vulnerabilities_fixed')
          .maybeSingle();

        if (currentStat) {
          await supabase
            .from('security_stats')
            .update({ 
              metric_value: Number(currentStat.metric_value) + 1,
              previous_value: currentStat.metric_value,
              updated_at: new Date().toISOString()
            })
            .eq('metric_name', 'vulnerabilities_fixed');
        }
      }
    }

    // Update local state (for both authenticated and unauthenticated)
    setVulnerabilities(prev => {
      const updated = prev.map(v => v.id === id ? { ...v, status, notes: notes || null } : v);
      calculateScoreFromVulnerabilities(updated);
      return updated;
    });

    if (status === 'resolved') {
      setStats(prev => ({
        ...prev,
        vulnerabilities_fixed: prev.vulnerabilities_fixed + 1
      }));
    }

    return true;
  }, [isAuthenticated, calculateScoreFromVulnerabilities]);

  const resetDashboard = useCallback(async () => {
    if (isAuthenticated) {
      // Delete all vulnerabilities for this user
      const { error: vulnError } = await supabase
        .from('vulnerabilities')
        .delete()
        .neq('id', '00000000-0000-0000-0000-000000000000');

      if (vulnError) {
        console.error('Error deleting vulnerabilities:', vulnError);
        return false;
      }

      // Delete all scans for this user
      const { error: scanError } = await supabase
        .from('security_scans')
        .delete()
        .neq('id', '00000000-0000-0000-0000-000000000000');

      if (scanError) {
        console.error('Error deleting scans:', scanError);
        return false;
      }

      // Reset security stats
      const statsToReset = ['threats_blocked', 'vulnerabilities_fixed', 'avg_response_time_ms', 'security_score', 'total_scans'];
      for (const metricName of statsToReset) {
        await supabase
          .from('security_stats')
          .upsert({
            metric_name: metricName,
            metric_value: metricName === 'security_score' ? 100 : 0,
            previous_value: 0,
            updated_at: new Date().toISOString(),
            user_id: user?.id
          }, { onConflict: 'metric_name' });
      }
    }

    // Reset local state (for both authenticated and unauthenticated)
    setVulnerabilities([]);
    setScans([]);
    setStats(defaultStats);
    setScoreBreakdown(defaultScoreBreakdown);
    setChanges(defaultChanges);
    setScoreHistory([]);

    return true;
  }, [isAuthenticated, user?.id]);

  // Load data on mount and when auth state changes
  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true);
      
      if (isAuthenticated) {
        // Fetch from database for authenticated users
        await Promise.all([fetchStats(), fetchVulnerabilities(), fetchScans()]);
      } else {
        // For unauthenticated users, start with clean state
        setStats(defaultStats);
        setScoreBreakdown(defaultScoreBreakdown);
        setChanges(defaultChanges);
        setVulnerabilities([]);
        setScans([]);
        setScoreHistory([]);
      }
      
      setIsLoading(false);
    };

    loadData();
  }, [isAuthenticated, fetchStats, fetchVulnerabilities, fetchScans]);

  // Subscribe to real-time updates for authenticated users only
  useEffect(() => {
    if (!isAuthenticated) return;

    const statsChannel = supabase
      .channel('security_stats_changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'security_stats' },
        () => fetchStats()
      )
      .subscribe();

    const vulnChannel = supabase
      .channel('vulnerabilities_changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'vulnerabilities' },
        () => fetchVulnerabilities()
      )
      .subscribe();

    const scansChannel = supabase
      .channel('security_scans_changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'security_scans' },
        () => fetchScans()
      )
      .subscribe();

    return () => {
      supabase.removeChannel(statsChannel);
      supabase.removeChannel(vulnChannel);
      supabase.removeChannel(scansChannel);
    };
  }, [isAuthenticated, fetchStats, fetchVulnerabilities, fetchScans]);

  return {
    stats,
    changes,
    scoreBreakdown,
    scoreHistory,
    vulnerabilities,
    scans,
    isLoading,
    isAuthenticated,
    refetch: async () => {
      if (isAuthenticated) {
        await Promise.all([fetchStats(), fetchVulnerabilities(), fetchScans()]);
      }
    },
    updateVulnerabilityStatus,
    resetDashboard,
    // Local state management for unauthenticated users
    addLocalVulnerability,
    addLocalVulnerabilities,
  };
}
