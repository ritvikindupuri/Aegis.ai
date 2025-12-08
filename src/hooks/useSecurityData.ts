import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';

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

interface StatsChanges {
  threats_blocked: string;
  vulnerabilities_fixed: string;
  avg_response_time_ms: string;
  security_score: string;
}

interface Vulnerability {
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
}

interface SecurityScan {
  id: string;
  scan_type: 'code' | 'url' | 'dependency';
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  created_at: string;
  completed_at: string | null;
  metadata: Record<string, unknown>;
}

export function useSecurityData() {
  const { user } = useAuth();
  
  const [stats, setStats] = useState<SecurityStats>({
    threats_blocked: 0,
    vulnerabilities_fixed: 0,
    avg_response_time_ms: 0,
    security_score: 100,
    total_scans: 0,
  });

  const [scoreBreakdown, setScoreBreakdown] = useState<ScoreBreakdown>({
    total: 0,
    resolved: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    baseScore: 100,
    penalty: 0,
  });

  const [changes, setChanges] = useState<StatsChanges>({
    threats_blocked: '+0%',
    vulnerabilities_fixed: '+0%',
    avg_response_time_ms: '0%',
    security_score: '+0%',
  });

  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [scans, setScans] = useState<SecurityScan[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Reset state to defaults (for unauthenticated users on refresh)
  const resetToDefaults = useCallback(() => {
    setStats({
      threats_blocked: 0,
      vulnerabilities_fixed: 0,
      avg_response_time_ms: 0,
      security_score: 100,
      total_scans: 0,
    });
    setScoreBreakdown({
      total: 0,
      resolved: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      baseScore: 100,
      penalty: 0,
    });
    setChanges({
      threats_blocked: '+0%',
      vulnerabilities_fixed: '+0%',
      avg_response_time_ms: '0%',
      security_score: '+0%',
    });
    setVulnerabilities([]);
    setScans([]);
  }, []);

  const calculateChange = (current: number, previous: number): string => {
    if (previous === 0) return current > 0 ? '+100%' : '0%';
    const change = ((current - previous) / previous) * 100;
    return change >= 0 ? `+${Math.round(change)}%` : `${Math.round(change)}%`;
  };

  const fetchStats = async () => {
    const { data, error } = await supabase
      .from('security_stats')
      .select('*');

    if (error) {
      console.error('Error fetching stats:', error);
      return;
    }

    if (data) {
      const newStats: SecurityStats = {
        threats_blocked: 0,
        vulnerabilities_fixed: 0,
        avg_response_time_ms: 0,
        security_score: 100,
        total_scans: 0,
      };

      const newChanges: StatsChanges = {
        threats_blocked: '+0%',
        vulnerabilities_fixed: '+0%',
        avg_response_time_ms: '0%',
        security_score: '+0%',
      };

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
  };

  const fetchVulnerabilities = async () => {
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
      
      // Calculate score breakdown from vulnerability data
      const total = data.filter(v => v.status !== 'false_positive').length;
      const resolved = data.filter(v => v.status === 'resolved').length;
      const critical = data.filter(v => v.status === 'detected' && v.severity === 'critical').length;
      const high = data.filter(v => v.status === 'detected' && v.severity === 'high').length;
      const medium = data.filter(v => v.status === 'detected' && v.severity === 'medium').length;
      const low = data.filter(v => v.status === 'detected' && v.severity === 'low').length;
      
      const baseScore = total === 0 ? 100 : (resolved / total) * 100;
      const penalty = (critical * 15) + (high * 10) + (medium * 5) + (low * 2);
      
      setScoreBreakdown({
        total,
        resolved,
        critical,
        high,
        medium,
        low,
        baseScore: Math.round(baseScore * 100) / 100,
        penalty,
      });
    }
  };

  const fetchScans = async () => {
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
  };

  const updateVulnerabilityStatus = async (id: string, status: Vulnerability['status'], notes?: string) => {
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

    // Update local state
    setVulnerabilities(prev => 
      prev.map(v => v.id === id ? { ...v, status, notes: notes || null } : v)
    );

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

    return true;
  };

  useEffect(() => {
    // For unauthenticated users, reset to defaults on mount (page refresh/new tab)
    if (!user) {
      resetToDefaults();
      setIsLoading(false);
      return;
    }

    // Only fetch from database for authenticated users
    const loadData = async () => {
      setIsLoading(true);
      await Promise.all([fetchStats(), fetchVulnerabilities(), fetchScans()]);
      setIsLoading(false);
    };

    loadData();

    // Subscribe to real-time updates (only for authenticated users)
    const statsChannel = supabase
      .channel('security_stats_changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'security_stats' },
        () => {
          fetchStats();
        }
      )
      .subscribe();

    const vulnChannel = supabase
      .channel('vulnerabilities_changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'vulnerabilities' },
        () => {
          fetchVulnerabilities();
        }
      )
      .subscribe();

    const scansChannel = supabase
      .channel('security_scans_changes')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'security_scans' },
        () => {
          fetchScans();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(statsChannel);
      supabase.removeChannel(vulnChannel);
      supabase.removeChannel(scansChannel);
    };
  }, [user, resetToDefaults]);

  return {
    stats,
    changes,
    scoreBreakdown,
    vulnerabilities,
    scans,
    isLoading,
    refetch: async () => {
      await Promise.all([fetchStats(), fetchVulnerabilities(), fetchScans()]);
    },
    updateVulnerabilityStatus,
  };
}
