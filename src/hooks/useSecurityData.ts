import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';

interface SecurityStats {
  threats_blocked: number;
  vulnerabilities_fixed: number;
  avg_response_time_ms: number;
  security_score: number;
  total_scans: number;
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
  const [stats, setStats] = useState<SecurityStats>({
    threats_blocked: 0,
    vulnerabilities_fixed: 0,
    avg_response_time_ms: 0,
    security_score: 100,
    total_scans: 0,
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

  const updateVulnerabilityStatus = async (id: string, status: Vulnerability['status']) => {
    const { error } = await supabase
      .from('vulnerabilities')
      .update({ 
        status, 
        resolved_at: status === 'resolved' ? new Date().toISOString() : null 
      })
      .eq('id', id);

    if (error) {
      console.error('Error updating vulnerability:', error);
      return false;
    }

    // Update local state
    setVulnerabilities(prev => 
      prev.map(v => v.id === id ? { ...v, status } : v)
    );

    // Update fixed count if resolved
    if (status === 'resolved') {
      const { data: currentStat } = await supabase
        .from('security_stats')
        .select('*')
        .eq('metric_name', 'vulnerabilities_fixed')
        .single();

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
    const loadData = async () => {
      setIsLoading(true);
      await Promise.all([fetchStats(), fetchVulnerabilities(), fetchScans()]);
      setIsLoading(false);
    };

    loadData();

    // Subscribe to real-time updates
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
  }, []);

  return {
    stats,
    changes,
    vulnerabilities,
    scans,
    isLoading,
    refetch: async () => {
      await Promise.all([fetchStats(), fetchVulnerabilities(), fetchScans()]);
    },
    updateVulnerabilityStatus,
  };
}
