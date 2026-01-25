import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from './useAuth';

interface UsageStats {
  agent_requests_today: number;
  scan_requests_today: number;
  total_requests_today: number;
  last_request_at: string | null;
  date: string;
}

interface LocalUsage {
  agentRequests: number;
  scanRequests: number;
  date: string;
}

const HOURLY_LIMIT = 20;
const LOCAL_STORAGE_KEY = 'aegis_usage_stats';

export function useUserUsage() {
  const { user } = useAuth();
  const isAuthenticated = !!user;
  
  const [usage, setUsage] = useState<UsageStats>({
    agent_requests_today: 0,
    scan_requests_today: 0,
    total_requests_today: 0,
    last_request_at: null,
    date: new Date().toISOString().split('T')[0],
  });
  const [isLoading, setIsLoading] = useState(true);

  // Get today's date string
  const getTodayString = () => new Date().toISOString().split('T')[0];

  // Get local usage from localStorage for unauthenticated users
  const getLocalUsage = useCallback((): LocalUsage => {
    try {
      const stored = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        // Reset if it's a new day
        if (parsed.date !== getTodayString()) {
          return { agentRequests: 0, scanRequests: 0, date: getTodayString() };
        }
        return parsed;
      }
    } catch (e) {
      console.error('Error reading local usage:', e);
    }
    return { agentRequests: 0, scanRequests: 0, date: getTodayString() };
  }, []);

  // Save local usage to localStorage
  const saveLocalUsage = useCallback((localUsage: LocalUsage) => {
    try {
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(localUsage));
    } catch (e) {
      console.error('Error saving local usage:', e);
    }
  }, []);

  // Fetch usage stats from database for authenticated users
  const fetchUsage = useCallback(async () => {
    if (!isAuthenticated || !user) {
      // For unauthenticated users, use localStorage
      const localUsage = getLocalUsage();
      setUsage({
        agent_requests_today: localUsage.agentRequests,
        scan_requests_today: localUsage.scanRequests,
        total_requests_today: localUsage.agentRequests + localUsage.scanRequests,
        last_request_at: null,
        date: localUsage.date,
      });
      setIsLoading(false);
      return;
    }

    try {
      const { data, error } = await supabase.rpc('get_user_usage_stats', {
        p_user_id: user.id,
      });

      if (error) {
        console.error('Error fetching usage:', error);
        return;
      }

      if (data && typeof data === 'object' && !Array.isArray(data)) {
        const usageData = data as Record<string, unknown>;
        setUsage({
          agent_requests_today: Number(usageData.agent_requests_today) || 0,
          scan_requests_today: Number(usageData.scan_requests_today) || 0,
          total_requests_today: Number(usageData.total_requests_today) || 0,
          last_request_at: usageData.last_request_at as string | null,
          date: (usageData.date as string) || getTodayString(),
        });
      }
    } catch (e) {
      console.error('Error fetching usage:', e);
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, user, getLocalUsage]);

  // Increment local usage for unauthenticated users
  const incrementLocalUsage = useCallback((type: 'agent' | 'scan') => {
    const localUsage = getLocalUsage();
    
    if (type === 'agent') {
      localUsage.agentRequests += 1;
    } else {
      localUsage.scanRequests += 1;
    }
    
    saveLocalUsage(localUsage);
    
    setUsage({
      agent_requests_today: localUsage.agentRequests,
      scan_requests_today: localUsage.scanRequests,
      total_requests_today: localUsage.agentRequests + localUsage.scanRequests,
      last_request_at: new Date().toISOString(),
      date: localUsage.date,
    });
  }, [getLocalUsage, saveLocalUsage]);

  // Check rate limit and increment usage
  const checkAndIncrementUsage = useCallback(async (type: 'agent' | 'scan'): Promise<{
    allowed: boolean;
    currentCount: number;
    hourlyLimit: number;
    resetAt?: string;
    error?: string;
  }> => {
    if (!isAuthenticated || !user) {
      // For unauthenticated users, use local tracking with same limits
      const localUsage = getLocalUsage();
      const currentCount = type === 'agent' ? localUsage.agentRequests : localUsage.scanRequests;
      
      if (currentCount >= HOURLY_LIMIT) {
        return {
          allowed: false,
          currentCount,
          hourlyLimit: HOURLY_LIMIT,
          error: `Rate limit exceeded (${HOURLY_LIMIT} ${type} requests per day). Please try again tomorrow.`,
        };
      }
      
      incrementLocalUsage(type);
      return {
        allowed: true,
        currentCount: currentCount + 1,
        hourlyLimit: HOURLY_LIMIT,
      };
    }

    try {
      const { data, error } = await supabase.rpc('check_and_increment_usage', {
        p_user_id: user.id,
        p_request_type: type,
        p_hourly_limit: HOURLY_LIMIT,
      });

      if (error) {
        console.error('Error checking usage:', error);
        // Allow the request but log the error
        return { allowed: true, currentCount: 0, hourlyLimit: HOURLY_LIMIT };
      }

      const result = data as {
        allowed: boolean;
        current_count: number;
        hourly_limit: number;
        reset_at?: string;
        error?: string;
      };

      // Refresh usage stats after increment
      fetchUsage();

      return {
        allowed: result.allowed,
        currentCount: result.current_count,
        hourlyLimit: result.hourly_limit,
        resetAt: result.reset_at,
        error: result.error,
      };
    } catch (e) {
      console.error('Error checking usage:', e);
      return { allowed: true, currentCount: 0, hourlyLimit: HOURLY_LIMIT };
    }
  }, [isAuthenticated, user, getLocalUsage, incrementLocalUsage, fetchUsage]);

  // Load usage on mount and when auth changes
  useEffect(() => {
    fetchUsage();
  }, [fetchUsage]);

  // Calculate remaining requests
  const remainingAgentRequests = Math.max(0, HOURLY_LIMIT - usage.agent_requests_today);
  const remainingScanRequests = Math.max(0, HOURLY_LIMIT - usage.scan_requests_today);
  const totalRemaining = remainingAgentRequests + remainingScanRequests;

  return {
    usage,
    isLoading,
    isAuthenticated,
    hourlyLimit: HOURLY_LIMIT,
    remainingAgentRequests,
    remainingScanRequests,
    totalRemaining,
    checkAndIncrementUsage,
    refetch: fetchUsage,
  };
}
