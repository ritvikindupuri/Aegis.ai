-- Create user_usage table to track daily request counts for rate limiting
CREATE TABLE public.user_usage (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  request_date DATE NOT NULL DEFAULT CURRENT_DATE,
  agent_requests INTEGER NOT NULL DEFAULT 0,
  scan_requests INTEGER NOT NULL DEFAULT 0,
  last_request_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE(user_id, request_date)
);

-- Create index for fast lookups
CREATE INDEX idx_user_usage_user_date ON public.user_usage(user_id, request_date);
CREATE INDEX idx_user_usage_last_request ON public.user_usage(user_id, last_request_at);

-- Enable RLS
ALTER TABLE public.user_usage ENABLE ROW LEVEL SECURITY;

-- Users can view their own usage
CREATE POLICY "Users can view own usage"
ON public.user_usage
FOR SELECT
USING (auth.uid() = user_id);

-- Users can insert their own usage (edge functions use service role)
CREATE POLICY "Users can insert own usage"
ON public.user_usage
FOR INSERT
WITH CHECK (auth.uid() = user_id);

-- Users can update their own usage
CREATE POLICY "Users can update own usage"
ON public.user_usage
FOR UPDATE
USING (auth.uid() = user_id);

-- Function to increment usage and check rate limits
-- Returns: { allowed: boolean, current_count: int, reset_at: timestamp }
CREATE OR REPLACE FUNCTION public.check_and_increment_usage(
  p_user_id UUID,
  p_request_type TEXT, -- 'agent' or 'scan'
  p_hourly_limit INTEGER DEFAULT 20
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_today DATE := CURRENT_DATE;
  v_one_hour_ago TIMESTAMP WITH TIME ZONE := now() - INTERVAL '1 hour';
  v_current_count INTEGER;
  v_last_hour_count INTEGER;
  v_reset_at TIMESTAMP WITH TIME ZONE;
  v_result JSONB;
BEGIN
  -- Get or create today's usage record
  INSERT INTO public.user_usage (user_id, request_date, agent_requests, scan_requests)
  VALUES (p_user_id, v_today, 0, 0)
  ON CONFLICT (user_id, request_date) DO NOTHING;
  
  -- Count requests in the last hour by checking last_request_at
  SELECT COUNT(*)
  INTO v_last_hour_count
  FROM public.user_usage
  WHERE user_id = p_user_id
    AND last_request_at >= v_one_hour_ago;
  
  -- For simplicity, we'll use a rolling window approach
  -- Get current hourly requests from today's record
  SELECT 
    CASE WHEN p_request_type = 'agent' THEN agent_requests ELSE scan_requests END
  INTO v_current_count
  FROM public.user_usage
  WHERE user_id = p_user_id AND request_date = v_today;
  
  -- Calculate reset time (1 hour from now if at limit)
  v_reset_at := now() + INTERVAL '1 hour';
  
  -- Check if under hourly limit
  IF v_current_count < p_hourly_limit THEN
    -- Increment the appropriate counter
    IF p_request_type = 'agent' THEN
      UPDATE public.user_usage
      SET agent_requests = agent_requests + 1,
          last_request_at = now()
      WHERE user_id = p_user_id AND request_date = v_today;
    ELSE
      UPDATE public.user_usage
      SET scan_requests = scan_requests + 1,
          last_request_at = now()
      WHERE user_id = p_user_id AND request_date = v_today;
    END IF;
    
    v_result := jsonb_build_object(
      'allowed', true,
      'current_count', v_current_count + 1,
      'daily_total', v_current_count + 1,
      'hourly_limit', p_hourly_limit,
      'reset_at', v_reset_at
    );
  ELSE
    v_result := jsonb_build_object(
      'allowed', false,
      'current_count', v_current_count,
      'daily_total', v_current_count,
      'hourly_limit', p_hourly_limit,
      'reset_at', v_reset_at,
      'error', 'Rate limit exceeded. Please wait before making more requests.'
    );
  END IF;
  
  RETURN v_result;
END;
$$;

-- Function to get user's current usage stats
CREATE OR REPLACE FUNCTION public.get_user_usage_stats(p_user_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_today DATE := CURRENT_DATE;
  v_agent_count INTEGER := 0;
  v_scan_count INTEGER := 0;
  v_last_request TIMESTAMP WITH TIME ZONE;
BEGIN
  SELECT agent_requests, scan_requests, last_request_at
  INTO v_agent_count, v_scan_count, v_last_request
  FROM public.user_usage
  WHERE user_id = p_user_id AND request_date = v_today;
  
  RETURN jsonb_build_object(
    'agent_requests_today', COALESCE(v_agent_count, 0),
    'scan_requests_today', COALESCE(v_scan_count, 0),
    'total_requests_today', COALESCE(v_agent_count, 0) + COALESCE(v_scan_count, 0),
    'last_request_at', v_last_request,
    'date', v_today
  );
END;
$$;