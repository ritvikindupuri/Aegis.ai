-- Fix the recalculate_security_score function to handle user_id properly
CREATE OR REPLACE FUNCTION public.recalculate_security_score()
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $$
DECLARE
  critical_count integer;
  high_count integer;
  medium_count integer;
  low_count integer;
  total_penalty numeric;
  current_score numeric;
  previous_score numeric;
  current_user_id uuid;
BEGIN
  -- Get the current user from auth context
  current_user_id := auth.uid();
  
  -- If no authenticated user, just return without doing anything
  IF current_user_id IS NULL THEN
    RETURN;
  END IF;

  -- Count only unresolved vulnerabilities for this user
  SELECT COUNT(*) INTO critical_count FROM vulnerabilities 
    WHERE status IN ('detected', 'analyzing') AND severity = 'critical' AND user_id = current_user_id;
  SELECT COUNT(*) INTO high_count FROM vulnerabilities 
    WHERE status IN ('detected', 'analyzing') AND severity = 'high' AND user_id = current_user_id;
  SELECT COUNT(*) INTO medium_count FROM vulnerabilities 
    WHERE status IN ('detected', 'analyzing') AND severity = 'medium' AND user_id = current_user_id;
  SELECT COUNT(*) INTO low_count FROM vulnerabilities 
    WHERE status IN ('detected', 'analyzing') AND severity = 'low' AND user_id = current_user_id;

  -- Get previous score for this user
  SELECT metric_value INTO previous_score FROM security_stats 
    WHERE metric_name = 'security_score' AND user_id = current_user_id;
  IF previous_score IS NULL THEN
    previous_score := 100;
  END IF;

  -- Calculate total penalty from unresolved vulnerabilities
  total_penalty := (critical_count * 15) + (high_count * 10) + (medium_count * 5) + (low_count * 2);
  
  -- Score = 100 - penalties (min 0)
  current_score := GREATEST(0, 100 - total_penalty);

  -- Update or insert the security_score stat for this user
  INSERT INTO security_stats (metric_name, metric_value, previous_value, updated_at, user_id)
  VALUES ('security_score', current_score, ROUND(previous_score), now(), current_user_id)
  ON CONFLICT (metric_name, user_id) DO UPDATE SET
    metric_value = current_score,
    previous_value = ROUND(previous_score),
    updated_at = now();
END;
$$;

-- Add unique constraint for metric_name + user_id if it doesn't exist
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'security_stats_metric_name_user_id_key'
  ) THEN
    -- First, clean up any duplicate rows
    DELETE FROM security_stats a USING security_stats b
    WHERE a.id > b.id 
    AND a.metric_name = b.metric_name 
    AND COALESCE(a.user_id, '00000000-0000-0000-0000-000000000000') = COALESCE(b.user_id, '00000000-0000-0000-0000-000000000000');
    
    -- Now add the constraint
    ALTER TABLE security_stats DROP CONSTRAINT IF EXISTS security_stats_metric_name_key;
    ALTER TABLE security_stats ADD CONSTRAINT security_stats_metric_name_user_id_key UNIQUE (metric_name, user_id);
  END IF;
END $$;