CREATE OR REPLACE FUNCTION public.recalculate_security_score()
 RETURNS void
 LANGUAGE plpgsql
 SET search_path TO 'public'
AS $function$
DECLARE
  critical_count integer;
  high_count integer;
  medium_count integer;
  low_count integer;
  total_penalty numeric;
  current_score numeric;
  previous_score numeric;
BEGIN
  -- Count only unresolved vulnerabilities (detected or analyzing, not resolved or false_positive)
  SELECT COUNT(*) INTO critical_count FROM vulnerabilities WHERE status IN ('detected', 'analyzing') AND severity = 'critical';
  SELECT COUNT(*) INTO high_count FROM vulnerabilities WHERE status IN ('detected', 'analyzing') AND severity = 'high';
  SELECT COUNT(*) INTO medium_count FROM vulnerabilities WHERE status IN ('detected', 'analyzing') AND severity = 'medium';
  SELECT COUNT(*) INTO low_count FROM vulnerabilities WHERE status IN ('detected', 'analyzing') AND severity = 'low';

  -- Get previous score
  SELECT metric_value INTO previous_score FROM security_stats WHERE metric_name = 'security_score';
  IF previous_score IS NULL THEN
    previous_score := 100;
  END IF;

  -- Calculate total penalty from unresolved vulnerabilities
  total_penalty := (critical_count * 15) + (high_count * 10) + (medium_count * 5) + (low_count * 2);
  
  -- Score = 100 - penalties (min 0)
  current_score := GREATEST(0, 100 - total_penalty);

  -- Update or insert the security_score stat
  INSERT INTO security_stats (metric_name, metric_value, previous_value, updated_at)
  VALUES ('security_score', current_score, ROUND(previous_score), now())
  ON CONFLICT (metric_name) DO UPDATE SET
    metric_value = current_score,
    previous_value = ROUND(previous_score),
    updated_at = now();
END;
$function$;