CREATE OR REPLACE FUNCTION public.recalculate_security_score()
 RETURNS void
 LANGUAGE plpgsql
 SET search_path TO 'public'
AS $function$
DECLARE
  total_vulns integer;
  resolved_count integer;
  false_positive_count integer;
  critical_count integer;
  high_count integer;
  medium_count integer;
  low_count integer;
  base_score numeric;
  severity_penalty numeric;
  current_score numeric;
  previous_score numeric;
BEGIN
  -- Get counts
  SELECT COUNT(*) INTO total_vulns FROM vulnerabilities WHERE status != 'false_positive';
  SELECT COUNT(*) INTO resolved_count FROM vulnerabilities WHERE status = 'resolved';
  SELECT COUNT(*) INTO false_positive_count FROM vulnerabilities WHERE status = 'false_positive';
  SELECT COUNT(*) INTO critical_count FROM vulnerabilities WHERE status = 'detected' AND severity = 'critical';
  SELECT COUNT(*) INTO high_count FROM vulnerabilities WHERE status = 'detected' AND severity = 'high';
  SELECT COUNT(*) INTO medium_count FROM vulnerabilities WHERE status = 'detected' AND severity = 'medium';
  SELECT COUNT(*) INTO low_count FROM vulnerabilities WHERE status = 'detected' AND severity = 'low';

  -- Get previous score
  SELECT metric_value INTO previous_score FROM security_stats WHERE metric_name = 'security_score';
  IF previous_score IS NULL THEN
    previous_score := 100;
  END IF;

  -- Calculate base score (100 if no vulns, otherwise based on resolution rate)
  IF total_vulns = 0 THEN
    base_score := 100;
  ELSE
    base_score := (resolved_count::numeric / total_vulns::numeric) * 100;
  END IF;

  -- Apply severity penalties for unresolved issues
  severity_penalty := (critical_count * 15) + (high_count * 10) + (medium_count * 5) + (low_count * 2);
  
  -- Calculate final score (min 0, max 100) - ROUND to whole number
  current_score := ROUND(GREATEST(0, LEAST(100, base_score - severity_penalty)));

  -- Update or insert the security_score stat
  INSERT INTO security_stats (metric_name, metric_value, previous_value, updated_at)
  VALUES ('security_score', current_score, ROUND(previous_score), now())
  ON CONFLICT (metric_name) DO UPDATE SET
    metric_value = current_score,
    previous_value = ROUND(previous_score),
    updated_at = now();
END;
$function$;