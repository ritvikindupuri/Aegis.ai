-- Add notes column to vulnerabilities table
ALTER TABLE public.vulnerabilities ADD COLUMN IF NOT EXISTS notes text;

-- Create a function to recalculate security score based on vulnerabilities
CREATE OR REPLACE FUNCTION public.recalculate_security_score()
RETURNS void
LANGUAGE plpgsql
SET search_path = public
AS $$
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
  
  -- Calculate final score (min 0, max 100)
  current_score := GREATEST(0, LEAST(100, base_score - severity_penalty));

  -- Update or insert the security_score stat
  INSERT INTO security_stats (metric_name, metric_value, previous_value, updated_at)
  VALUES ('security_score', current_score, previous_score, now())
  ON CONFLICT (metric_name) DO UPDATE SET
    metric_value = current_score,
    previous_value = previous_score,
    updated_at = now();
END;
$$;

-- Add unique constraint on metric_name if not exists
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'security_stats_metric_name_key'
  ) THEN
    ALTER TABLE public.security_stats ADD CONSTRAINT security_stats_metric_name_key UNIQUE (metric_name);
  END IF;
END $$;

-- Create trigger to auto-recalculate score when vulnerabilities change
CREATE OR REPLACE FUNCTION public.trigger_recalculate_score()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  PERFORM recalculate_security_score();
  RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS recalculate_score_on_vuln_change ON public.vulnerabilities;
CREATE TRIGGER recalculate_score_on_vuln_change
AFTER INSERT OR UPDATE OR DELETE ON public.vulnerabilities
FOR EACH ROW
EXECUTE FUNCTION public.trigger_recalculate_score();