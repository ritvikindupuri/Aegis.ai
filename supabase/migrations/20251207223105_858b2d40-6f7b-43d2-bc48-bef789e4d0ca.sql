-- Create security_scans table to store real scan results
CREATE TABLE public.security_scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('code', 'url', 'dependency')),
  target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE,
  metadata JSONB DEFAULT '{}'::jsonb
);

-- Create vulnerabilities table to store detected issues
CREATE TABLE public.vulnerabilities (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID REFERENCES public.security_scans(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  category TEXT NOT NULL,
  location TEXT,
  remediation TEXT,
  cve_id TEXT,
  cvss_score DECIMAL(3,1),
  status TEXT NOT NULL DEFAULT 'detected' CHECK (status IN ('detected', 'analyzing', 'resolved', 'false_positive')),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  resolved_at TIMESTAMP WITH TIME ZONE
);

-- Create security_stats table for real-time metrics
CREATE TABLE public.security_stats (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  metric_name TEXT NOT NULL UNIQUE,
  metric_value DECIMAL NOT NULL DEFAULT 0,
  previous_value DECIMAL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Insert initial stats
INSERT INTO public.security_stats (metric_name, metric_value, previous_value) VALUES
  ('threats_blocked', 0, 0),
  ('vulnerabilities_fixed', 0, 0),
  ('avg_response_time_ms', 0, 0),
  ('security_score', 100, 100),
  ('total_scans', 0, 0);

-- Enable RLS on all tables (public access for now since no auth)
ALTER TABLE public.security_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_stats ENABLE ROW LEVEL SECURITY;

-- Create policies for public access (demo mode)
CREATE POLICY "Allow public read access on security_scans" ON public.security_scans FOR SELECT USING (true);
CREATE POLICY "Allow public insert on security_scans" ON public.security_scans FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update on security_scans" ON public.security_scans FOR UPDATE USING (true);

CREATE POLICY "Allow public read access on vulnerabilities" ON public.vulnerabilities FOR SELECT USING (true);
CREATE POLICY "Allow public insert on vulnerabilities" ON public.vulnerabilities FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update on vulnerabilities" ON public.vulnerabilities FOR UPDATE USING (true);

CREATE POLICY "Allow public read access on security_stats" ON public.security_stats FOR SELECT USING (true);
CREATE POLICY "Allow public update on security_stats" ON public.security_stats FOR UPDATE USING (true);

-- Enable realtime for live updates
ALTER PUBLICATION supabase_realtime ADD TABLE public.vulnerabilities;
ALTER PUBLICATION supabase_realtime ADD TABLE public.security_stats;
ALTER PUBLICATION supabase_realtime ADD TABLE public.security_scans;