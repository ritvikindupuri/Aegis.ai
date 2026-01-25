-- Create table for scheduled scan configurations
CREATE TABLE public.scheduled_scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  repo_url TEXT NOT NULL,
  repo_name TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  last_scan_at TIMESTAMP WITH TIME ZONE,
  last_scan_result JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE(user_id, repo_url)
);

-- Enable RLS
ALTER TABLE public.scheduled_scans ENABLE ROW LEVEL SECURITY;

-- RLS policies
CREATE POLICY "Users can view own scheduled scans"
ON public.scheduled_scans FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own scheduled scans"
ON public.scheduled_scans FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own scheduled scans"
ON public.scheduled_scans FOR UPDATE
USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own scheduled scans"
ON public.scheduled_scans FOR DELETE
USING (auth.uid() = user_id);

-- Add trigger for updated_at
CREATE TRIGGER update_scheduled_scans_updated_at
  BEFORE UPDATE ON public.scheduled_scans
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

-- Create index for faster queries
CREATE INDEX idx_scheduled_scans_user_id ON public.scheduled_scans(user_id);
CREATE INDEX idx_scheduled_scans_active ON public.scheduled_scans(is_active) WHERE is_active = true;