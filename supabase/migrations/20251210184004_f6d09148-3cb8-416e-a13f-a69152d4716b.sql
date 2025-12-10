-- Add user_id columns to security tables
ALTER TABLE public.vulnerabilities ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE;
ALTER TABLE public.security_scans ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE;
ALTER TABLE public.security_stats ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_user_id ON public.vulnerabilities(user_id);
CREATE INDEX IF NOT EXISTS idx_security_scans_user_id ON public.security_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_security_stats_user_id ON public.security_stats(user_id);

-- Drop existing public policies on vulnerabilities
DROP POLICY IF EXISTS "Allow public read access on vulnerabilities" ON public.vulnerabilities;
DROP POLICY IF EXISTS "Allow public insert on vulnerabilities" ON public.vulnerabilities;
DROP POLICY IF EXISTS "Allow public update on vulnerabilities" ON public.vulnerabilities;
DROP POLICY IF EXISTS "Allow public delete on vulnerabilities" ON public.vulnerabilities;

-- Create user-scoped policies for vulnerabilities
CREATE POLICY "Users can view own vulnerabilities" ON public.vulnerabilities FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own vulnerabilities" ON public.vulnerabilities FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own vulnerabilities" ON public.vulnerabilities FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own vulnerabilities" ON public.vulnerabilities FOR DELETE USING (auth.uid() = user_id);

-- Drop existing public policies on security_scans
DROP POLICY IF EXISTS "Allow public read access on security_scans" ON public.security_scans;
DROP POLICY IF EXISTS "Allow public insert on security_scans" ON public.security_scans;
DROP POLICY IF EXISTS "Allow public update on security_scans" ON public.security_scans;
DROP POLICY IF EXISTS "Allow public delete on security_scans" ON public.security_scans;

-- Create user-scoped policies for security_scans
CREATE POLICY "Users can view own scans" ON public.security_scans FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own scans" ON public.security_scans FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own scans" ON public.security_scans FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own scans" ON public.security_scans FOR DELETE USING (auth.uid() = user_id);

-- Drop existing public policies on security_stats
DROP POLICY IF EXISTS "Allow public read access on security_stats" ON public.security_stats;
DROP POLICY IF EXISTS "Allow public insert on security_stats" ON public.security_stats;
DROP POLICY IF EXISTS "Allow public update on security_stats" ON public.security_stats;

-- Create user-scoped policies for security_stats
CREATE POLICY "Users can view own stats" ON public.security_stats FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own stats" ON public.security_stats FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own stats" ON public.security_stats FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own stats" ON public.security_stats FOR DELETE USING (auth.uid() = user_id);