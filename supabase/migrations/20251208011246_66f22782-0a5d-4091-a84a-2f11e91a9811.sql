-- Add INSERT policy for security_stats so the trigger can insert new stats
CREATE POLICY "Allow public insert on security_stats" 
ON public.security_stats 
FOR INSERT 
WITH CHECK (true);