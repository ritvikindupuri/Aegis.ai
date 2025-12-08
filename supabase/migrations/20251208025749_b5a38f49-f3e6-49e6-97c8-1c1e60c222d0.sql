-- Add DELETE policies for vulnerabilities and security_scans tables
CREATE POLICY "Allow public delete on vulnerabilities" 
ON public.vulnerabilities 
FOR DELETE 
USING (true);

CREATE POLICY "Allow public delete on security_scans" 
ON public.security_scans 
FOR DELETE 
USING (true);