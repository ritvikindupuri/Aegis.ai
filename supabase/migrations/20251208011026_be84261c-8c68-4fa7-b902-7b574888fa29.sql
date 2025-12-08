-- Drop the existing check constraint and add a new one with llm_protection
ALTER TABLE public.security_scans DROP CONSTRAINT IF EXISTS security_scans_scan_type_check;

ALTER TABLE public.security_scans 
ADD CONSTRAINT security_scans_scan_type_check 
CHECK (scan_type IN ('code', 'url', 'dependency', 'llm_protection'));