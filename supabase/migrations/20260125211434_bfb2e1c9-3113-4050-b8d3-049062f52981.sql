-- Create notification_preferences table for user email notification settings
CREATE TABLE public.notification_preferences (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL UNIQUE,
  email TEXT NOT NULL,
  notify_critical BOOLEAN NOT NULL DEFAULT true,
  notify_high BOOLEAN NOT NULL DEFAULT true,
  notify_medium BOOLEAN NOT NULL DEFAULT false,
  notify_low BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create index for fast lookups
CREATE INDEX idx_notification_prefs_user ON public.notification_preferences(user_id);

-- Enable RLS
ALTER TABLE public.notification_preferences ENABLE ROW LEVEL SECURITY;

-- Users can view their own preferences
CREATE POLICY "Users can view own notification prefs"
ON public.notification_preferences
FOR SELECT
USING (auth.uid() = user_id);

-- Users can insert their own preferences
CREATE POLICY "Users can insert own notification prefs"
ON public.notification_preferences
FOR INSERT
WITH CHECK (auth.uid() = user_id);

-- Users can update their own preferences
CREATE POLICY "Users can update own notification prefs"
ON public.notification_preferences
FOR UPDATE
USING (auth.uid() = user_id);

-- Users can delete their own preferences
CREATE POLICY "Users can delete own notification prefs"
ON public.notification_preferences
FOR DELETE
USING (auth.uid() = user_id);

-- Add trigger for updated_at
CREATE TRIGGER update_notification_prefs_updated_at
BEFORE UPDATE ON public.notification_preferences
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();