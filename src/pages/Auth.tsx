import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import { Loader2, Mail, Lock, ArrowLeft, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import { z } from 'zod';
import zxcvbn from 'zxcvbn';
import { cn } from '@/lib/utils';

const emailSchema = z.string().email('Please enter a valid email address');
const passwordSchema = z.string().min(8, 'Password must be at least 8 characters');

interface PasswordStrength {
  score: number;
  feedback: {
    warning: string;
    suggestions: string[];
  };
  crackTime: string;
}

const Auth = () => {
  const navigate = useNavigate();
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<{ email?: string; password?: string; confirmPassword?: string }>({});

  // Calculate password strength using zxcvbn
  const passwordStrength = useMemo((): PasswordStrength | null => {
    if (!password || isLogin) return null;
    
    const result = zxcvbn(password, [email.split('@')[0], 'aegis', 'security']);
    return {
      score: result.score,
      feedback: result.feedback,
      crackTime: result.crack_times_display.offline_slow_hashing_1e4_per_second as string,
    };
  }, [password, email, isLogin]);

  const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
  const strengthColors = [
    'bg-destructive',
    'bg-orange-500',
    'bg-amber-500',
    'bg-primary',
    'bg-success',
  ];

  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (session?.user) {
        navigate('/');
      }
    });

    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session?.user) {
        navigate('/');
      }
    });

    return () => subscription.unsubscribe();
  }, [navigate]);

  const validateForm = () => {
    const newErrors: typeof errors = {};
    
    const emailResult = emailSchema.safeParse(email);
    if (!emailResult.success) {
      newErrors.email = emailResult.error.errors[0].message;
    }
    
    const passwordResult = passwordSchema.safeParse(password);
    if (!passwordResult.success) {
      newErrors.password = passwordResult.error.errors[0].message;
    }
    
    // For signup, require minimum password strength
    if (!isLogin && passwordStrength && passwordStrength.score < 2) {
      newErrors.password = 'Password is too weak. Please choose a stronger password.';
    }
    
    if (!isLogin && password !== confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    setIsLoading(true);

    try {
      if (isLogin) {
        const { error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });
        
        if (error) {
          if (error.message.includes('Invalid login credentials')) {
            toast.error('Invalid email or password');
          } else {
            toast.error(error.message);
          }
          return;
        }
        
        toast.success('Signed in successfully');
      } else {
        const { error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            emailRedirectTo: `${window.location.origin}/`,
          },
        });
        
        if (error) {
          if (error.message.includes('already registered')) {
            toast.error('This email is already registered. Try signing in instead.');
          } else {
            toast.error(error.message);
          }
          return;
        }
        
        toast.success('Account created successfully!');
      }
    } catch (error) {
      toast.error('An unexpected error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="p-4 border-b border-border">
        <a href="/" className="flex items-center gap-2.5 w-fit">
          <div className="relative w-8 h-8">
            <div className="absolute inset-0 rounded-lg bg-gradient-to-br from-primary via-primary/80 to-primary/60 opacity-90" />
            <div className="absolute inset-[2px] rounded-[6px] bg-background/95" />
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-primary font-black text-sm tracking-tighter">Æ</span>
            </div>
          </div>
          <span className="text-lg font-bold tracking-tight text-foreground">
            AEGIS<span className="text-primary font-light">.ai</span>
          </span>
        </a>
      </header>

      {/* Main content */}
      <main className="flex-1 flex items-center justify-center p-4">
        <div className="w-full max-w-sm">
          <div className="text-center mb-8">
            <h1 className="text-2xl font-semibold text-foreground mb-2">
              {isLogin ? 'Welcome back' : 'Create account'}
            </h1>
            <p className="text-sm text-muted-foreground">
              {isLogin ? 'Sign in to access your security dashboard' : 'Get started with AEGIS.ai'}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={`pl-10 ${errors.email ? 'border-destructive' : ''}`}
                  disabled={isLoading}
                />
              </div>
              {errors.email && <p className="text-xs text-destructive">{errors.email}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={`pl-10 ${errors.password ? 'border-destructive' : ''}`}
                  disabled={isLoading}
                />
              </div>
              {errors.password && <p className="text-xs text-destructive">{errors.password}</p>}
              
              {/* Password Strength Indicator - only show during signup */}
              {!isLogin && password && passwordStrength && (
                <div className="space-y-2 pt-1">
                  {/* Strength Bar */}
                  <div className="flex gap-1">
                    {[0, 1, 2, 3, 4].map((level) => (
                      <div
                        key={level}
                        className={cn(
                          'h-1.5 flex-1 rounded-full transition-colors',
                          level <= passwordStrength.score
                            ? strengthColors[passwordStrength.score]
                            : 'bg-muted'
                        )}
                      />
                    ))}
                  </div>
                  
                  {/* Strength Label and Crack Time */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      {passwordStrength.score >= 2 ? (
                        <CheckCircle className="w-3.5 h-3.5 text-success" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5 text-destructive" />
                      )}
                      <span className={cn(
                        'text-xs font-medium',
                        passwordStrength.score >= 3 ? 'text-success' :
                        passwordStrength.score >= 2 ? 'text-primary' :
                        passwordStrength.score >= 1 ? 'text-amber-500' : 'text-destructive'
                      )}>
                        {strengthLabels[passwordStrength.score]}
                      </span>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      Crack time: {passwordStrength.crackTime}
                    </span>
                  </div>
                  
                  {/* Warning */}
                  {passwordStrength.feedback.warning && (
                    <div className="flex items-start gap-2 p-2 rounded-md bg-destructive/10 border border-destructive/20">
                      <AlertTriangle className="w-4 h-4 text-destructive shrink-0 mt-0.5" />
                      <p className="text-xs text-destructive">
                        {passwordStrength.feedback.warning}
                      </p>
                    </div>
                  )}
                  
                  {/* Suggestions */}
                  {passwordStrength.feedback.suggestions.length > 0 && passwordStrength.score < 3 && (
                    <div className="flex items-start gap-2 p-2 rounded-md bg-muted/50 border border-border">
                      <Info className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
                      <div className="text-xs text-muted-foreground">
                        {passwordStrength.feedback.suggestions.map((suggestion, i) => (
                          <p key={i}>{suggestion}</p>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {!isLogin && (
              <div className="space-y-2">
                <Label htmlFor="confirmPassword">Confirm Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    id="confirmPassword"
                    type="password"
                    placeholder="••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className={`pl-10 ${errors.confirmPassword ? 'border-destructive' : ''}`}
                    disabled={isLoading}
                  />
                </div>
                {errors.confirmPassword && <p className="text-xs text-destructive">{errors.confirmPassword}</p>}
              </div>
            )}

            <Button 
              type="submit" 
              className="w-full" 
              disabled={isLoading || (!isLogin && passwordStrength && passwordStrength.score < 2)}
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  {isLogin ? 'Signing in...' : 'Creating account...'}
                </>
              ) : (
                isLogin ? 'Sign in' : 'Create account'
              )}
            </Button>
          </form>

          <div className="mt-6 text-center">
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setErrors({});
              }}
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              {isLogin ? "Don't have an account? " : 'Already have an account? '}
              <span className="text-primary font-medium">
                {isLogin ? 'Sign up' : 'Sign in'}
              </span>
            </button>
          </div>

          <div className="mt-8">
            <a
              href="/"
              className="flex items-center justify-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to home
            </a>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Auth;
