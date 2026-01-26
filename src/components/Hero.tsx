import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/button';
import { useState, useEffect } from 'react';
import { Shield, Zap, Github } from 'lucide-react';

const Hero = () => {
  const { user } = useAuth();
  const [displayText, setDisplayText] = useState('');
  const [showCursor, setShowCursor] = useState(true);
  const fullText = 'Intelligent security';

  useEffect(() => {
    let index = 0;
    let isDeleting = false;
    let pauseTimeout: ReturnType<typeof setTimeout>;
    
    const typingInterval = setInterval(() => {
      if (!isDeleting) {
        if (index <= fullText.length) {
          setDisplayText(fullText.slice(0, index));
          index++;
        } else {
          clearInterval(typingInterval);
          pauseTimeout = setTimeout(() => {
            isDeleting = true;
            startTyping();
          }, 2000);
        }
      } else {
        if (index > 0) {
          index--;
          setDisplayText(fullText.slice(0, index));
        } else {
          clearInterval(typingInterval);
          pauseTimeout = setTimeout(() => {
            isDeleting = false;
            startTyping();
          }, 500);
        }
      }
    }, isDeleting ? 40 : 80);

    function startTyping() {
      index = isDeleting ? fullText.length : 0;
      const newInterval = setInterval(() => {
        if (!isDeleting) {
          if (index <= fullText.length) {
            setDisplayText(fullText.slice(0, index));
            index++;
          } else {
            clearInterval(newInterval);
            setTimeout(() => {
              isDeleting = true;
              startTyping();
            }, 2000);
          }
        } else {
          if (index > 0) {
            index--;
            setDisplayText(fullText.slice(0, index));
          } else {
            clearInterval(newInterval);
            setTimeout(() => {
              isDeleting = false;
              startTyping();
            }, 500);
          }
        }
      }, isDeleting ? 40 : 80);
    }

    return () => {
      clearInterval(typingInterval);
      clearTimeout(pauseTimeout);
    };
  }, []);

  // Cursor blink effect
  useEffect(() => {
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 530);

    return () => clearInterval(cursorInterval);
  }, []);

  return (
    <section className="pt-24 pb-32 px-4 sm:px-6 lg:px-8 relative overflow-hidden">
      {/* Decorative floating elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {/* Floating orbs */}
        <div className="absolute top-20 left-[10%] w-64 h-64 bg-primary/5 rounded-full blur-3xl animate-float" />
        <div className="absolute top-40 right-[15%] w-48 h-48 bg-primary/8 rounded-full blur-3xl animate-float" style={{ animationDelay: '-2s' }} />
        <div className="absolute bottom-20 left-[20%] w-56 h-56 bg-primary/4 rounded-full blur-3xl animate-float" style={{ animationDelay: '-4s' }} />
        
        {/* Subtle gradient lines */}
        <div className="absolute top-1/4 left-0 w-full h-px bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
        <div className="absolute top-3/4 left-0 w-full h-px bg-gradient-to-r from-transparent via-primary/10 to-transparent" />
      </div>

      <div className="max-w-5xl mx-auto text-center relative z-10">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-8 animate-fade-in">
          <Shield className="w-4 h-4" />
          <span>AI-Powered Security Platform</span>
          <Zap className="w-4 h-4" />
        </div>

        {/* Main heading with typing animation */}
        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold text-foreground tracking-tight mb-8 leading-[1.05]">
          <span className="inline-block min-h-[1.2em]">
            {displayText}
            <span 
              className={`inline-block w-[4px] h-[0.85em] bg-primary ml-1 align-middle rounded-sm transition-opacity duration-100 ${
                showCursor ? 'opacity-100' : 'opacity-0'
              }`}
            />
          </span>
          <br />
          <span className="text-gradient opacity-0 animate-fade-in" style={{ animationDelay: '1.5s', animationFillMode: 'forwards' }}>
            for modern apps
          </span>
        </h1>

        {/* Subheading */}
        <p className="text-lg sm:text-xl text-muted-foreground max-w-2xl mx-auto mb-12 leading-relaxed opacity-0 animate-fade-in" style={{ animationDelay: '2s', animationFillMode: 'forwards' }}>
          AI-powered vulnerability detection with GitHub repository scanning, 
          threat analysis, and automated remediation. 
          <span className="text-foreground font-medium"> Built for developers shipping fast.</span>
        </p>

        {/* CTA */}
        {user ? (
          <a
            href="#agent"
            className="inline-flex items-center gap-2 text-primary hover:text-primary/80 font-medium transition-colors group opacity-0 animate-fade-in"
            style={{ animationDelay: '2.3s', animationFillMode: 'forwards' }}
          >
            Go to Dashboard
            <span className="group-hover:translate-x-0.5 transition-transform">→</span>
          </a>
        ) : (
          <div className="flex items-center justify-center gap-5 opacity-0 animate-fade-in" style={{ animationDelay: '2.3s', animationFillMode: 'forwards' }}>
            <a href="/auth">
              <Button size="lg" className="h-12 px-8 text-base font-semibold shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30 transition-all">
                Get started free
              </Button>
            </a>
            <a
              href="#features"
              className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors font-medium"
            >
              <span>Learn more</span>
              <span>→</span>
            </a>
          </div>
        )}

        {/* Trust indicators */}
        <div className="mt-16 pt-12 border-t border-border/50 opacity-0 animate-fade-in" style={{ animationDelay: '2.6s', animationFillMode: 'forwards' }}>
          <p className="text-xs text-muted-foreground uppercase tracking-wider mb-6">Powered by</p>
          <div className="flex items-center justify-center gap-8 flex-wrap">
            <div className="flex items-center gap-2 text-muted-foreground">
              <Github className="w-5 h-5" />
              <span className="text-sm font-medium">GitHub Integration</span>
            </div>
            <div className="w-px h-4 bg-border hidden sm:block" />
            <div className="flex items-center gap-2 text-muted-foreground">
              <Shield className="w-5 h-5" />
              <span className="text-sm font-medium">OWASP Top 10</span>
            </div>
            <div className="w-px h-4 bg-border hidden sm:block" />
            <div className="flex items-center gap-2 text-muted-foreground">
              <Zap className="w-5 h-5" />
              <span className="text-sm font-medium">Real-time NVD</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Hero;
