import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/button';
import { useState, useEffect } from 'react';

const Hero = () => {
  const { user } = useAuth();
  const [displayText, setDisplayText] = useState('');
  const [showCursor, setShowCursor] = useState(true);
  const fullText = 'Intelligent security';

  useEffect(() => {
    let index = 0;
    const typingInterval = setInterval(() => {
      if (index <= fullText.length) {
        setDisplayText(fullText.slice(0, index));
        index++;
      } else {
        clearInterval(typingInterval);
        // Keep cursor blinking after typing completes
        setTimeout(() => setShowCursor(false), 1500);
      }
    }, 80);

    return () => clearInterval(typingInterval);
  }, []);

  // Cursor blink effect
  useEffect(() => {
    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 530);

    return () => clearInterval(cursorInterval);
  }, []);

  return (
    <section className="pt-20 pb-24 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto text-center">
        {/* Main heading with typing animation */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold text-foreground tracking-tight mb-6 leading-[1.1]">
          <span className="inline-block min-h-[1.2em]">
            {displayText}
            <span 
              className={`inline-block w-[3px] h-[0.9em] bg-primary ml-1 align-middle transition-opacity duration-100 ${
                showCursor ? 'opacity-100' : 'opacity-0'
              }`}
            />
          </span>
          <br />
          <span className="text-primary/70 animate-fade-in" style={{ animationDelay: '1.5s', animationFillMode: 'both' }}>
            for modern apps
          </span>
        </h1>

        {/* Subheading */}
        <p className="text-base sm:text-lg text-muted-foreground max-w-xl mx-auto mb-10 leading-relaxed animate-fade-in" style={{ animationDelay: '2s', animationFillMode: 'both' }}>
          AI-powered vulnerability detection, threat analysis, and automated remediation. 
          Built for developers shipping fast.
        </p>

        {/* CTA */}
        {user ? (
          <a
            href="#agent"
            className="inline-flex items-center gap-2 text-primary hover:text-primary/80 font-medium transition-colors group animate-fade-in"
            style={{ animationDelay: '2.3s', animationFillMode: 'both' }}
          >
            Go to Dashboard
            <span className="group-hover:translate-x-0.5 transition-transform">→</span>
          </a>
        ) : (
          <div className="flex items-center justify-center gap-4 animate-fade-in" style={{ animationDelay: '2.3s', animationFillMode: 'both' }}>
            <a href="/auth">
              <Button size="lg">
                Get started free
              </Button>
            </a>
            <a
              href="#features"
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              Learn more →
            </a>
          </div>
        )}
      </div>
    </section>
  );
};

export default Hero;
