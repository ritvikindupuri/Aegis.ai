import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/button';

const Hero = () => {
  const { user } = useAuth();

  return (
    <section className="pt-20 pb-24 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto text-center">
        {/* Main heading */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold text-foreground tracking-tight mb-6 leading-[1.1]">
          Intelligent security
          <br />
          <span className="text-muted-foreground">for modern apps</span>
        </h1>

        {/* Subheading */}
        <p className="text-base sm:text-lg text-muted-foreground max-w-xl mx-auto mb-10 leading-relaxed">
          AI-powered vulnerability detection, threat analysis, and automated remediation. 
          Built for developers shipping fast.
        </p>

        {/* CTA */}
        {user ? (
          <a
            href="#agent"
            className="inline-flex items-center gap-2 text-primary hover:text-primary/80 font-medium transition-colors group"
          >
            Go to Dashboard
            <span className="group-hover:translate-x-0.5 transition-transform">→</span>
          </a>
        ) : (
          <div className="flex items-center justify-center gap-4">
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