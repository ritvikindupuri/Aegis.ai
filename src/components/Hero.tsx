import { Shield, Zap, Brain, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface HeroProps {
  onStartChat: () => void;
}

const Hero = ({ onStartChat }: HeroProps) => {
  return (
    <section className="relative min-h-screen flex items-center justify-center px-6 py-20">
      <div className="max-w-6xl mx-auto text-center relative z-10">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass mb-8 animate-fade-in">
          <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />
          <span className="text-sm text-muted-foreground">AI-Native Security Platform</span>
        </div>

        {/* Main heading */}
        <h1 className="font-display text-5xl md:text-7xl lg:text-8xl font-bold mb-6 animate-fade-in" style={{ animationDelay: '0.1s' }}>
          <span className="text-foreground">Welcome to the</span>
          <br />
          <span className="gradient-text text-glow">AI Native World</span>
        </h1>

        {/* Subheading */}
        <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-8 animate-fade-in" style={{ animationDelay: '0.2s' }}>
          Software's DNA has changed. The rules of application security will never be the same. 
          Protect your AI-powered applications with next-generation agentic security.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16 animate-fade-in" style={{ animationDelay: '0.3s' }}>
          <Button 
            onClick={onStartChat}
            size="lg" 
            className="group bg-primary text-primary-foreground hover:bg-primary/90 glow-primary px-8 py-6 text-lg font-semibold"
          >
            <Brain className="w-5 h-5 mr-2" />
            Start Security Analysis
            <ArrowRight className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform" />
          </Button>
          <Button 
            variant="outline" 
            size="lg"
            className="border-border bg-secondary/50 hover:bg-secondary text-foreground px-8 py-6 text-lg"
          >
            Watch Demo
          </Button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-3xl mx-auto animate-fade-in" style={{ animationDelay: '0.4s' }}>
          <div className="glass rounded-xl p-6 hover:glow-primary transition-all duration-300">
            <div className="flex items-center justify-center w-12 h-12 rounded-lg bg-primary/10 mx-auto mb-4">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <div className="text-3xl font-display font-bold text-foreground mb-2">99.9%</div>
            <div className="text-sm text-muted-foreground">Threat Detection Rate</div>
          </div>
          <div className="glass rounded-xl p-6 hover:glow-primary transition-all duration-300">
            <div className="flex items-center justify-center w-12 h-12 rounded-lg bg-accent/10 mx-auto mb-4">
              <Zap className="w-6 h-6 text-accent" />
            </div>
            <div className="text-3xl font-display font-bold text-foreground mb-2">&lt;100ms</div>
            <div className="text-sm text-muted-foreground">Response Time</div>
          </div>
          <div className="glass rounded-xl p-6 hover:glow-primary transition-all duration-300">
            <div className="flex items-center justify-center w-12 h-12 rounded-lg bg-primary/10 mx-auto mb-4">
              <Brain className="w-6 h-6 text-primary" />
            </div>
            <div className="text-3xl font-display font-bold text-foreground mb-2">24/7</div>
            <div className="text-sm text-muted-foreground">AI Monitoring</div>
          </div>
        </div>
      </div>

      {/* Gradient orbs */}
      <div className="absolute top-1/4 -left-32 w-64 h-64 bg-primary/20 rounded-full blur-[100px] animate-float" />
      <div className="absolute bottom-1/4 -right-32 w-64 h-64 bg-accent/20 rounded-full blur-[100px] animate-float" style={{ animationDelay: '2s' }} />
    </section>
  );
};

export default Hero;
