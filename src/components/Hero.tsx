import { ArrowRight, Zap, Clock, Activity } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface HeroProps {
  onStartChat: () => void;
}

const Hero = ({ onStartChat }: HeroProps) => {
  return (
    <section className="pt-24 pb-16 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto text-center">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 text-primary text-sm font-medium mb-6">
          <span className="w-1.5 h-1.5 rounded-full bg-primary" />
          AI-Native Security Platform
        </div>

        {/* Main heading */}
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-foreground tracking-tight mb-6">
          Security for the{' '}
          <span className="text-gradient">AI era</span>
        </h1>

        {/* Subheading */}
        <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-8">
          Protect your AI-powered applications with next-generation agentic security. 
          Detect vulnerabilities, analyze threats, and remediate issues in real-time.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-16">
          <Button 
            onClick={onStartChat}
            size="lg" 
            className="gap-2"
          >
            Start Security Analysis
            <ArrowRight className="w-4 h-4" />
          </Button>
          <Button 
            variant="outline" 
            size="lg"
          >
            View Documentation
          </Button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 max-w-3xl mx-auto">
          <div className="p-6 rounded-xl border border-border bg-card">
            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center mx-auto mb-3">
              <Zap className="w-5 h-5 text-primary" />
            </div>
            <div className="text-2xl font-bold text-foreground mb-1">99.9%</div>
            <div className="text-sm text-muted-foreground">Detection Rate</div>
          </div>
          <div className="p-6 rounded-xl border border-border bg-card">
            <div className="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center mx-auto mb-3">
              <Clock className="w-5 h-5 text-success" />
            </div>
            <div className="text-2xl font-bold text-foreground mb-1">&lt;100ms</div>
            <div className="text-sm text-muted-foreground">Response Time</div>
          </div>
          <div className="p-6 rounded-xl border border-border bg-card">
            <div className="w-10 h-10 rounded-lg bg-warning/10 flex items-center justify-center mx-auto mb-3">
              <Activity className="w-5 h-5 text-warning" />
            </div>
            <div className="text-2xl font-bold text-foreground mb-1">24/7</div>
            <div className="text-sm text-muted-foreground">AI Monitoring</div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Hero;