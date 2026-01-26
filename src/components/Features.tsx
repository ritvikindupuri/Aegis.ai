import { Code, Brain, Eye, Workflow, Scan, Lock, Github, ArrowRight } from 'lucide-react';
import FeatureCard from './FeatureCard';

const Features = () => {
  const features = [
    {
      icon: Code,
      title: 'Code Security Analysis',
      description: 'AI-powered static analysis detects vulnerabilities in code with remediation suggestions.',
    },
    {
      icon: Github,
      title: 'GitHub Repository Scanning',
      description: 'Scan entire GitHub repositories for vulnerabilities with daily automated monitoring.',
    },
    {
      icon: Brain,
      title: 'LLM Protection',
      description: 'Detect and block prompt injection, jailbreaks, and adversarial inputs to your AI systems.',
    },
    {
      icon: Eye,
      title: 'Unified Visibility',
      description: 'Track vulnerabilities across code, dependencies, and AI components in one dashboard.',
    },
    {
      icon: Workflow,
      title: 'Auto-Remediation',
      description: 'Get AI-generated fixes you can apply with one click to resolve issues faster.',
    },
    {
      icon: Scan,
      title: 'Real-Time Scanning',
      description: 'On-demand security scans powered by AI agents for immediate threat detection.',
    },
    {
      icon: Lock,
      title: 'Dependency Scanning',
      description: 'Identify vulnerable packages and outdated dependencies with upgrade recommendations.',
    },
  ];

  return (
    <section id="features" className="py-24 px-4 sm:px-6 lg:px-8 relative">
      {/* Background decoration */}
      <div className="absolute inset-0 bg-gradient-to-b from-muted/50 via-muted/30 to-transparent pointer-events-none" />
      
      <div className="max-w-7xl mx-auto relative z-10">
        {/* Section header */}
        <div className="text-center mb-16">
          <p className="text-primary font-semibold text-sm uppercase tracking-wider mb-3">Features</p>
          <h2 className="text-3xl sm:text-4xl font-bold text-foreground mb-4">
            Security for modern development
          </h2>
          <p className="text-muted-foreground max-w-xl mx-auto text-lg">
            Comprehensive security coverage for AI-accelerated development workflows.
          </p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {features.map((feature, index) => (
            <div 
              key={feature.title}
              className="opacity-0 animate-fade-in-up"
              style={{ 
                animationDelay: `${index * 100}ms`, 
                animationFillMode: 'forwards' 
              }}
            >
              <FeatureCard
                icon={feature.icon}
                title={feature.title}
                description={feature.description}
              />
            </div>
          ))}
        </div>

        {/* Bottom CTA */}
        <div className="mt-16 text-center">
          <a 
            href="#dashboard" 
            className="inline-flex items-center gap-2 text-primary hover:text-primary/80 font-semibold transition-colors group"
          >
            <span>See it in action</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </a>
        </div>
      </div>
    </section>
  );
};

export default Features;
