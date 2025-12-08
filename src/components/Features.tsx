import { Code, Brain, Eye, Workflow, Scan, Lock } from 'lucide-react';
import FeatureCard from './FeatureCard';

const Features = () => {
  const features = [
    {
      icon: Code,
      title: 'Code Security Analysis',
      description: 'AI-powered static analysis detects vulnerabilities in code with remediation suggestions.',
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
    <section id="features" className="py-20 px-4 sm:px-6 lg:px-8 bg-muted/30">
      <div className="max-w-7xl mx-auto">
        {/* Section header */}
        <div className="text-center mb-12">
          <h2 className="text-2xl sm:text-3xl font-semibold text-foreground mb-3">
            Security for modern development
          </h2>
          <p className="text-muted-foreground max-w-xl mx-auto">
            Comprehensive security coverage for AI-accelerated development workflows.
          </p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((feature) => (
            <FeatureCard
              key={feature.title}
              icon={feature.icon}
              title={feature.title}
              description={feature.description}
            />
          ))}
        </div>
      </div>
    </section>
  );
};

export default Features;