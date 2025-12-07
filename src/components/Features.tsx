import { Shield, Brain, Eye, Workflow, Code, Lock } from 'lucide-react';
import FeatureCard from './FeatureCard';

const Features = () => {
  const features = [
    {
      icon: Code,
      title: 'Securing AI Generated Code',
      description: 'Go beyond static tools—analyze and secure code written by humans & machines with deep semantic understanding.',
      gradient: 'primary' as const,
    },
    {
      icon: Brain,
      title: 'Securing AI Powered Applications',
      description: 'Protect LLMs, agents, models, and all AI-driven app components from prompt injection and model attacks.',
      gradient: 'accent' as const,
    },
    {
      icon: Eye,
      title: 'Holistic Platform Visibility',
      description: 'See every risk and vector—across code, open source, containers, and AI—in one unified security dashboard.',
      gradient: 'primary' as const,
    },
    {
      icon: Workflow,
      title: 'AI-Based Remediation Workflows',
      description: 'Close risks fast with next-generation, AI-powered remediation workflows that prioritize and auto-fix vulnerabilities.',
      gradient: 'accent' as const,
    },
    {
      icon: Shield,
      title: 'Real-Time Threat Detection',
      description: 'Continuous monitoring with AI agents that detect and respond to security threats in milliseconds.',
      gradient: 'primary' as const,
    },
    {
      icon: Lock,
      title: 'Zero-Trust Architecture',
      description: 'Built-in zero-trust security principles with continuous verification and least-privilege access controls.',
      gradient: 'accent' as const,
    },
  ];

  return (
    <section className="relative py-24 px-6">
      <div className="max-w-7xl mx-auto">
        {/* Section header */}
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl md:text-5xl font-bold text-foreground mb-4 animate-fade-in">
            What makes this an{' '}
            <span className="gradient-text">AI-Native</span> platform
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto animate-fade-in" style={{ animationDelay: '0.1s' }}>
            Purpose-built for secure AI-accelerated development with intelligent automation at every layer.
          </p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => (
            <FeatureCard
              key={feature.title}
              icon={feature.icon}
              title={feature.title}
              description={feature.description}
              gradient={feature.gradient}
              delay={0.1 + index * 0.1}
            />
          ))}
        </div>
      </div>
    </section>
  );
};

export default Features;
