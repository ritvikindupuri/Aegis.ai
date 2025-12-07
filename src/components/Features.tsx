import { Brain, Eye, Workflow, Code, Lock, Scan } from 'lucide-react';
import FeatureCard from './FeatureCard';

const Features = () => {
  const features = [
    {
      icon: Code,
      title: 'AI-Generated Code Security',
      description: 'Analyze and secure code written by humans & machines with deep semantic understanding.',
    },
    {
      icon: Brain,
      title: 'LLM Protection',
      description: 'Protect LLMs, agents, and AI-driven components from prompt injection and model attacks.',
    },
    {
      icon: Eye,
      title: 'Platform Visibility',
      description: 'See every risk across code, dependencies, containers, and AI in one unified dashboard.',
    },
    {
      icon: Workflow,
      title: 'AI Remediation',
      description: 'Close risks fast with AI-powered workflows that prioritize and auto-fix vulnerabilities.',
    },
    {
      icon: Scan,
      title: 'Real-Time Detection',
      description: 'Continuous monitoring with AI agents that detect and respond to threats instantly.',
    },
    {
      icon: Lock,
      title: 'Zero-Trust Architecture',
      description: 'Built-in zero-trust principles with continuous verification and least-privilege access.',
    },
  ];

  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8 bg-muted/30">
      <div className="max-w-7xl mx-auto">
        {/* Section header */}
        <div className="text-center mb-12">
          <h2 className="text-3xl sm:text-4xl font-bold text-foreground mb-4">
            Built for AI-native development
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Purpose-built security for AI-accelerated development with intelligent automation at every layer.
          </p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
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