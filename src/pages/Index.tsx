import { useRef } from 'react';
import Navbar from '@/components/Navbar';
import Hero from '@/components/Hero';
import Features from '@/components/Features';
import ThreatDashboard from '@/components/ThreatDashboard';
import SecurityAgent from '@/components/SecurityAgent';
import Footer from '@/components/Footer';

const Index = () => {
  const agentRef = useRef<HTMLDivElement>(null);

  const scrollToAgent = () => {
    agentRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar onStartChat={scrollToAgent} />
      
      <main>
        <Hero onStartChat={scrollToAgent} />
        <div id="features">
          <Features />
        </div>
        <div id="dashboard">
          <ThreatDashboard />
        </div>
        <div ref={agentRef}>
          <SecurityAgent />
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Index;