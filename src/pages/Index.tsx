import Navbar from '@/components/Navbar';
import Hero from '@/components/Hero';
import Features from '@/components/Features';
import ThreatDashboard from '@/components/ThreatDashboard';
import SecurityAgent from '@/components/SecurityAgent';
import Footer from '@/components/Footer';

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <main>
        <Hero />
        <div id="features">
          <Features />
        </div>
        <div id="dashboard">
          <ThreatDashboard />
        </div>
        <div>
          <SecurityAgent />
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Index;