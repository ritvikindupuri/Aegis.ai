interface HeroProps {
  onStartChat: () => void;
}

const Hero = ({ onStartChat }: HeroProps) => {
  return (
    <section className="pt-20 pb-24 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto text-center">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-muted text-muted-foreground text-xs font-medium mb-8 tracking-wide uppercase">
          <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
          Now in Beta
        </div>

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

        {/* Simple CTA */}
        <a
          href="#agent"
          onClick={(e) => {
            e.preventDefault();
            onStartChat();
          }}
          className="inline-flex items-center gap-2 text-primary hover:text-primary/80 font-medium transition-colors group"
        >
          Start scanning
          <span className="group-hover:translate-x-0.5 transition-transform">→</span>
        </a>
      </div>
    </section>
  );
};

export default Hero;