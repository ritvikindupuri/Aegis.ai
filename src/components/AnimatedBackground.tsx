const AnimatedBackground = () => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {/* Animated gradient mesh */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-primary/10 rounded-full blur-[120px] animate-blob" />
        <div className="absolute top-1/3 right-1/4 w-[500px] h-[500px] bg-primary/8 rounded-full blur-[100px] animate-blob animation-delay-2000" />
        <div className="absolute bottom-0 left-1/3 w-[550px] h-[550px] bg-primary/6 rounded-full blur-[110px] animate-blob animation-delay-4000" />
      </div>
      
      {/* Subtle grid overlay */}
      <div 
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(hsl(var(--foreground)) 1px, transparent 1px),
                           linear-gradient(90deg, hsl(var(--foreground)) 1px, transparent 1px)`,
          backgroundSize: '60px 60px'
        }}
      />
      
      {/* Radial gradient overlay */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-background/50 to-background" />
    </div>
  );
};

export default AnimatedBackground;
