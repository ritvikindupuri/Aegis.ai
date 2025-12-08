const Footer = () => {
  return (
    <footer className="py-8 px-4 sm:px-6 lg:px-8 border-t border-border">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
        <a href="/" className="flex items-center gap-2">
          <div className="w-5 h-5 rounded bg-gradient-to-br from-primary to-primary/70 flex items-center justify-center">
            <span className="text-primary-foreground font-bold text-[8px]">Æ</span>
          </div>
          <span className="text-sm font-medium text-foreground">
            aegis<span className="text-primary">.ai</span>
          </span>
        </a>
        <p className="text-xs text-muted-foreground">
          © 2024 aegis.ai
        </p>
      </div>
    </footer>
  );
};

export default Footer;