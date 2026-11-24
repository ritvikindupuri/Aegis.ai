import AegisLogo from "@/components/AegisLogo";
const Footer = () => {
  return (
    <footer className="py-8 px-4 sm:px-6 lg:px-8 border-t border-border">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
        <a href="/" className="flex items-center gap-2">
          <AegisLogo className="w-5 h-5" compact />
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