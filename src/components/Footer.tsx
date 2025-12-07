import { Shield, Github, Twitter, Linkedin } from 'lucide-react';

const Footer = () => {
  return (
    <footer className="relative py-16 px-6 border-t border-border">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-12 mb-12">
          {/* Brand */}
          <div className="md:col-span-1">
            <a href="/" className="flex items-center gap-2 mb-4">
              <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
                <Shield className="w-5 h-5 text-primary" />
              </div>
              <span className="font-display text-xl font-bold text-foreground">
                AEGIS<span className="text-primary">.ai</span>
              </span>
            </a>
            <p className="text-muted-foreground text-sm mb-4">
              AI-native application security for the modern development era.
            </p>
            <div className="flex gap-4">
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">
                <Github className="w-5 h-5" />
              </a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">
                <Twitter className="w-5 h-5" />
              </a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">
                <Linkedin className="w-5 h-5" />
              </a>
            </div>
          </div>

          {/* Links */}
          <div>
            <h4 className="font-display font-semibold text-foreground mb-4">Product</h4>
            <ul className="space-y-2">
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Features</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Pricing</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Integrations</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Changelog</a></li>
            </ul>
          </div>

          <div>
            <h4 className="font-display font-semibold text-foreground mb-4">Resources</h4>
            <ul className="space-y-2">
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Documentation</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">API Reference</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Security Blog</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Community</a></li>
            </ul>
          </div>

          <div>
            <h4 className="font-display font-semibold text-foreground mb-4">Company</h4>
            <ul className="space-y-2">
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">About</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Careers</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Contact</a></li>
              <li><a href="#" className="text-muted-foreground hover:text-foreground transition-colors text-sm">Privacy</a></li>
            </ul>
          </div>
        </div>

        {/* Bottom */}
        <div className="pt-8 border-t border-border flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-muted-foreground">
            © 2024 AEGIS.ai. All rights reserved.
          </p>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <a href="#" className="hover:text-foreground transition-colors">Terms</a>
            <a href="#" className="hover:text-foreground transition-colors">Privacy</a>
            <a href="#" className="hover:text-foreground transition-colors">Cookies</a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
