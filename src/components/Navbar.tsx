import { useState } from 'react';
import { Menu, X, LogOut } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

interface NavbarProps {
  onStartChat: () => void;
}

const Navbar = ({ onStartChat }: NavbarProps) => {
  const [isOpen, setIsOpen] = useState(false);
  const { user, profile, signOut } = useAuth();

  const navLinks = [
    { label: 'Features', href: '#features' },
    { label: 'Dashboard', href: '#dashboard' },
    { label: 'Agent', href: '#agent' },
  ];

  return (
    <nav className="sticky top-0 z-50 bg-background/80 backdrop-blur-md border-b border-border/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Logo */}
          <a href="/" className="flex items-center gap-2.5 group">
            <div className="relative w-8 h-8">
              <div className="absolute inset-0 rounded-lg bg-gradient-to-br from-primary via-primary/80 to-primary/60 opacity-90" />
              <div className="absolute inset-[2px] rounded-[6px] bg-background/95" />
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-primary font-black text-sm tracking-tighter">Æ</span>
              </div>
            </div>
            <span className="text-lg font-bold tracking-tight text-foreground">
              AEGIS<span className="text-primary font-light">.ai</span>
            </span>
          </a>

          {/* Desktop nav */}
          <div className="hidden md:flex items-center gap-6">
            {navLinks.map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                {link.label}
              </a>
            ))}
            <a
              href="#agent"
              onClick={(e) => {
                e.preventDefault();
                onStartChat();
              }}
              className="text-sm font-medium text-primary hover:text-primary/80 transition-colors"
            >
              Try it →
            </a>
            
            {/* Auth button */}
            {user ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" className="h-8">
                    {profile?.display_name || user.email?.split('@')[0]}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={signOut}>
                    <LogOut className="w-4 h-4 mr-2" />
                    Sign out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : (
              <a href="/auth">
                <Button variant="outline" size="sm" className="h-8">
                  Sign in
                </Button>
              </a>
            )}
          </div>

          {/* Mobile menu button */}
          <button
            onClick={() => setIsOpen(!isOpen)}
            className="md:hidden p-2 text-foreground"
          >
            {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>

        {/* Mobile menu */}
        <div className={cn(
          'md:hidden overflow-hidden transition-all duration-200',
          isOpen ? 'max-h-64 pb-4' : 'max-h-0'
        )}>
          <div className="flex flex-col gap-1 pt-2">
            {navLinks.map((link) => (
              <a
                key={link.label}
                href={link.href}
                onClick={() => setIsOpen(false)}
                className="text-sm text-muted-foreground hover:text-foreground transition-colors py-2"
              >
                {link.label}
              </a>
            ))}
            <a
              href="#agent"
              onClick={(e) => {
                e.preventDefault();
                setIsOpen(false);
                onStartChat();
              }}
              className="text-sm font-medium text-primary py-2"
            >
              Try it →
            </a>
            
            {/* Mobile auth */}
            {user ? (
              <button
                onClick={() => {
                  signOut();
                  setIsOpen(false);
                }}
                className="text-sm text-muted-foreground hover:text-foreground transition-colors py-2 text-left flex items-center gap-2"
              >
                <LogOut className="w-4 h-4" />
                Sign out
              </button>
            ) : (
              <a
                href="/auth"
                onClick={() => setIsOpen(false)}
                className="text-sm font-medium text-primary py-2"
              >
                Sign in
              </a>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;