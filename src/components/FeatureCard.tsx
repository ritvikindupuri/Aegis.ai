import { LucideIcon } from 'lucide-react';

interface FeatureCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  gradient?: 'primary' | 'accent';
  delay?: number;
}

const FeatureCard = ({ icon: Icon, title, description, gradient = 'primary', delay = 0 }: FeatureCardProps) => {
  return (
    <div 
      className="group glass-strong rounded-2xl p-8 hover:scale-[1.02] transition-all duration-300 cursor-pointer animate-fade-in"
      style={{ animationDelay: `${delay}s` }}
    >
      <div className={`relative w-14 h-14 rounded-xl mb-6 flex items-center justify-center ${
        gradient === 'primary' ? 'bg-primary/10' : 'bg-accent/10'
      }`}>
        <Icon className={`w-7 h-7 ${gradient === 'primary' ? 'text-primary' : 'text-accent'}`} />
        <div className={`absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 ${
          gradient === 'primary' ? 'glow-primary' : 'glow-accent'
        }`} />
      </div>
      
      <h3 className="font-display text-xl font-semibold text-foreground mb-3 group-hover:text-primary transition-colors">
        {title}
      </h3>
      
      <p className="text-muted-foreground leading-relaxed">
        {description}
      </p>
      
      <div className="mt-6 flex items-center text-primary opacity-0 group-hover:opacity-100 transition-opacity">
        <span className="text-sm font-medium">Learn more</span>
        <svg className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
      </div>
    </div>
  );
};

export default FeatureCard;
