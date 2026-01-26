import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface FeatureCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
}

const FeatureCard = ({ icon: Icon, title, description }: FeatureCardProps) => {
  return (
    <div className={cn(
      "group p-6 rounded-2xl border border-border bg-card",
      "hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5",
      "transition-all duration-300 ease-out",
      "hover:-translate-y-1"
    )}>
      <div className={cn(
        "w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center mb-5",
        "group-hover:bg-primary/15 group-hover:scale-110",
        "transition-all duration-300"
      )}>
        <Icon className="w-6 h-6 text-primary" />
      </div>
      
      <h3 className="text-lg font-semibold text-foreground mb-2 group-hover:text-primary transition-colors">
        {title}
      </h3>
      
      <p className="text-sm text-muted-foreground leading-relaxed">
        {description}
      </p>
    </div>
  );
};

export default FeatureCard;
