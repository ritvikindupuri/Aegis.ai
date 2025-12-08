import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';
import { cn } from '@/lib/utils';

interface ScoreHistoryEntry {
  timestamp: string;
  score: number;
  penalty: number;
}

interface ScoreHistoryChartProps {
  history: ScoreHistoryEntry[];
  className?: string;
}

const ScoreHistoryChart = ({ history, className }: ScoreHistoryChartProps) => {
  // Format data for the chart
  const chartData = history.map((entry, index) => ({
    name: new Date(entry.timestamp).toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }),
    score: entry.score,
    penalty: entry.penalty,
    index,
  }));

  // Custom tooltip
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-popover border border-border rounded-lg p-3 shadow-lg">
          <p className="text-xs text-muted-foreground mb-1">{label}</p>
          <p className={cn(
            "font-bold text-lg",
            data.score >= 80 ? 'text-success' :
            data.score >= 50 ? 'text-warning' : 'text-destructive'
          )}>
            Score: {data.score}
          </p>
          <p className="text-xs text-destructive">
            Penalty: -{data.penalty} pts
          </p>
        </div>
      );
    }
    return null;
  };

  if (history.length === 0) {
    return (
      <div className={cn("flex items-center justify-center h-[200px] text-muted-foreground text-sm", className)}>
        No score history yet. Run a scan to start tracking.
      </div>
    );
  }

  return (
    <div className={cn("h-[200px] w-full", className)}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
          <XAxis 
            dataKey="name" 
            tick={{ fontSize: 10 }} 
            className="text-muted-foreground"
            tickLine={false}
          />
          <YAxis 
            domain={[0, 100]} 
            tick={{ fontSize: 10 }} 
            className="text-muted-foreground"
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <ReferenceLine y={80} stroke="hsl(var(--success))" strokeDasharray="5 5" strokeOpacity={0.5} />
          <ReferenceLine y={50} stroke="hsl(var(--warning))" strokeDasharray="5 5" strokeOpacity={0.5} />
          <Line 
            type="monotone" 
            dataKey="score" 
            stroke="hsl(var(--primary))" 
            strokeWidth={2}
            dot={{ fill: 'hsl(var(--primary))', strokeWidth: 0, r: 4 }}
            activeDot={{ r: 6, fill: 'hsl(var(--primary))' }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ScoreHistoryChart;
