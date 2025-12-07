import { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Loader2, Shield, Code, AlertTriangle, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';
import ReactMarkdown from 'react-markdown';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

type AgentMode = 'security' | 'code_review' | 'threat_intel' | 'general';

const SecurityAgent = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [mode, setMode] = useState<AgentMode>('security');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const modes = [
    { id: 'security' as const, label: 'SENTINEL', icon: Shield, description: 'Security Analysis' },
    { id: 'code_review' as const, label: 'CODEX', icon: Code, description: 'Code Review' },
    { id: 'threat_intel' as const, label: 'AEGIS', icon: AlertTriangle, description: 'Threat Intel' },
    { id: 'general' as const, label: 'ASSIST', icon: Sparkles, description: 'General Help' },
  ];

  const streamChat = async (userMessage: string) => {
    setIsLoading(true);
    const newMessages = [...messages, { role: 'user' as const, content: userMessage }];
    setMessages(newMessages);
    setInput('');

    let assistantContent = '';

    try {
      const response = await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/security-agent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        },
        body: JSON.stringify({ messages: newMessages, mode }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to get response');
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error('No reader available');

      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        let newlineIndex: number;
        while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
          let line = buffer.slice(0, newlineIndex);
          buffer = buffer.slice(newlineIndex + 1);

          if (line.endsWith('\r')) line = line.slice(0, -1);
          if (line.startsWith(':') || line.trim() === '') continue;
          if (!line.startsWith('data: ')) continue;

          const jsonStr = line.slice(6).trim();
          if (jsonStr === '[DONE]') break;

          try {
            const parsed = JSON.parse(jsonStr);
            const content = parsed.choices?.[0]?.delta?.content;
            if (content) {
              assistantContent += content;
              setMessages([...newMessages, { role: 'assistant', content: assistantContent }]);
            }
          } catch {
            buffer = line + '\n' + buffer;
            break;
          }
        }
      }
    } catch (error) {
      console.error('Chat error:', error);
      setMessages([
        ...newMessages,
        { role: 'assistant', content: `Error: ${error instanceof Error ? error.message : 'Something went wrong. Please try again.'}` },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim() && !isLoading) {
      streamChat(input.trim());
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const quickPrompts = [
    'Analyze my code for security vulnerabilities',
    'What are the top AI security risks?',
    'How do I prevent prompt injection attacks?',
    'Review my authentication implementation',
  ];

  return (
    <section id="agent" className="relative py-24 px-6">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h2 className="font-display text-3xl md:text-5xl font-bold text-foreground mb-4">
            <span className="gradient-text">AI Security Agent</span>
          </h2>
          <p className="text-muted-foreground">
            Interact with our intelligent security agents for real-time analysis
          </p>
        </div>

        {/* Mode selector */}
        <div className="flex flex-wrap justify-center gap-2 mb-6">
          {modes.map((m) => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-200',
                mode === m.id
                  ? 'bg-primary text-primary-foreground glow-primary'
                  : 'glass hover:bg-secondary'
              )}
            >
              <m.icon className="w-4 h-4" />
              <span className="font-medium">{m.label}</span>
            </button>
          ))}
        </div>

        {/* Chat container */}
        <div className="glass-strong rounded-2xl overflow-hidden">
          {/* Messages area */}
          <div className="h-[500px] overflow-y-auto p-6 space-y-4">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center">
                <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mb-4 animate-pulse-glow">
                  <Bot className="w-8 h-8 text-primary" />
                </div>
                <h3 className="font-display text-xl font-semibold text-foreground mb-2">
                  {modes.find(m => m.id === mode)?.label} Agent Ready
                </h3>
                <p className="text-muted-foreground mb-6 max-w-md">
                  {mode === 'security' && 'I can analyze your application for vulnerabilities and provide remediation guidance.'}
                  {mode === 'code_review' && 'Paste your code and I\'ll review it for security issues and best practices.'}
                  {mode === 'threat_intel' && 'Ask me about emerging threats, attack vectors, and security trends.'}
                  {mode === 'general' && 'How can I help you with your security questions today?'}
                </p>

                {/* Quick prompts */}
                <div className="flex flex-wrap gap-2 justify-center">
                  {quickPrompts.slice(0, 2).map((prompt) => (
                    <button
                      key={prompt}
                      onClick={() => setInput(prompt)}
                      className="px-3 py-1.5 text-sm glass rounded-lg hover:bg-secondary transition-colors"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((message, index) => (
                <div
                  key={index}
                  className={cn(
                    'flex gap-3 animate-fade-in',
                    message.role === 'user' ? 'justify-end' : 'justify-start'
                  )}
                >
                  {message.role === 'assistant' && (
                    <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <Bot className="w-4 h-4 text-primary" />
                    </div>
                  )}
                  <div
                    className={cn(
                      'max-w-[80%] rounded-2xl px-4 py-3',
                      message.role === 'user'
                        ? 'bg-primary text-primary-foreground'
                        : 'glass'
                    )}
                  >
                    {message.role === 'assistant' ? (
                      <div className="prose prose-invert prose-sm max-w-none">
                        <ReactMarkdown
                          components={{
                            code: ({ className, children, ...props }) => {
                              const isInline = !className;
                              return isInline ? (
                                <code className="bg-secondary/50 px-1.5 py-0.5 rounded text-primary text-sm" {...props}>
                                  {children}
                                </code>
                              ) : (
                                <code className="block bg-background/50 p-3 rounded-lg overflow-x-auto text-sm" {...props}>
                                  {children}
                                </code>
                              );
                            },
                            pre: ({ children }) => <pre className="bg-transparent p-0">{children}</pre>,
                          }}
                        >
                          {message.content}
                        </ReactMarkdown>
                      </div>
                    ) : (
                      <p className="text-sm">{message.content}</p>
                    )}
                  </div>
                  {message.role === 'user' && (
                    <div className="w-8 h-8 rounded-lg bg-secondary flex items-center justify-center flex-shrink-0">
                      <User className="w-4 h-4 text-foreground" />
                    </div>
                  )}
                </div>
              ))
            )}
            {isLoading && messages[messages.length - 1]?.role === 'user' && (
              <div className="flex gap-3 animate-fade-in">
                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Bot className="w-4 h-4 text-primary" />
                </div>
                <div className="glass rounded-2xl px-4 py-3">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span className="text-sm">Analyzing...</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input area */}
          <form onSubmit={handleSubmit} className="p-4 border-t border-border">
            <div className="flex gap-3">
              <Textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={`Ask ${modes.find(m => m.id === mode)?.label} anything about security...`}
                className="min-h-[50px] max-h-[150px] resize-none bg-secondary/50 border-border focus:ring-primary"
                disabled={isLoading}
              />
              <Button
                type="submit"
                size="icon"
                className="h-[50px] w-[50px] bg-primary hover:bg-primary/90"
                disabled={!input.trim() || isLoading}
              >
                {isLoading ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <Send className="w-5 h-5" />
                )}
              </Button>
            </div>
          </form>
        </div>
      </div>
    </section>
  );
};

export default SecurityAgent;
