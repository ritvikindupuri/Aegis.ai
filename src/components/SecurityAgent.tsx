import { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Loader2, Code, AlertTriangle, Sparkles, Scan, Trash2, History, MessageSquare, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';
import ReactMarkdown from 'react-markdown';
import { toast } from 'sonner';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
}

interface ChatSession {
  id: string;
  messages: Message[];
  createdAt: number;
  preview: string;
}

type AgentMode = 'security' | 'code_review' | 'threat_intel' | 'general';

const STORAGE_KEY = 'aegis_chat_sessions';

const SecurityAgent = () => {
  const [sessions, setSessions] = useState<Record<AgentMode, ChatSession[]>>(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        return JSON.parse(stored);
      } catch {
        return { security: [], code_review: [], threat_intel: [], general: [] };
      }
    }
    return { security: [], code_review: [], threat_intel: [], general: [] };
  });
  
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [mode, setMode] = useState<AgentMode>('security');
  const [showHistory, setShowHistory] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const modes = [
    { 
      id: 'security' as const, 
      label: 'SENTINEL', 
      icon: Scan, 
      description: 'Security Analysis',
      color: 'text-destructive',
      features: ['Vulnerability scanning', 'OWASP Top 10 analysis', 'Security recommendations']
    },
    { 
      id: 'code_review' as const, 
      label: 'CODEX', 
      icon: Code, 
      description: 'Code Review',
      color: 'text-primary',
      features: ['Code security review', 'Best practices', 'Fix suggestions']
    },
    { 
      id: 'threat_intel' as const, 
      label: 'AEGIS', 
      icon: AlertTriangle, 
      description: 'Threat Intel',
      color: 'text-warning',
      features: ['Threat intelligence', 'Attack vectors', 'Mitigation strategies']
    },
    { 
      id: 'general' as const, 
      label: 'ASSIST', 
      icon: Sparkles, 
      description: 'General Help',
      color: 'text-success',
      features: ['General questions', 'Security concepts', 'Learning resources']
    },
  ];

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
  }, [sessions]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    // Load last session for current mode or start fresh
    const modeSessions = sessions[mode];
    if (modeSessions.length > 0 && !currentSessionId) {
      const lastSession = modeSessions[modeSessions.length - 1];
      setCurrentSessionId(lastSession.id);
      setMessages(lastSession.messages);
    } else if (!currentSessionId) {
      setMessages([]);
    }
  }, [mode]);

  const saveSession = (newMessages: Message[]) => {
    if (newMessages.length === 0) return;
    
    const sessionId = currentSessionId || Date.now().toString();
    const preview = newMessages[0]?.content.slice(0, 50) || 'New session';
    
    setSessions(prev => {
      const modeSessions = prev[mode].filter(s => s.id !== sessionId);
      const updatedSession: ChatSession = {
        id: sessionId,
        messages: newMessages,
        createdAt: parseInt(sessionId),
        preview
      };
      return {
        ...prev,
        [mode]: [...modeSessions, updatedSession]
      };
    });
    
    if (!currentSessionId) {
      setCurrentSessionId(sessionId);
    }
  };

  const startNewSession = () => {
    setCurrentSessionId(null);
    setMessages([]);
    setShowHistory(false);
  };

  const loadSession = (session: ChatSession) => {
    setCurrentSessionId(session.id);
    setMessages(session.messages);
    setShowHistory(false);
  };

  const deleteSession = (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSessions(prev => ({
      ...prev,
      [mode]: prev[mode].filter(s => s.id !== sessionId)
    }));
    if (currentSessionId === sessionId) {
      setCurrentSessionId(null);
      setMessages([]);
    }
    toast.success('Session deleted');
  };

  const clearAllHistory = () => {
    setSessions(prev => ({
      ...prev,
      [mode]: []
    }));
    setCurrentSessionId(null);
    setMessages([]);
    toast.success('All history cleared');
  };

  const streamChat = async (userMessage: string) => {
    setIsLoading(true);
    const newMessages: Message[] = [...messages, { role: 'user', content: userMessage, timestamp: Date.now() }];
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
        body: JSON.stringify({ messages: newMessages.map(m => ({ role: m.role, content: m.content })), mode }),
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
              const updatedMessages: Message[] = [...newMessages, { role: 'assistant', content: assistantContent, timestamp: Date.now() }];
              setMessages(updatedMessages);
            }
          } catch {
            buffer = line + '\n' + buffer;
            break;
          }
        }
      }

      const finalMessages: Message[] = [...newMessages, { role: 'assistant', content: assistantContent, timestamp: Date.now() }];
      setMessages(finalMessages);
      saveSession(finalMessages);
    } catch (error) {
      console.error('Chat error:', error);
      const errorMessages: Message[] = [
        ...newMessages,
        { role: 'assistant', content: `Error: ${error instanceof Error ? error.message : 'Something went wrong.'}`, timestamp: Date.now() },
      ];
      setMessages(errorMessages);
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

  const currentMode = modes.find(m => m.id === mode)!;
  const modeSessions = sessions[mode];

  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <section id="agent" className="py-20 px-4 sm:px-6 lg:px-8 bg-muted/30">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-6">
          <h2 className="text-2xl font-semibold text-foreground mb-1">
            AI Security Agents
          </h2>
          <p className="text-sm text-muted-foreground">
            Specialized agents for different security tasks
          </p>
        </div>

        {/* Mode selector */}
        <div className="flex flex-wrap justify-center gap-2 mb-6">
          {modes.map((m) => (
            <button
              key={m.id}
              onClick={() => {
                setMode(m.id);
                setCurrentSessionId(null);
                setShowHistory(false);
              }}
              className={cn(
                'flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all',
                mode === m.id
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-card border border-border text-muted-foreground hover:text-foreground'
              )}
            >
              <m.icon className="w-4 h-4" />
              {m.label}
            </button>
          ))}
        </div>

        {/* Agent features */}
        <div className="flex flex-wrap justify-center gap-2 mb-6">
          {currentMode.features.map((feature) => (
            <span key={feature} className="text-xs px-2 py-1 rounded-full bg-muted text-muted-foreground">
              {feature}
            </span>
          ))}
        </div>

        {/* Chat container */}
        <div className="rounded-lg border border-border bg-card overflow-hidden">
          {/* Toolbar */}
          <div className="flex items-center justify-between p-3 border-b border-border bg-muted/30">
            <div className="flex items-center gap-2">
              <currentMode.icon className={cn("w-4 h-4", currentMode.color)} />
              <span className="text-sm font-medium">{currentMode.label}</span>
              {currentSessionId && (
                <span className="text-xs text-muted-foreground">• Active session</span>
              )}
            </div>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowHistory(!showHistory)}
                className="h-8 px-2"
              >
                <History className="w-4 h-4 mr-1" />
                <span className="text-xs">History ({modeSessions.length})</span>
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={startNewSession}
                className="h-8 px-2"
              >
                <MessageSquare className="w-4 h-4 mr-1" />
                <span className="text-xs">New</span>
              </Button>
            </div>
          </div>

          {/* History panel */}
          {showHistory && (
            <div className="border-b border-border bg-background p-4">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-sm font-medium">Session History</h4>
                {modeSessions.length > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearAllHistory}
                    className="h-7 px-2 text-destructive hover:text-destructive"
                  >
                    <Trash2 className="w-3 h-3 mr-1" />
                    Clear All
                  </Button>
                )}
              </div>
              {modeSessions.length === 0 ? (
                <p className="text-xs text-muted-foreground text-center py-4">No history yet</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {[...modeSessions].reverse().map((session) => (
                    <div
                      key={session.id}
                      onClick={() => loadSession(session)}
                      className={cn(
                        'flex items-center justify-between p-2 rounded cursor-pointer transition-colors',
                        currentSessionId === session.id ? 'bg-primary/10' : 'hover:bg-muted'
                      )}
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-sm truncate">{session.preview}...</p>
                        <p className="text-[10px] text-muted-foreground">{formatTime(session.createdAt)}</p>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => deleteSession(session.id, e)}
                        className="h-6 w-6 p-0 text-muted-foreground hover:text-destructive"
                      >
                        <X className="w-3 h-3" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Messages area */}
          <div className="h-[380px] overflow-y-auto p-4 space-y-3">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center">
                <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center mb-3", 
                  mode === 'security' ? 'bg-destructive/10' :
                  mode === 'code_review' ? 'bg-primary/10' :
                  mode === 'threat_intel' ? 'bg-warning/10' : 'bg-success/10'
                )}>
                  <currentMode.icon className={cn("w-5 h-5", currentMode.color)} />
                </div>
                <h3 className="text-sm font-medium text-foreground mb-1">
                  {currentMode.label}
                </h3>
                <p className="text-xs text-muted-foreground max-w-sm">
                  {mode === 'security' && 'Ask about security threats, OWASP Top 10, or paste code snippets for analysis.'}
                  {mode === 'code_review' && 'Paste code snippets for security review and remediation guidance.'}
                  {mode === 'threat_intel' && 'Ask about CVEs, attack vectors, and security trends.'}
                  {mode === 'general' && 'Ask any security-related questions.'}
                </p>
              </div>
            ) : (
              messages.map((message, index) => (
                <div
                  key={index}
                  className={cn(
                    'flex gap-2',
                    message.role === 'user' ? 'justify-end' : 'justify-start'
                  )}
                >
                  {message.role === 'assistant' && (
                    <div className={cn("w-7 h-7 rounded flex items-center justify-center flex-shrink-0",
                      mode === 'security' ? 'bg-destructive/10' :
                      mode === 'code_review' ? 'bg-primary/10' :
                      mode === 'threat_intel' ? 'bg-warning/10' : 'bg-success/10'
                    )}>
                      <Bot className={cn("w-4 h-4", currentMode.color)} />
                    </div>
                  )}
                  <div
                    className={cn(
                      'max-w-[80%] rounded-lg px-3 py-2',
                      message.role === 'user'
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted'
                    )}
                  >
                    {message.role === 'assistant' ? (
                      <div className="prose prose-sm max-w-none dark:prose-invert text-sm">
                        <ReactMarkdown
                          components={{
                            code: ({ className, children, ...props }) => {
                              const isInline = !className;
                              return isInline ? (
                                <code className="bg-background/50 px-1 py-0.5 rounded text-xs" {...props}>
                                  {children}
                                </code>
                              ) : (
                                <code className="block bg-background p-2 rounded text-xs overflow-x-auto" {...props}>
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
                    <div className="w-7 h-7 rounded bg-muted flex items-center justify-center flex-shrink-0">
                      <User className="w-4 h-4 text-foreground" />
                    </div>
                  )}
                </div>
              ))
            )}
            {isLoading && messages[messages.length - 1]?.role === 'user' && (
              <div className="flex gap-2">
                <div className={cn("w-7 h-7 rounded flex items-center justify-center",
                  mode === 'security' ? 'bg-destructive/10' :
                  mode === 'code_review' ? 'bg-primary/10' :
                  mode === 'threat_intel' ? 'bg-warning/10' : 'bg-success/10'
                )}>
                  <Bot className={cn("w-4 h-4", currentMode.color)} />
                </div>
                <div className="bg-muted rounded-lg px-3 py-2">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Loader2 className="w-3 h-3 animate-spin" />
                    <span className="text-xs">Analyzing...</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input area */}
          <form onSubmit={handleSubmit} className="p-3 border-t border-border">
            <div className="flex gap-2">
              <Textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={`Ask ${currentMode.label}...`}
                className="min-h-[44px] max-h-[120px] resize-none bg-muted border-0 text-sm focus-visible:ring-1 focus-visible:ring-primary"
                disabled={isLoading}
              />
              <Button
                type="submit"
                size="icon"
                className="h-11 w-11"
                disabled={!input.trim() || isLoading}
              >
                {isLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
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