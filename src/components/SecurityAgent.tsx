import { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Loader2, Code, AlertTriangle, Sparkles, Scan, Trash2, History, MessageSquare, X, LogIn, Upload, FileCode, RefreshCw, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';
import ReactMarkdown from 'react-markdown';
import { toast } from 'sonner';
import { useAuth } from '@/hooks/useAuth';
import { supabase } from '@/integrations/supabase/client';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  isRateLimitError?: boolean;
}

interface ChatSession {
  id: string;
  agent_mode: string;
  messages: Message[];
  preview: string | null;
  created_at: string;
}

type AgentMode = 'security' | 'code_review' | 'threat_intel' | 'general';

interface RateLimitError {
  type: 'rate_limit' | 'payment_required';
  message: string;
  lastInput: string;
}

const SecurityAgent = () => {
  const { user } = useAuth();
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingSessions, setIsLoadingSessions] = useState(false);
  const [mode, setMode] = useState<AgentMode>('security');
  const [showHistory, setShowHistory] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState<string[]>([]);
  const [rateLimitError, setRateLimitError] = useState<RateLimitError | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const modes = [
    { 
      id: 'security' as const, 
      label: 'SENTINEL', 
      icon: Scan, 
      description: 'Quick Security Q&A',
      color: 'text-destructive',
      features: ['Fast answers', 'Security concepts', 'Quick vulnerability checks'],
      examples: [
        'What is SQL injection?',
        'Is this query safe: SELECT * FROM users WHERE id = ?',
        'How do I prevent XSS attacks?'
      ]
    },
    { 
      id: 'code_review' as const, 
      label: 'CODEX', 
      icon: Code, 
      description: 'Deep Code Audit',
      color: 'text-primary',
      features: ['Full code review', 'Detailed fixes', 'Refactoring guidance'],
      examples: [
        'Review this auth function and fix all security issues: [paste 50+ lines]',
        'Audit this API endpoint for vulnerabilities: [paste entire handler]',
        'Rewrite this code following security best practices: [paste code]'
      ]
    },
    { 
      id: 'threat_intel' as const, 
      label: 'AEGIS', 
      icon: AlertTriangle, 
      description: 'Threat Intelligence',
      color: 'text-warning',
      features: ['CVE research', 'Attack analysis', 'Mitigation strategies'],
      examples: [
        'Tell me about CVE-2024-1234',
        'How do ransomware attacks work?',
        'What are the latest Log4j vulnerabilities?'
      ]
    },
    { 
      id: 'general' as const, 
      label: 'ASSIST', 
      icon: Sparkles, 
      description: 'General Help',
      color: 'text-success',
      features: ['Learning resources', 'Career advice', 'Tool recommendations'],
      examples: [
        'What certifications should I get for security?',
        'Best tools for penetration testing?',
        'How do I start a career in cybersecurity?'
      ]
    },
  ];

  // Fetch sessions for current mode
  const fetchSessions = async () => {
    if (!user) return;
    
    setIsLoadingSessions(true);
    const { data, error } = await supabase
      .from('chat_sessions')
      .select('*')
      .eq('user_id', user.id)
      .eq('agent_mode', mode)
      .order('updated_at', { ascending: false });
    
    if (error) {
      console.error('Error fetching sessions:', error);
    } else if (data) {
      // Cast the messages from Json to Message[]
      const typedSessions: ChatSession[] = data.map(session => ({
        ...session,
        messages: (session.messages as unknown as Message[]) || []
      }));
      setSessions(typedSessions);
    }
    setIsLoadingSessions(false);
  };

  useEffect(() => {
    if (user) {
      fetchSessions();
    } else {
      setSessions([]);
    }
  }, [user, mode]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    // Reset messages when changing mode
    setCurrentSessionId(null);
    setMessages([]);
    setShowHistory(false);
  }, [mode]);

  const saveSession = async (newMessages: Message[]) => {
    if (!user || newMessages.length === 0) return;
    
    const preview = newMessages[0]?.content.slice(0, 50) || 'New session';
    
    if (currentSessionId) {
      // Update existing session
      await supabase
        .from('chat_sessions')
        .update({ 
          messages: newMessages as any,
          preview 
        })
        .eq('id', currentSessionId);
    } else {
      // Create new session
      const { data, error } = await supabase
        .from('chat_sessions')
        .insert({
          user_id: user.id,
          agent_mode: mode,
          messages: newMessages as any,
          preview
        })
        .select()
        .single();
      
      if (!error && data) {
        setCurrentSessionId(data.id);
        fetchSessions();
      }
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

  const deleteSession = async (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    
    const { error } = await supabase
      .from('chat_sessions')
      .delete()
      .eq('id', sessionId);
    
    if (error) {
      toast.error('Failed to delete session');
    } else {
      if (currentSessionId === sessionId) {
        setCurrentSessionId(null);
        setMessages([]);
      }
      fetchSessions();
      toast.success('Session deleted');
    }
  };

  const clearAllHistory = async () => {
    if (!user) return;
    
    const { error } = await supabase
      .from('chat_sessions')
      .delete()
      .eq('user_id', user.id)
      .eq('agent_mode', mode);
    
    if (error) {
      toast.error('Failed to clear history');
    } else {
      setSessions([]);
      setCurrentSessionId(null);
      setMessages([]);
      toast.success('All history cleared');
    }
  };

  const streamChat = async (userMessage: string, isRetry = false) => {
    setIsLoading(true);
    setRateLimitError(null);
    
    const newMessages: Message[] = isRetry 
      ? messages 
      : [...messages, { role: 'user', content: userMessage, timestamp: Date.now() }];
    
    if (!isRetry) {
      setMessages(newMessages);
      setInput('');
    }

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
        
        // Handle rate limit errors
        if (response.status === 429) {
          setRateLimitError({
            type: 'rate_limit',
            message: 'Rate limit exceeded. Please wait a moment before trying again.',
            lastInput: userMessage
          });
          toast.error('Rate limit reached. Please wait before retrying.');
          return;
        }
        
        // Handle payment required errors
        if (response.status === 402) {
          setRateLimitError({
            type: 'payment_required',
            message: 'AI credits exhausted. Please add credits to continue using the agents.',
            lastInput: userMessage
          });
          toast.error('Credits exhausted. Please add more credits.');
          return;
        }
        
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
      const errorMessage = error instanceof Error ? error.message : 'Something went wrong.';
      const errorMessages: Message[] = [
        ...newMessages,
        { role: 'assistant', content: `Error: ${errorMessage}`, timestamp: Date.now(), isRateLimitError: true },
      ];
      setMessages(errorMessages);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRetry = () => {
    if (rateLimitError) {
      streamChat(rateLimitError.lastInput, true);
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

  const formatTime = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Show sign in prompt if not authenticated
  if (!user) {
    return (
      <section id="agent" className="py-20 px-4 sm:px-6 lg:px-8 bg-muted/30">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-6">
            <h2 className="text-2xl font-semibold text-foreground mb-1">
              AI Security Agents
            </h2>
            <p className="text-sm text-muted-foreground">
              Specialized agents for different security tasks
            </p>
          </div>

          <div className="rounded-lg border border-border bg-card p-12 text-center">
            <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
              <LogIn className="w-8 h-8 text-primary" />
            </div>
            <h3 className="text-lg font-medium text-foreground mb-2">
              Sign in to use AI Agents
            </h3>
            <p className="text-sm text-muted-foreground mb-6 max-w-sm mx-auto">
              Create an account or sign in to access our AI security agents and save your chat history.
            </p>
            <div className="flex gap-3 justify-center">
              <a href="/auth">
                <Button>Sign in</Button>
              </a>
              <a href="/auth">
                <Button variant="outline">Create account</Button>
              </a>
            </div>
          </div>
        </div>
      </section>
    );
  }

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
              onClick={() => setMode(m.id)}
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
                <span className="text-xs">History ({sessions.length})</span>
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
                {sessions.length > 0 && (
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
              {isLoadingSessions ? (
                <div className="flex items-center justify-center py-4">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                </div>
              ) : sessions.length === 0 ? (
                <p className="text-xs text-muted-foreground text-center py-4">No history yet</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {sessions.map((session) => (
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
                        <p className="text-[10px] text-muted-foreground">{formatTime(session.created_at)}</p>
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
              <div className="h-full flex flex-col items-center justify-center text-center px-4">
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
                <p className="text-xs text-muted-foreground max-w-sm mb-4">
                  {currentMode.description}
                </p>
                
                {/* Example prompts */}
                <div className="w-full max-w-md space-y-2">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-2">Try asking:</p>
                  {currentMode.examples?.map((example, i) => (
                    <button
                      key={i}
                      onClick={() => setInput(example)}
                      className="w-full text-left p-2.5 rounded-lg bg-muted/50 hover:bg-muted text-xs text-muted-foreground hover:text-foreground transition-colors border border-transparent hover:border-border"
                    >
                      &quot;{example}&quot;
                    </button>
                  ))}
                </div>
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
                      <div className={cn(
                        "prose prose-sm max-w-none dark:prose-invert text-sm",
                        mode === 'code_review' && "codex-output"
                      )}>
                        <ReactMarkdown
                          components={{
                            h1: ({ children }) => (
                              <h1 className="text-base font-bold text-foreground mt-4 mb-2 first:mt-0 border-b border-border pb-1">{children}</h1>
                            ),
                            h2: ({ children }) => (
                              <h2 className="text-sm font-bold text-foreground mt-3 mb-1.5">{children}</h2>
                            ),
                            h3: ({ children }) => (
                              <h3 className="text-sm font-semibold text-foreground mt-2 mb-1">{children}</h3>
                            ),
                            strong: ({ children }) => (
                              <strong className="font-semibold text-foreground">{children}</strong>
                            ),
                            ul: ({ children }) => (
                              <ul className="list-disc list-outside ml-4 my-1.5 space-y-0.5">{children}</ul>
                            ),
                            ol: ({ children }) => (
                              <ol className="list-decimal list-outside ml-4 my-1.5 space-y-0.5">{children}</ol>
                            ),
                            li: ({ children }) => (
                              <li className="text-muted-foreground leading-relaxed">{children}</li>
                            ),
                            code: ({ className, children, ...props }) => {
                              const isInline = !className;
                              return isInline ? (
                                <code className="bg-primary/10 text-primary px-1.5 py-0.5 rounded text-xs font-mono" {...props}>
                                  {children}
                                </code>
                              ) : (
                                <code className="block bg-background border border-border p-3 rounded-lg text-xs font-mono overflow-x-auto whitespace-pre" {...props}>
                                  {children}
                                </code>
                              );
                            },
                            pre: ({ children }) => (
                              <pre className="bg-transparent p-0 my-2">{children}</pre>
                            ),
                            p: ({ children }) => (
                              <p className="text-muted-foreground leading-relaxed my-1.5">{children}</p>
                            ),
                            blockquote: ({ children }) => (
                              <blockquote className="border-l-2 border-primary/50 pl-3 my-2 italic text-muted-foreground">{children}</blockquote>
                            ),
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
            
            {/* Rate limit error UI */}
            {rateLimitError && !isLoading && (
              <div className="flex gap-2">
                <div className="w-7 h-7 rounded flex items-center justify-center bg-destructive/10">
                  <AlertCircle className="w-4 h-4 text-destructive" />
                </div>
                <div className="bg-destructive/10 border border-destructive/20 rounded-lg px-3 py-3 max-w-[80%]">
                  <p className="text-sm text-destructive font-medium mb-2">
                    {rateLimitError.type === 'rate_limit' ? 'Rate Limit Reached' : 'Credits Exhausted'}
                  </p>
                  <p className="text-xs text-muted-foreground mb-3">
                    {rateLimitError.message}
                  </p>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={handleRetry}
                      className="h-7 text-xs"
                    >
                      <RefreshCw className="w-3 h-3 mr-1" />
                      Retry
                    </Button>
                    {rateLimitError.type === 'payment_required' && (
                      <Button
                        size="sm"
                        variant="default"
                        onClick={() => window.open('https://lovable.dev/settings', '_blank')}
                        className="h-7 text-xs"
                      >
                        Add Credits
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            )}
            
            <div ref={messagesEndRef} />
          </div>

          {/* Input area */}
          <form onSubmit={handleSubmit} className="p-3 border-t border-border">
            {/* File upload for CODEX mode */}
            {mode === 'code_review' && (
              <div className="mb-2">
                <input
                  type="file"
                  ref={fileInputRef}
                  multiple
                  accept=".js,.jsx,.ts,.tsx,.py,.java,.c,.cpp,.cs,.go,.rb,.php,.rs,.swift,.kt,.vue,.svelte,.html,.css,.sql,.sh,.yml,.yaml,.json,.xml,.md,.txt"
                  className="hidden"
                  onChange={async (e) => {
                    const files = Array.from(e.target.files || []);
                    if (files.length === 0) return;
                    
                    const totalSize = files.reduce((sum, f) => sum + f.size, 0);
                    if (totalSize > 500 * 1024) {
                      toast.error('Total file size exceeds 500KB limit.');
                      return;
                    }
                    
                    const fileContents: string[] = [];
                    const fileNames: string[] = [];
                    
                    for (const file of files) {
                      const content = await new Promise<string>((resolve) => {
                        const reader = new FileReader();
                        reader.onload = (event) => resolve(event.target?.result as string);
                        reader.readAsText(file);
                      });
                      fileContents.push(`### ${file.name}\n\`\`\`\n${content}\n\`\`\``);
                      fileNames.push(file.name);
                    }
                    
                    const batchReview = files.length > 1 
                      ? `Review these ${files.length} code files:\n\n${fileContents.join('\n\n')}`
                      : `Review this code from ${files[0].name}:\n\n\`\`\`\n${fileContents[0].replace(/^### .+\n\`\`\`\n/, '').replace(/\n\`\`\`$/, '')}\n\`\`\``;
                    
                    setInput(batchReview);
                    setUploadedFiles(fileNames);
                  }}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isLoading}
                  className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-dashed border-border bg-background hover:bg-muted/50 transition-colors text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
                >
                  <Upload className="w-3.5 h-3.5" />
                  {uploadedFiles.length > 0 ? (
                    <span className="flex items-center gap-1.5 flex-wrap justify-center">
                      <FileCode className="w-3.5 h-3.5 text-primary" />
                      {uploadedFiles.length === 1 ? uploadedFiles[0] : `${uploadedFiles.length} files selected`}
                      <X 
                        className="w-3 h-3 text-muted-foreground hover:text-destructive cursor-pointer" 
                        onClick={(e) => {
                          e.stopPropagation();
                          setUploadedFiles([]);
                          setInput('');
                          if (fileInputRef.current) fileInputRef.current.value = '';
                        }}
                      />
                    </span>
                  ) : (
                    'Upload code files for review (max 500KB total)'
                  )}
                </button>
              </div>
            )}
            <div className="flex gap-2">
              <Textarea
                value={input}
                onChange={(e) => {
                  setInput(e.target.value);
                  if (uploadedFiles.length > 0 && !uploadedFiles.some(f => e.target.value.includes(f))) {
                    setUploadedFiles([]);
                  }
                }}
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