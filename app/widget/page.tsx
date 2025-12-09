"use client";
import { useState, useEffect, useRef, useCallback, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import io, { Socket } from 'socket.io-client';
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { LogOut, MessageCircle, Minus } from 'lucide-react';

type MessageEvent = { id: string; sessionId: string; role: 'USER' | 'AGENT'; content: string; createdAt: string };
type ChatEvent = { sessionId: string };
type SessionStartedPayload = { sessionId: string; visitorId: string; initialMessage?: string };

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5010';
const DEFAULT_PRIMARY_COLOR = '#024F9E'; // Enagic water-brand blue
const socket: Socket = io(BACKEND_URL, { autoConnect: false });

function CustomerWidgetInner() {
  const searchParams = useSearchParams();
  const primaryColor = searchParams.get('primaryColor') || DEFAULT_PRIMARY_COLOR;
  const logoUrl = searchParams.get('logoUrl');
  const welcomeTitle = searchParams.get('welcomeTitle') || 'Kangen Care Bot';
  const welcomeSubtitle = searchParams.get('welcomeSubtitle') || '';
  const widgetMode = (searchParams.get('mode') || 'floating').toLowerCase();
  const isInlineMode = widgetMode === 'inline';
  const sessionIdParam = searchParams.get('sessionId');
  const visitorIdParam = searchParams.get('visitorId');
  const [sessionId, setSessionId] = useState<string>('');
  const [visitorId, setVisitorId] = useState<string>('');
  const [messageInput, setMessageInput] = useState<string>('');
  const [messages, setMessages] = useState<MessageEvent[]>([]);
  const [status, setStatus] = useState<string>('Disconnected');
  const [isAgentTyping, setIsAgentTyping] = useState<boolean>(false);
  const agentTypingTimerRef = useRef<number | null>(null);
  const sessionIdRef = useRef<string>('');
  const [showChat, setShowChat] = useState(false);
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [isClosed, setIsClosed] = useState<boolean>(false);
  const [emailForTranscript, setEmailForTranscript] = useState<string>('');
  const [isMinimized, setIsMinimized] = useState<boolean>(!isInlineMode);
  const [showEmojiPicker, setShowEmojiPicker] = useState<boolean>(false);
  const [csatRating, setCsatRating] = useState<number | null>(null);
  const [csatComment, setCsatComment] = useState<string>('');
  const [csatSubmitting, setCsatSubmitting] = useState<boolean>(false);
  const [csatSubmitted, setCsatSubmitted] = useState<boolean>(false);
  const [csatMessage, setCsatMessage] = useState<string>('');
  const [handoffRequested, setHandoffRequested] = useState<boolean>(false);
  const [handoffInProgress, setHandoffInProgress] = useState<boolean>(false);
  const pendingMessageRef = useRef<string | null>(null);

  useEffect(() => {
    // Keep a ref of the current sessionId to avoid stale closures in socket handlers
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  const EMOJIS = ['😀','😃','😄','😁','😅','😂','😊','😍','🥰','😘','🤩','🤔','🤨','😎','😢','😭','😡','👍','👋','🙏','💧','💙','🎉'];

  const escapeHtml = (s: string) =>
    s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  const renderMessageContent = (text: string) => {
    let out = escapeHtml(text);
    out = out.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    out = out.replace(/_(.+?)_/g, '<em>$1</em>');
    out = out.replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 rounded bg-slate-200 text-xs">$1</code>');
    out = out.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" rel="noopener noreferrer" class="underline">$1</a>');
    out = out.replace(/\n/g, '<br />');
    return out;
  };

  const downloadTranscript = async (format: 'text' | 'html') => {
    if (!sessionId) return;
    try {
      const url = `${BACKEND_URL}/sessions/${sessionId}/transcript${format === 'html' ? '?format=html' : ''}`;
      const res = await fetch(url);
      if (!res.ok) {
        setStatus('Failed to download transcript');
        return;
      }
      const content = await res.text();
      const blob = new Blob([content], { type: format === 'html' ? 'text/html' : 'text/plain' });
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = `transcript-${sessionId}.${format === 'html' ? 'html' : 'txt'}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(href);
    } catch {
      setStatus('Failed to download transcript');
    }
  };

  useEffect(() => {
    const handleNewMessage = (data: MessageEvent) => {
      console.debug('[widget] new_message received:', { role: data.role, content: data.content, sessionId: data.sessionId });
      setMessages((prev) => [...prev, data]);
      // Any new message should clear typing indicator
      setIsAgentTyping(false);
      if (agentTypingTimerRef.current) window.clearTimeout(agentTypingTimerRef.current);
      agentTypingTimerRef.current = null;
    };

    socket.on('connect', () => setStatus('Connected'));
    socket.on('disconnect', (reason) => setStatus(`Disconnected: ${reason || 'unknown'}`));
    socket.on('reconnect', () => {
      setStatus('Reconnected');
      // Rejoin session as visitor if we already have identifiers
      const sId = sessionIdRef.current;
      if (sId && visitorId) {
        socket.emit('visitor_join', { sessionId: sId, visitorId }, () => {});
      }
    });
    socket.on('chat_started', (data: ChatEvent) => setSessionId(data.sessionId));
    socket.on('new_message', handleNewMessage);
    socket.on('agent_joined', () => setStatus('Agent has joined the chat'));
    socket.on('chat_closed', () => {
      setStatus('Chat has been closed');
      setIsClosed(true);
    });
    socket.on('user_typing', (data: { sessionId: string; role: 'USER' | 'AGENT' }) => {
      if (data.role === 'AGENT' && data.sessionId === sessionIdRef.current) {
        setIsAgentTyping(true);
        if (agentTypingTimerRef.current) window.clearTimeout(agentTypingTimerRef.current);
        agentTypingTimerRef.current = window.setTimeout(() => setIsAgentTyping(false), 3000) as unknown as number;
      }
    });
    socket.on('user_stop_typing', (data: { sessionId: string; role: 'USER' | 'AGENT' }) => {
      if (data.role === 'AGENT' && data.sessionId === sessionIdRef.current) {
        if (agentTypingTimerRef.current) window.clearTimeout(agentTypingTimerRef.current);
        setIsAgentTyping(false);
      }
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('reconnect');
      socket.off('chat_started');
      socket.off('new_message', handleNewMessage);
      socket.off('agent_joined');
      socket.off('chat_closed');
      socket.off('user_typing');
      socket.off('user_stop_typing');
      if (agentTypingTimerRef.current) window.clearTimeout(agentTypingTimerRef.current);
      agentTypingTimerRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (scrollAreaRef.current) {
      scrollAreaRef.current.scrollTop = scrollAreaRef.current.scrollHeight;
    }
  }, [messages]);

  useEffect(() => {
    socket.on('new_message_notification', (data) => {
      if (Notification.permission === 'granted') {
        new Notification('New Message Received', { body: data.content });
      }
    });
    socket.on('agent_joined_notification', () => {
      if (Notification.permission === 'granted') {
        new Notification('Agent has joined the chat');
      }
    });
    return () => {
      socket.off('new_message_notification');
      socket.off('agent_joined_notification');
    };
  }, []);

  useEffect(() => {
    const urlSessionId = sessionIdParam;
    const urlVisitorId = visitorIdParam;
    if (!urlSessionId || !urlVisitorId || sessionId || visitorId) {
      return;
    }
    setSessionId(urlSessionId);
    setVisitorId(urlVisitorId);
    setShowChat(true);
    setIsClosed(false);
    socket.connect();
    socket.emit('visitor_join', { sessionId: urlSessionId, visitorId: urlVisitorId }, (resp: { status?: string }) => {
      if (resp.status === 'joined') {
        setStatus('Kangen Care Bot is ready to help');
        socket.emit('get_chat_history', { sessionId: urlSessionId }, (history: MessageEvent[]) => {
          setMessages(history);
        });
      } else {
        setStatus('Failed to join session');
      }
    });
  }, [sessionIdParam, visitorIdParam, sessionId, visitorId]);

  // After pre-chat form / auto bot session start
  const handleSessionStarted = (data: SessionStartedPayload) => {
    console.debug('[widget] handleSessionStarted:', data);
    setSessionId(data.sessionId);
    setVisitorId(data.visitorId);
    setShowChat(true);
    setIsClosed(false);
    // Connect socket and join session as visitor
    socket.connect();
    socket.emit('visitor_join', { sessionId: data.sessionId, visitorId: data.visitorId }, (resp: { status?: string }) => {
      if (resp.status === 'joined') {
        setStatus('Kangen Care Bot is ready to help');
        socket.emit('get_chat_history', { sessionId: data.sessionId }, (history: MessageEvent[]) => {
          setMessages(history);
          if (pendingMessageRef.current && data.sessionId) {
            socket.emit('send_message', {
              sessionId: data.sessionId,
              role: 'USER',
              content: pendingMessageRef.current,
            });
            pendingMessageRef.current = null;
          }
        });
      } else {
        setStatus('Failed to join session');
      }
    });
  };

  const startBotSession = async () => {
    console.debug('[widget] startBotSession called', { sessionId, visitorId });
    if (sessionId || visitorId) return;
    try {
      setStatus('Connecting to virtual agent...');
      console.debug('[widget] startBotSession POST /sessions');
      const res = await fetch(`${BACKEND_URL}/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        console.error('[widget] startBotSession /sessions failed', res.status, res.statusText);
        setStatus('Unable to start chat. Please try again later.');
        return;
      }
      const data = (await res.json()) as SessionStartedPayload;
      console.debug('[widget] startBotSession /sessions ok, response:', data);
      handleSessionStarted(data);
    } catch (err) {
      console.error('[widget] startBotSession error', err);
      setStatus('Unable to start chat. Please try again later.');
    }
  };

  // In inline mode, automatically show the chat and start a bot session
  useEffect(() => {
    if (!isInlineMode) return;
    if (!showChat) {
      setShowChat(true);
    }
    if (!sessionId && !visitorId) {
      console.debug('[widget] inline mode auto-starting bot session');
      void startBotSession();
    }
  }, [isInlineMode, showChat, sessionId, visitorId]);

  const sendMessage = () => {
    const trimmed = messageInput.trim();
    if (!trimmed) return;
    if (!sessionId) {
      console.debug('[widget] sendMessage queued (no session yet):', trimmed);
      pendingMessageRef.current = trimmed;
      setMessageInput('');
      return;
    }
    console.debug('[widget] sendMessage emitting to server:', { sessionId, content: trimmed });
    socket.emit('send_message', { sessionId, role: 'USER', content: trimmed });
    setMessageInput('');
  };

  const exitChat = () => {
    if (!sessionId) return;
    socket.emit('end_chat', { sessionId });
  };

  const requestHandoff = () => {
    if (!sessionId || handoffInProgress || handoffRequested) return;
    setHandoffInProgress(true);
    setStatus('Requesting a live agent...');
    socket.emit(
      'request_handoff',
      { sessionId },
      (resp: { ok?: boolean; error?: string } = {}) => {
        setHandoffInProgress(false);
        if (resp.ok) {
          setHandoffRequested(true);
          setStatus('Waiting for a live agent to join...');
        } else {
          setStatus('Unable to request a live agent right now. Please try again.');
        }
      }
    );
  };

  const submitCsatFeedback = useCallback(async () => {
    if (!sessionId) return;
    if (csatSubmitting) return;
    if (csatRating === null) {
      setCsatMessage('Please select a rating.');
      return;
    }
    setCsatSubmitting(true);
    setCsatMessage('');
    try {
      const payload = {
        rating: csatRating,
        comment: csatComment.trim() || undefined,
      };
      const response = await fetch(`${BACKEND_URL}/sessions/${sessionId}/csat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        setCsatMessage('Failed to submit feedback. Try again.');
        return;
      }
      setCsatSubmitted(true);
      setCsatMessage('Feedback recorded.');
    } catch (err) {
      console.error('csat error', err);
      setCsatMessage('Unable to submit feedback.');
    } finally {
      setCsatSubmitting(false);
    }
  }, [csatComment, csatRating, csatSubmitting, sessionId]);

  const startNewChat = () => {
    // Reset to pre-chat form
    try { socket.disconnect(); } catch {}
    setMessages([]);
    setMessageInput('');
    setSessionId('');
    setVisitorId('');
    setIsAgentTyping(false);
    setIsClosed(false);
    setEmailForTranscript('');
    setStatus('Disconnected');
    setShowChat(false);
    if (!isInlineMode) {
      setIsMinimized(true);
    }
    setCsatRating(null);
    setCsatComment('');
    setCsatSubmitted(false);
    setCsatMessage('');
  };

  const emailTranscript = async () => {
    if (!sessionId || !emailForTranscript) {
      setStatus('Enter your email to receive transcript');
      return;
    }
    setStatus('Sending transcript...');
    try {
      const res = await fetch(`${BACKEND_URL}/transcripts/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, toEmail: emailForTranscript }),
      });
      if (!res.ok) {
        setStatus('Failed to send transcript');
        return;
      }
      setStatus('Transcript sent');
    } catch {
      setStatus('Failed to send transcript');
    }
  };

  const renderLauncher = () => (
    <button
      type="button"
      onClick={() => {
        setIsMinimized(false);
        setShowChat(true);
        if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'default') {
          Notification.requestPermission();
        }
        if (!sessionId && !visitorId) {
          void startBotSession();
        }
      }}
      className="flex items-center gap-2 rounded-full bg-[#024F9E] px-5 py-3 text-white font-semibold shadow-lg hover:bg-[#013a75] transition"
      aria-label="Open chat"
    >
      <MessageCircle className="h-5 w-5" />
      Chat with us
    </button>
  );

  const hasConversationActivity = messages.length > 0;

  return (
    <div className={isInlineMode ? 'w-full h-full' : 'fixed bottom-4 right-4'}>
      {!isInlineMode && isMinimized ? (
        renderLauncher()
      ) : (
        <Card className={`relative flex flex-col ${isInlineMode ? 'w-full h-full max-h-[720px]' : 'w-[420px] h-[560px] overflow-y-auto'}`}>
          <CardHeader className="flex flex-col gap-3 bg-gradient-to-r from-[#e3f1ff] to-[#f3fbff] pb-3">
            <div className="flex w-full items-start justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-full bg-[#024F9E] text-white text-sm font-semibold shadow-sm">
                  KC
                </div>
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <CardTitle className="text-base font-bold" style={{ color: primaryColor }}>
                      {welcomeTitle}
                    </CardTitle>
                    <span className="rounded-full bg-white/80 px-2 py-0.5 text-[11px] font-medium text-sky-700 border border-sky-100">
                      Virtual assistant
                    </span>
                  </div>
                  {welcomeSubtitle && (
                    <p className="text-[11px] text-slate-500">{welcomeSubtitle}</p>
                  )}
                  <p className="text-[11px] text-slate-500">Status: {status}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  disabled={!sessionId || handoffInProgress || handoffRequested}
                  onClick={requestHandoff}
                  className="rounded-full bg-gradient-to-r from-sky-500 to-blue-600 text-white text-xs font-semibold shadow-sm hover:from-sky-600 hover:to-blue-700 px-4 py-1"
                >
                  {handoffRequested ? 'Agent requested' : 'Talk to Live Agent'}
                </Button>
                {!isInlineMode && (
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    className="text-slate-600 bg-white/90 hover:bg-white shadow rounded-full"
                    onClick={() => setIsMinimized(true)}
                    aria-label="Minimize chat"
                  >
                    <Minus className="h-5 w-5" />
                  </Button>
                )}
                {sessionId && !isClosed && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={exitChat}
                    className="text-slate-500 hover:text-red-600"
                    title="End this chat"
                    aria-label="End chat"
                  >
                    <LogOut className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>
            <div className="mt-2 flex flex-col gap-1">
              <p className="text-[11px] text-slate-600">Try asking about:</p>
              <div className="flex flex-wrap gap-2">
                {['Order status', 'Warranty & repairs', 'Device setup'].map((label) => (
                  <button
                    key={label}
                    type="button"
                    className="rounded-full border border-sky-100 bg-white/80 px-3 py-1 text-xs font-medium text-slate-700 shadow-sm hover:bg-white"
                    onClick={() => {
                      if (!sessionId) {
                        setMessageInput(label);
                        return;
                      }
                      socket.emit('send_message', { sessionId, role: 'USER', content: label });
                    }}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent className="flex-1 p-0 bg-gradient-to-b from-[#f3fbff] to-[#e6f3ff]">
            <ScrollArea className="h-full p-4" ref={scrollAreaRef}>
              {messages.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full gap-2 text-center">
                  <p className="text-sm font-medium text-slate-700">Ask Kangen Care Bot a question to get started.</p>
                  <p className="text-xs text-slate-500 max-w-xs">
                    You can type your own question below or tap one of the suggested topics.
                  </p>
                </div>
              )}
              {messages.map((msg, index) => (
                <div
                  key={msg.id ?? `${msg.sessionId}-${msg.createdAt ?? 't'}-${index}`}
                  className={`mb-2 text-sm ${msg.role === 'USER' ? 'text-right' : 'text-left'}`}
                >
                  <div
                    className={`inline-block p-2 rounded-lg ${
                      msg.role === 'USER' ? 'text-white' : 'bg-gray-200 dark:bg-gray-700'
                    }`}
                    style={msg.role === 'USER' ? { backgroundColor: primaryColor } : undefined}
                  >
                    <span
                      className="whitespace-pre-wrap text-sm"
                      dangerouslySetInnerHTML={{ __html: renderMessageContent(msg.content) }}
                    />
                  </div>
                </div>
              ))}
              {isAgentTyping && <p className="text-sm italic">Agent is typing...</p>}
            </ScrollArea>
          </CardContent>
          {showChat && !isClosed && (
            <CardFooter className="p-4 border-t">
              <div className="flex w-full flex-col gap-2">
                <div className="flex w-full items-center justify-between gap-2">
                  <div className="flex flex-1 space-x-2">
                    <Input
                      placeholder="Type a message..."
                      value={messageInput}
                      onChange={(e) => {
                        setMessageInput(e.target.value);
                        if (e.target.value) {
                          socket.emit('typing', { sessionId, role: 'USER' });
                        } else {
                          socket.emit('stop_typing', { sessionId, role: 'USER' });
                        }
                      }}
                      onBlur={() => {
                        if (sessionId) socket.emit('stop_typing', { sessionId, role: 'USER' });
                      }}
                      onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setShowEmojiPicker((prev) => !prev)}
                    >
                      🙂
                    </Button>
                    <Button onClick={sendMessage}>Send</Button>
                  </div>
                  {hasConversationActivity && (
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      disabled={!sessionId || handoffInProgress || handoffRequested}
                      onClick={requestHandoff}
                      className="whitespace-nowrap"
                    >
                      {handoffRequested ? 'Agent requested' : 'Talk to live agent'}
                    </Button>
                  )}
                </div>
                {showEmojiPicker && (
                  <div className="flex flex-wrap gap-1 rounded-md border border-slate-200 bg-slate-50 p-2 text-lg shadow-sm">
                    {EMOJIS.map((emoji) => (
                      <button
                        key={emoji}
                        type="button"
                        className="px-1 hover:bg-slate-200 rounded"
                        onClick={() => {
                          setMessageInput((prev) => prev + emoji);
                          setShowEmojiPicker(false);
                        }}
                      >
                        {emoji}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </CardFooter>
          )}
          {sessionId && isClosed && (
            <CardFooter className="p-4 border-t">
              <div className="flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">This chat has ended.</span>
                  <Button onClick={startNewChat} size="sm">Start New Chat</Button>
                </div>
                {csatSubmitted ? (
                  <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">
                    Thank you for the feedback!{csatMessage ? ` ${csatMessage}` : ''}
                  </div>
                ) : (
                  <div className="space-y-2 rounded-md border border-muted bg-background/80 p-3">
                    <p className="text-sm font-semibold text-foreground">How was your experience?</p>
                    <div className="flex items-center gap-1">
                      {[1, 2, 3, 4, 5].map((value) => (
                        <button
                          key={value}
                          type="button"
                          className={`flex h-8 w-8 items-center justify-center rounded-full border text-sm font-semibold transition ${csatRating === value ? 'border-slate-600 bg-slate-900 text-white' : 'border-slate-300 bg-white text-slate-600 hover:border-slate-500'}`}
                          onClick={() => setCsatRating(value)}
                          aria-label={`Give ${value} star${value > 1 ? 's' : ''}`}
                        >
                          {value}
                        </button>
                      ))}
                    </div>
                    <Textarea
                      placeholder="Tell us what went well or how we can improve"
                      value={csatComment}
                      onChange={(event) => setCsatComment(event.target.value)}
                      className="resize-none"
                      rows={3}
                    />
                    {csatMessage && <p className="text-xs text-red-600">{csatMessage}</p>}
                    <Button size="sm" onClick={submitCsatFeedback} disabled={csatSubmitting || !sessionId || csatSubmitted}>
                      {csatSubmitting ? 'Submitting...' : 'Submit Feedback'}
                    </Button>
                  </div>
                )}
                <div className="flex items-center gap-2">
                  <Input
                    type="email"
                    placeholder="Enter your email to receive transcript"
                    value={emailForTranscript}
                    onChange={(e) => setEmailForTranscript(e.target.value)}
                  />
                  <Button size="sm" variant="outline" onClick={emailTranscript}>Email Transcript</Button>
                </div>
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="ghost" onClick={() => downloadTranscript('text')}>Download .txt</Button>
                  <Button size="sm" variant="ghost" onClick={() => downloadTranscript('html')}>Download .html</Button>
                </div>
              </div>
            </CardFooter>
          )}
        </Card>
      )}
    </div>
  );
}

export default function CustomerWidget() {
  return (
    <Suspense fallback={null}>
      <CustomerWidgetInner />
    </Suspense>
  );
}
