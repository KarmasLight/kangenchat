"use client";
import { useState, useEffect, useRef, useCallback, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import io, { Socket } from 'socket.io-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Loader2, MessageCircle, Minus, Send, X } from 'lucide-react';

type MessageEvent = {
  id: string;
  sessionId: string;
  role: 'USER' | 'AGENT';
  content: string;
  createdAt: string;
  agentId?: string | null;
};
type ChatEvent = { sessionId: string };
type SessionStartedPayload = { sessionId: string; visitorId: string; initialMessage?: string };
type AgentInfo = { id: string; name?: string | null; displayName?: string | null; email?: string | null };

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:3010';
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
  const [assignedAgent, setAssignedAgent] = useState<AgentInfo | null>(null);
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
  const [queuePosition, setQueuePosition] = useState<number | null>(null);
  const [awaitingContactInfo, setAwaitingContactInfo] = useState<boolean>(false);
  const pendingMessageRef = useRef<string | null>(null);
  const startSessionInFlightRef = useRef(false);

  const persistSession = (sid: string, vid: string) => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem('kangen_widget_session', JSON.stringify({ sessionId: sid, visitorId: vid }));
    } catch {
      // ignore storage errors
    }
  };

  const clearPersistedSession = () => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.removeItem('kangen_widget_session');
    } catch {
      // ignore storage errors
    }
  };

  useEffect(() => {
    // Keep a ref of the current sessionId to avoid stale closures in socket handlers
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  const EMOJIS = ['😀','😅','😊','😍','👍','🙏','💙','🎉'];

  const getInitials = (name?: string | null) => {
    if (!name) return 'AG';
    const parts = name.split(' ').filter(Boolean);
    if (parts.length === 0) return 'AG';
    const first = parts[0]?.[0] ?? '';
    const second = parts.length > 1 ? parts[1]?.[0] ?? '' : '';
    const combined = `${first}${second}`.trim();
    return (combined || 'AG').toUpperCase();
  };

  const isSameDay = (a: Date, b: Date) => {
    return (
      a.getFullYear() === b.getFullYear() &&
      a.getMonth() === b.getMonth() &&
      a.getDate() === b.getDate()
    );
  };

  const formatDateLabel = (d: Date) => {
    const now = new Date();
    if (isSameDay(d, now)) return 'Today';
    const yesterday = new Date(now);
    yesterday.setDate(now.getDate() - 1);
    if (isSameDay(d, yesterday)) return 'Yesterday';
    return d.toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
    });
  };

  const formatTimeLabel = (d: Date) => {
    return d.toLocaleTimeString(undefined, {
      hour: 'numeric',
      minute: '2-digit',
    });
  };

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
    socket.on(
      'agent_joined',
      (data: { sessionId: string; agent?: AgentInfo }) => {
        if (!data || data.sessionId !== sessionIdRef.current) return;
        if (data.agent) {
          setAssignedAgent(data.agent);
          const display = data.agent.displayName || data.agent.name || 'live agent';
          setStatus(`Connected to ${display}`);
        } else {
          setStatus('Agent has joined the chat');
        }
      }
    );
    socket.on('chat_closed', () => {
      setStatus('Chat has been closed');
      setIsClosed(true);
      clearPersistedSession();
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
    socket.on('handoff_status', (data: { sessionId: string; awaitingContactInfo: boolean; queuePosition?: number }) => {
      if (data.sessionId !== sessionIdRef.current) return;
      setAwaitingContactInfo(data.awaitingContactInfo);
      setQueuePosition(data.queuePosition ?? null);
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
      socket.off('handoff_status');
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

  // Restore a previous session from localStorage when there are no URL params
  useEffect(() => {
    if (sessionId || visitorId) return;
    if (sessionIdParam || visitorIdParam) return;
    if (typeof window === 'undefined') return;
    try {
      const raw = window.localStorage.getItem('kangen_widget_session');
      if (!raw) return;
      const parsed = JSON.parse(raw) as { sessionId?: string; visitorId?: string };
      if (!parsed.sessionId || !parsed.visitorId) return;
      const sid = parsed.sessionId;
      const vid = parsed.visitorId;
      setSessionId(sid);
      setVisitorId(vid);
      setShowChat(true);
      setIsClosed(false);
      socket.connect();
      socket.emit('visitor_join', { sessionId: sid, visitorId: vid }, (resp: { status?: string }) => {
        if (resp.status === 'joined') {
          setStatus('Kangen Care Bot is ready to help');
          socket.emit('get_chat_history', { sessionId: sid }, (history: MessageEvent[]) => {
            setMessages(history);
          });
        } else {
          setStatus('Failed to join session');
          clearPersistedSession();
        }
      });
    } catch {
      // ignore parse/storage errors
    }
  }, [sessionId, visitorId, sessionIdParam, visitorIdParam]);

  // After pre-chat form / auto bot session start
  const handleSessionStarted = (data: SessionStartedPayload) => {
    console.debug('[widget] handleSessionStarted:', data);
    setSessionId(data.sessionId);
    setVisitorId(data.visitorId);
    persistSession(data.sessionId, data.visitorId);
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

  const startBotSession = useCallback(async () => {
    console.debug('[widget] startBotSession called', { sessionId, visitorId });
    if (sessionId || visitorId || startSessionInFlightRef.current) return;
    startSessionInFlightRef.current = true;
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
    } finally {
      startSessionInFlightRef.current = false;
    }
  }, [sessionId, visitorId]);

  // In inline mode, automatically show the chat
  useEffect(() => {
    if (!isInlineMode) return;
    if (!showChat) {
      setShowChat(true);
    }
  }, [isInlineMode, showChat, sessionId, visitorId]);

  // Whenever the chat panel is visible without a session, start the bot automatically
  useEffect(() => {
    if (showChat && (!sessionId || !visitorId)) {
      startBotSession();
    }
  }, [showChat, sessionId, visitorId, startBotSession]);

  const sendMessage = () => {
    const trimmed = messageInput.trim();
    if (!trimmed) return;
    if (!sessionId) {
      console.debug('[widget] sendMessage queued (no session yet):', trimmed);
      pendingMessageRef.current = trimmed;
      setMessageInput('');
      startBotSession();
      return;
    }
    console.debug('[widget] sendMessage emitting to server:', { sessionId, content: trimmed });
    socket.emit('send_message', { sessionId, role: 'USER', content: trimmed });
    setMessageInput('');
  };

  const exitChat = () => {
    if (!sessionId) return;
    socket.emit('end_chat', { sessionId });
    clearPersistedSession();
  };

  const requestHandoff = () => {
    if (!sessionId || handoffInProgress || handoffRequested) return;
    setHandoffInProgress(true);
    setStatus('Requesting a live agent...');
    socket.emit(
      'request_handoff',
      { sessionId },
      (resp: { ok?: boolean; error?: string; queuePosition?: number } = {}) => {
        setHandoffInProgress(false);
        if (resp.ok) {
          setHandoffRequested(true);

          if (typeof resp.queuePosition === 'number' && resp.queuePosition > 0) {
            setQueuePosition(resp.queuePosition);
            if (resp.queuePosition === 1) {
              setStatus('Waiting for a live agent to join... You are next in the queue.');
            } else {
              setStatus(`Waiting for a live agent to join... You are #${resp.queuePosition} in the queue.`);
            }
          } else {
            setQueuePosition(null);
            setStatus('Waiting for a live agent to join...');
          }
        } else {
          setQueuePosition(null);
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
    clearPersistedSession();
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
    setHandoffRequested(false);
    setHandoffInProgress(false);
    setQueuePosition(null);
    setAssignedAgent(null);
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
      }}
      className="flex items-center gap-2 rounded-full bg-[#024F9E] px-5 py-3 text-white font-semibold shadow-lg hover:bg-[#013a75] transition"
      aria-label="Open chat"
    >
      <MessageCircle className="h-5 w-5" />
      Chat with us
    </button>
  );

  const hasConversationActivity = messages.length > 0;
  const isLiveAgentActive = !!assignedAgent;

  return (
    <div
      className={
        isInlineMode
          ? 'w-full h-full'
          : 'fixed bottom-24 right-6 z-40 rounded-t-[24px] bg-white shadow-lg max-h-[80vh] flex flex-col w-[min(100vw-2rem,420px)]'
      }
    >
      {!isInlineMode && isMinimized ? (
        renderLauncher()
      ) : (
        <div className={isInlineMode ? 'w-full h-full' : 'relative flex flex-col max-h-[80vh] min-h-0'}>
          <div className="flex-1 flex flex-col bg-white min-h-0">
          <div className="flex flex-col gap-2 rounded-t-[24px] bg-[#024F9E] pt-0 pb-3 text-white">
            <div className="mx-auto flex w-full max-w-[360px] items-start justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white/20 text-white text-sm font-semibold shadow-sm">
                  KC
                </div>
                <div className="flex flex-col gap-0.5">
                  <div className="flex items-center gap-2">
                    <div className="text-base font-bold text-white">
                      {welcomeTitle}
                    </div>
                  </div>
                  <p className="flex items-center gap-2 text-xs text-blue-100/90">
                    <span className="inline-block h-2 w-2 rounded-full bg-emerald-400" />
                    Online now
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                {!isInlineMode && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="bg-transparent text-white/80 hover:text-white hover:bg-[#003a7a]/70 rounded-full shadow-sm hover:shadow-md"
                    onClick={() => setIsMinimized(true)}
                    aria-label="Minimize chat"
                  >
                    <Minus className="h-5 w-5" />
                  </Button>
                )}
              </div>
            </div>
            {!isLiveAgentActive && (
              <div className="mt-2 hidden flex-col gap-1">
                <p className="text-[11px] text-slate-600">Try asking about:</p>
                <div className="flex flex-wrap gap-2">
                  {['Order status', 'Warranty & repairs', 'Machine Setup'].map((label) => (
                  <button
                    key={label}
                    type="button"
                    className="rounded-full border border-sky-100 bg-white/80 px-3 py-1 text-xs font-medium text-slate-700 shadow-sm hover:bg-white"
                    onClick={() => {
                      const trimmed = label.trim();
                      if (!trimmed) return;

                      // If there is no active session yet, queue this message and start the bot session.
                      if (!sessionId) {
                        console.debug('[widget] quick-reply clicked before session; queueing and starting bot session', { label: trimmed });
                        pendingMessageRef.current = trimmed;
                        setMessageInput('');
                        startBotSession();
                        return;
                      }

                      // If a session already exists, send immediately.
                      socket.emit('send_message', { sessionId, role: 'USER', content: trimmed });
                    }}
                  >
                    {label}
                  </button>
                ))}
                </div>
              </div>
            )}
          </div>
          <div className="flex-1 flex flex-col bg-white min-h-0">
            {!sessionId || !visitorId ? (
              <div className="p-6 flex flex-col items-center text-center gap-3 text-slate-600">
                <Loader2 className="h-6 w-6 animate-spin text-[#024F9E]" />
                <p className="text-sm font-medium text-slate-700">Connecting you to Kangen Care Bot…</p>
                <p className="text-xs text-slate-500">We’ll greet you in just a moment.</p>
              </div>
            ) : (
              <>
                <div className="flex-1 p-0 bg-white min-h-0 flex flex-col">
                  <div
                    className={`flex-1 px-3 pt-3 overflow-y-auto ${isAgentTyping ? 'pb-16' : 'pb-6'}`}
                    ref={scrollAreaRef}
                  >
              {messages.length === 0 && (
                <div className="mt-1 mb-3 flex items-start gap-2 max-w-[90%]">
                  <div className="mt-1 flex h-7 w-7 items-center justify-center rounded-full border bg-[#024F9E] text-white text-xs font-semibold shadow-sm">
                    KB
                  </div>
                  <div className="rounded-2xl bg-slate-100 px-3 py-2 text-sm text-slate-800 shadow-sm">
                    <p className="text-sm leading-relaxed wrap-break-word">
                      Hi, I'm Kangen Care Bot. How can I help you today?
                    </p>
                  </div>
                </div>
              )}
              {messages.map((msg, index) => {
                const isUser = msg.role === 'USER';
                const isBot = !isUser && !msg.agentId;
                const isHumanAgent = !isUser && !!msg.agentId;
                const activeAgentMatches =
                  isHumanAgent && assignedAgent && msg.agentId === assignedAgent.id;
                const agentName = activeAgentMatches
                  ? assignedAgent?.displayName || assignedAgent?.name || 'Live agent'
                  : isHumanAgent
                  ? 'Live agent'
                  : '';
                const avatarText = isHumanAgent ? getInitials(agentName) : 'KB';
                const created = msg.createdAt ? new Date(msg.createdAt) : null;
                const timeLabel = created ? formatTimeLabel(created) : '';
                const prev = index > 0 ? messages[index - 1] : null;
                const prevDate = prev?.createdAt ? new Date(prev.createdAt) : null;
                const showDateChip =
                  created && (!prevDate || !isSameDay(created, prevDate));
                const dateLabel = created ? formatDateLabel(created) : '';

                return (
                  <div
                    key={msg.id ?? `${msg.sessionId}-${msg.createdAt ?? 't'}-${index}`}
                    className="mb-3 last:mb-4"
                  >
                    {showDateChip && dateLabel && (
                      <div className="mb-2 flex justify-center">
                        <span className="rounded-full bg-slate-100 px-3 py-0.5 text-[11px] text-slate-500">
                          {dateLabel}
                        </span>
                      </div>
                    )}
                    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
                      {isUser ? (
                        <div
                          className="max-w-[80%] rounded-2xl px-3 py-2 text-sm shadow-sm text-white bg-sky-500"
                          style={{ backgroundColor: primaryColor }}
                        >
                          <span
                            className="whitespace-pre-wrap wrap-break-word text-sm leading-relaxed"
                            dangerouslySetInnerHTML={{ __html: renderMessageContent(msg.content) }}
                          />
                          {timeLabel && (
                            <div className="mt-1 text-[10px] text-white/80 text-right">
                              {timeLabel}
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="flex items-start gap-2 max-w-[90%]">
                          <div
                            className={`mt-1 flex h-7 w-7 items-center justify-center rounded-full border text-sm font-semibold shadow-sm ${
                              isBot
                                ? 'bg-[#024F9E] text-white'
                                : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            }`}
                          >
                            {avatarText}
                          </div>
                          <div
                            className="max-w-[80%] rounded-2xl px-3 py-2 text-sm shadow-sm bg-slate-100 text-slate-800"
                          >
                            <span
                              className="whitespace-pre-wrap wrap-break-word text-sm leading-relaxed"
                              dangerouslySetInnerHTML={{ __html: renderMessageContent(msg.content) }}
                            />
                            {timeLabel && (
                              <div className="mt-1 text-[10px] text-slate-500 text-right">
                                {timeLabel}
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
              {isAgentTyping && (
                <div className="mt-2 mb-1 flex justify-start">
                  <div className="inline-flex items-center gap-2 rounded-full bg-slate-100 px-3 py-1 text-[11px] italic text-slate-600 shadow-sm">
                    <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" aria-hidden="true" />
                    Agent is typing…
                  </div>
                </div>
              )}
                  </div>
                </div>
                {!isClosed && (
            <div className="p-3 border-t bg-slate-50">
              <div className="flex w-full flex-col gap-2">
                {handoffRequested && !isLiveAgentActive && (
                  <p className="text-[11px] text-slate-500">
                    {typeof queuePosition === 'number' && queuePosition > 0
                      ? queuePosition === 1
                        ? 'You are next in the queue for a live agent.'
                        : `You are #${queuePosition} in the queue for a live agent.`
                      : 'Waiting for a live agent to join...'}
                  </p>
                )}
                {awaitingContactInfo && (
                  <p className="text-[11px] text-amber-600">
                    Please provide your email and phone number so we can connect you with a live agent.
                  </p>
                )}
                {!isLiveAgentActive && (
                  <div className="flex flex-col gap-1">
                    <span className="text-[11px] text-slate-500">Quick reply</span>
                    <div className="flex flex-wrap gap-2">
                      {['Order status', 'Warranty & repairs', 'Machine Setup'].map((label) => (
                        <button
                          key={label}
                          type="button"
                          className="rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] font-medium text-slate-700 shadow-sm hover:bg-slate-50 whitespace-nowrap max-w-[150px] overflow-hidden text-ellipsis transition-colors duration-150"
                          onClick={() => {
                            const trimmed = label.trim();
                            if (!trimmed) return;

                            if (!sessionId) {
                              console.debug('[widget] quick-reply clicked before session; queueing and starting bot session', { label: trimmed });
                              pendingMessageRef.current = trimmed;
                              setMessageInput('');
                              return;
                            }

                            socket.emit('send_message', { sessionId, role: 'USER', content: trimmed });
                          }}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                <div className="mt-1 flex w-full items-center justify-between gap-2">
                  <div className="relative flex flex-1 items-center gap-2 rounded-full bg-white px-4 py-2 shadow-md border-2 border-slate-300">
                    <Input
                      placeholder="Type your message here..."
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
                      className="border-0 shadow-none focus-visible:ring-0 focus-visible:ring-offset-0 text-sm placeholder:text-slate-400"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="icon"
                      className="h-8 w-8 rounded-full border-none text-slate-500 hover:text-slate-700 transition-colors duration-150"
                      onClick={() => setShowEmojiPicker((prev) => !prev)}
                    >
                      🙂
                    </Button>
                    <Button
                      type="button"
                      className="h-9 w-9 rounded-full p-0 bg-[#024F9E] hover:bg-[#013a75] text-white shadow transition-colors duration-150"
                      onClick={sendMessage}
                    >
                      <Send className="h-4 w-4" />
                    </Button>

                    {showEmojiPicker && (
                      <div className="absolute top-12 right-0 z-50 flex flex-wrap gap-1 rounded-md border border-slate-200 bg-white p-2 text-lg shadow-lg">
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
                  {hasConversationActivity && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={!sessionId || handoffInProgress || handoffRequested || awaitingContactInfo}
                      onClick={requestHandoff}
                      className="whitespace-nowrap text-[11px] text-slate-600 hover:text-slate-900 transition-colors duration-150"
                    >
                      {awaitingContactInfo ? 'Awaiting contact info' : handoffRequested ? 'Agent requested' : 'Talk to live agent'}
                    </Button>
                  )}
                </div>
              </div>
            </div>
          )}
          {sessionId && isClosed && (
            <div className="p-4 border-t">
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
            </div>
          )}
              </>
            )}
          </div>
        </div>
        {!isInlineMode && sessionId && !isClosed && (
          <button
            type="button"
            onClick={exitChat}
            className="absolute -bottom-12 left-6 flex h-12 w-12 items-center justify-center rounded-full border-4 border-white bg-red-500 text-white shadow-xl hover:bg-red-600 transition-colors duration-150"
            aria-label="End chat"
          >
            <X className="h-5 w-5" />
          </button>
        )}
        {isInlineMode && sessionId && !isClosed && (
          <div className="mt-4 flex justify-center">
            <Button variant="destructive" size="sm" onClick={exitChat}>
              End chat
            </Button>
          </div>
        )}
      </div>
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
