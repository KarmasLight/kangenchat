"use client";
import { useState, useEffect, useRef } from 'react';
import io, { Socket } from 'socket.io-client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Avatar, AvatarImage, AvatarFallback } from '@/components/ui/avatar';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';

type ChatEvent = { sessionId: string; visitor?: { name?: string; email?: string }; issueType?: string; createdAt?: string };
type EnrichedSession = { id: string; issueType?: string; status: string; createdAt?: string; visitor?: { id: string; name?: string; email?: string } };
type MessageEvent = { id: string; sessionId: string; role: 'USER' | 'AGENT'; content: string; createdAt: string };

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5010';
const socket: Socket = io(BACKEND_URL, { autoConnect: false });

export default function AgentDashboard() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const [status, setStatus] = useState<string>('Disconnected');
  const [email, setEmail] = useState<string>('agent@example.com');
  const [name, setName] = useState<string>('Support Agent');
  const [password, setPassword] = useState<string>('changeme');
  const [token, setToken] = useState<string>('');
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [agentDisplayName, setAgentDisplayName] = useState<string>('');
  const [agentEmail, setAgentEmail] = useState<string>('');
  const [agentPhone, setAgentPhone] = useState<string>('');
  const [agentAvatarUrl, setAgentAvatarUrl] = useState<string>('');
  const [presenceOnline, setPresenceOnline] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'chats' | 'profile'>('chats');
  const [pwdCurrent, setPwdCurrent] = useState('');
  const [pwdNew, setPwdNew] = useState('');
  const [availableChats, setAvailableChats] = useState<ChatEvent[]>([]);
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [messages, setMessages] = useState<MessageEvent[]>([]);
  const [messageInput, setMessageInput] = useState('');
  const [isTyping, setIsTyping] = useState<{ role: 'USER' | 'AGENT' } | null>(null);
  const typingTimerRef = useRef<number | null>(null);
  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({});
  const [newChats, setNewChats] = useState<Record<string, boolean>>({});
  const [notifPermission, setNotifPermission] = useState<'default' | 'denied' | 'granted'>(() =>
    typeof window !== 'undefined' && 'Notification' in window ? Notification.permission : 'default'
  );
  const [alerts, setAlerts] = useState<string[]>([]);
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false);
  // Live time ticks
  const [listTick, setListTick] = useState<number>(0);
  const [durationTick, setDurationTick] = useState<number>(0);
  const [selectedSessionCreatedAt, setSelectedSessionCreatedAt] = useState<string | undefined>(undefined);
  const [selectedSessionClosedAt, setSelectedSessionClosedAt] = useState<string | undefined>(undefined);

  useEffect(() => {
    // Hydrate from storage on first mount: token, profile, selected session
    try {
      const savedToken = typeof window !== 'undefined' ? window.localStorage.getItem('agent_token') : null;
      const savedProfile = typeof window !== 'undefined' ? window.localStorage.getItem('agent_profile') : null;
      const savedSession = typeof window !== 'undefined' ? window.localStorage.getItem('selected_session') : null;
      if (savedToken) {
        setToken(savedToken);
        (socket as any).auth = { token: savedToken };
        socket.connect();
        socket.emit('agent_ready');
      }
      if (savedProfile) {
        const p = JSON.parse(savedProfile);
        setAgentEmail(p.email || '');
        setName(p.name || '');
        setAgentDisplayName(p.displayName || p.name || '');
        setAgentPhone(p.phone || '');
        setAgentAvatarUrl(p.avatarUrl || '');
        setPresenceOnline((p.status || 'ONLINE') === 'ONLINE');
      }
      if (savedSession) {
        setSelectedSession(savedSession);
        socket.emit('join_session', { sessionId: savedSession }, () => {
          setIsLoadingHistory(true);
          socket.emit('get_chat_history', { sessionId: savedSession }, (history: MessageEvent[]) => {
            setMessages(history);
            setIsLoadingHistory(false);
          });
        });
        // Fetch session meta for duration
        fetch(`${BACKEND_URL}/sessions/${savedSession}`, {
          headers: token ? { Authorization: `Bearer ${token}` } : undefined as any,
        })
          .then(r => r.ok ? r.json() : null)
          .then((s) => {
            if (s?.createdAt) setSelectedSessionCreatedAt(s.createdAt);
          })
          .catch(() => {});
      }
    } catch {}
  }, []);

  useEffect(() => {
    // Persist selected session
    if (typeof window === 'undefined') return;
    if (selectedSession) {
      window.localStorage.setItem('selected_session', selectedSession);
    } else {
      window.localStorage.removeItem('selected_session');
    }
  }, [selectedSession]);

  useEffect(() => {
    // Socket listeners and realtime handlers
    const handleNewMessage = (data: MessageEvent) => {
      if (selectedSession === data.sessionId) {
        setMessages((prev) => [...prev, data]);
      } else {
        // increment unread for other sessions
        setUnreadCounts((prev) => ({ ...prev, [data.sessionId]: (prev[data.sessionId] || 0) + 1 }));
      }
    };

    socket.on('connect', () => setStatus('Connected'));
    socket.on('disconnect', (reason) => {
      setStatus(`Disconnected: ${reason || 'unknown'}`);
    });
    socket.on('connect_error', (err) => {
      setStatus(`Connect error: ${err?.message || 'unknown error'}`);
    });
    socket.on('error', (err) => {
      setStatus(`Socket error: ${typeof err === 'string' ? err : err?.message || 'unknown'}`);
    });
    socket.on('reconnect', () => {
      // Ensure auth is set after reconnect
      if (token) {
        (socket as any).auth = { token };
        socket.emit('agent_ready');
      }
      // Re-join selected session room to resume real-time updates
      if (selectedSession) {
        socket.emit('join_session', { sessionId: selectedSession }, () => {
          // Optionally refresh recent history to catch up any missed messages
          setIsLoadingHistory(true);
          socket.emit('get_chat_history', { sessionId: selectedSession }, (history: MessageEvent[]) => {
            setMessages(history);
            setIsLoadingHistory(false);
          });
        });
      }
      setStatus('Reconnected');
    });
    socket.on('new_chat_available', async (data: { sessionId: string }) => {
      // Fetch visitor and issueType for the sessionId
      if (!token) {
        // No token yet; add without visitor/issueType
        setAvailableChats((prev) => [...prev, { sessionId: data.sessionId }]);
        setNewChats((prev) => ({ ...prev, [data.sessionId]: true }));
        return;
      }
      try {
        const res = await fetch(`${BACKEND_URL}/sessions/${data.sessionId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const session = await res.json();
          const sessionData: EnrichedSession = session;
          const enriched: ChatEvent = {
            sessionId: data.sessionId,
            visitor: sessionData.visitor,
            issueType: sessionData.issueType,
            createdAt: sessionData.createdAt,
          };
          setAvailableChats((prev) => [...prev, enriched]);
          setNewChats((prev) => ({ ...prev, [data.sessionId]: true }));
        } else {
          // Fallback: add without visitor/issueType
          setAvailableChats((prev) => [...prev, { sessionId: data.sessionId }]);
          setNewChats((prev) => ({ ...prev, [data.sessionId]: true }));
        }
      } catch {
        // Fallback: add without visitor/issueType
        setAvailableChats((prev) => [...prev, { sessionId: data.sessionId }]);
        setNewChats((prev) => ({ ...prev, [data.sessionId]: true }));
      }
    });
    socket.on('new_message', handleNewMessage);
    socket.on('agent_joined', (data: ChatEvent) => console.log('Agent joined session:', data));
    socket.on('user_typing', (data: { sessionId: string; role: 'USER' | 'AGENT' }) => {
      if (selectedSession && data.sessionId === selectedSession) {
        setIsTyping({ role: data.role });
        if (typingTimerRef.current) window.clearTimeout(typingTimerRef.current);
        typingTimerRef.current = window.setTimeout(() => setIsTyping(null), 3000) as unknown as number;
      }
    });
    socket.on('user_stop_typing', (data: { sessionId: string; role: 'USER' | 'AGENT' }) => {
      if (selectedSession && data.sessionId === selectedSession) {
        if (typingTimerRef.current) window.clearTimeout(typingTimerRef.current);
        setIsTyping(null);
      }
    });
    socket.on('chat_closed', async (data: { sessionId: string }) => {
      if (selectedSession && data.sessionId === selectedSession) {
        // fetch closedAt for accurate total duration
        try {
          const res = await fetch(`${BACKEND_URL}/sessions/${data.sessionId}`, {
            headers: token ? { Authorization: `Bearer ${token}` } : undefined as any,
          });
          if (res.ok) {
            const s = await res.json();
            if (s?.closedAt) setSelectedSessionClosedAt(s.closedAt);
          }
        } catch {}
        setStatus('Chat closed');
      }
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('connect_error');
      socket.off('error');
      socket.off('reconnect');
      socket.off('new_chat_available');
      socket.off('new_message', handleNewMessage);
      socket.off('agent_joined');
      socket.off('user_typing');
      socket.off('user_stop_typing');
      socket.off('chat_closed');
    };
  }, [selectedSession, token]);

  useEffect(() => {
    // Clear typing indicator when switching sessions
    setIsTyping(null);
    if (typingTimerRef.current) window.clearTimeout(typingTimerRef.current);
    typingTimerRef.current = null;
  }, [selectedSession]);

  useEffect(() => {
    if (scrollAreaRef.current) {
      scrollAreaRef.current.scrollTop = scrollAreaRef.current.scrollHeight;
    }
  }, [messages]);

  // Tick list waiting times every 30s
  useEffect(() => {
    const id = window.setInterval(() => setListTick((t) => t + 1), 30000);
    return () => window.clearInterval(id);
  }, []);

  // Tick active chat duration every 1s when a session is selected
  useEffect(() => {
    if (!selectedSession) return;
    const id = window.setInterval(() => setDurationTick((t) => t + 1), 1000);
    return () => window.clearInterval(id);
  }, [selectedSession]);

  useEffect(() => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      setNotifPermission(Notification.permission);
    }
    socket.on('new_chat_notification', (data) => {
      if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
        new Notification('New Chat Available', { body: `Session ID: ${data.sessionId}` });
      } else {
        setAlerts((prev) => [...prev, `New chat available: ${data.sessionId}`]);
        setTimeout(() => setAlerts((prev) => prev.slice(1)), 4000);
      }
    });
    socket.on('new_message_notification', (data) => {
      if (
        typeof window !== 'undefined' &&
        'Notification' in window &&
        Notification.permission === 'granted' &&
        selectedSession === data.sessionId
      ) {
        new Notification('New Message', { body: data.content });
      } else if (selectedSession === data.sessionId) {
        setAlerts((prev) => [...prev, `New message: ${data.content.slice(0, 60)}`]);
        setTimeout(() => setAlerts((prev) => prev.slice(1)), 4000);
      }
    });
    return () => {
      socket.off('new_chat_notification');
      socket.off('new_message_notification');
    };
  }, []);

  const requestNotifications = async () => {
    if (typeof window === 'undefined' || !('Notification' in window)) return;
    try {
      const perm = await Notification.requestPermission();
      setNotifPermission(perm);
    } catch {}
  };

  const registerAgent = async () => {
    setStatus('Registering...');
    try {
      const res = await fetch(`${BACKEND_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, name, displayName: name, phone: agentPhone, avatarUrl: agentAvatarUrl }),
      });
      if (!res.ok) {
        const txt = await res.text();
        setStatus(`Registration failed${txt ? `: ${txt}` : ''}`);
        return;
      }
      const data = await res.json();
      setToken(data.token);
      try { window.localStorage.setItem('agent_token', data.token); } catch {}
      (socket as any).auth = { token: data.token };
      socket.connect();
      socket.emit('agent_ready');
      if (data.agent) {
        setAgentEmail(data.agent.email);
        setName(data.agent.name || name);
        setAgentDisplayName(data.agent.displayName || data.agent.name || name);
        setAgentPhone(data.agent.phone || '');
        setAgentAvatarUrl(data.agent.avatarUrl || '');
        setPresenceOnline((data.agent.status || 'ONLINE') === 'ONLINE');
        try { window.localStorage.setItem('agent_profile', JSON.stringify(data.agent)); } catch {}
      }
      setMode('login');
      setStatus('Registered. You are now logged in.');
    } catch (e) {
      setStatus('Registration error');
    }
  };

  const loginAgent = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        setStatus('Login failed');
        return;
      }
      const data = await res.json();
      setToken(data.token);
      try { window.localStorage.setItem('agent_token', data.token); } catch {}
      (socket as any).auth = { token: data.token };
      socket.connect();
      socket.emit('agent_ready');
      // hydrate profile from response
      if (data.agent) {
        setAgentEmail(data.agent.email);
        setName(data.agent.name || name);
        setAgentDisplayName(data.agent.displayName || data.agent.name || name);
        setAgentPhone(data.agent.phone || '');
        setAgentAvatarUrl(data.agent.avatarUrl || '');
        setPresenceOnline((data.agent.status || 'ONLINE') === 'ONLINE');
        try { window.localStorage.setItem('agent_profile', JSON.stringify(data.agent)); } catch {}
      } else {
        setAgentDisplayName(name);
      }
      setStatus('Logged in');
      setActiveTab('chats');
    } catch (e) {
      setStatus('Login error');
    }
  };

  const acceptChat = async (sessionId: string) => {
    socket.emit('agent_accept', { sessionId }, async (resp: { ok?: boolean; error?: string }) => {
      if (resp?.ok) {
        setSelectedSession(sessionId);
        // clear unread count when opening the chat
        setUnreadCounts((prev) => ({ ...prev, [sessionId]: 0 }));
        // clear "New" status when accepting
        setNewChats((prev) => ({ ...prev, [sessionId]: false }));
        // Explicitly join the session room to ensure real-time messages
        socket.emit('join_session', { sessionId }, () => {
          // After joining room, fetch history
          setIsLoadingHistory(true);
          socket.emit('get_chat_history', { sessionId }, (history: MessageEvent[]) => {
            setMessages(history);
            setIsLoadingHistory(false);
          });
        });
        // Fetch session meta for duration (ensure createdAt available)
        try {
          const resMeta = await fetch(`${BACKEND_URL}/sessions/${sessionId}`, {
            headers: token ? { Authorization: `Bearer ${token}` } : undefined as any,
          });
          if (resMeta.ok) {
            const sessMeta = await resMeta.json();
            if (sessMeta?.createdAt) setSelectedSessionCreatedAt(sessMeta.createdAt);
          }
        } catch {}
        // Fetch visitor info if missing
        const chat = availableChats.find(c => c.sessionId === sessionId);
        if (!chat?.visitor && token) {
          try {
            const res = await fetch(`${BACKEND_URL}/sessions/${sessionId}`, {
              headers: { Authorization: `Bearer ${token}` },
            });
            if (res.ok) {
              const session = await res.json();
              // Update availableChats with visitor info
              setAvailableChats(prev => prev.map(c => 
                c.sessionId === sessionId 
                  ? { ...c, visitor: session.visitor, issueType: session.issueType, createdAt: session.createdAt ?? c.createdAt }
                  : c
              ));
            }
          } catch {}
        }
      }
    });
  };

  const sendMessage = () => {
    if (selectedSession && messageInput.trim()) {
      socket.emit('send_message', { sessionId: selectedSession, role: 'AGENT', content: messageInput }, () => {});
      setMessageInput('');
    }
  };

  const initials = (agentDisplayName || name || email).split(' ').map(p=>p[0]).join('').slice(0,2).toUpperCase();

  const saveProfile = async () => {
    if (!token) return;
    setStatus('Saving profile...');
    try {
      const res = await fetch(`${BACKEND_URL}/me`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name, displayName: agentDisplayName, phone: agentPhone, avatarUrl: agentAvatarUrl }),
      });
      if (!res.ok) throw new Error('Save failed');
      setStatus('Profile saved');
    } catch {
      setStatus('Save failed');
    }
  };

  const changePassword = async () => {
    if (!token || !pwdCurrent || !pwdNew) return;
    setStatus('Updating password...');
    try {
      const res = await fetch(`${BACKEND_URL}/me/password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ currentPassword: pwdCurrent, newPassword: pwdNew }),
      });
      if (!res.ok) throw new Error('Password update failed');
      setPwdCurrent(''); setPwdNew('');
      setStatus('Password updated');
    } catch {
      setStatus('Password update failed');
    }
  };

  const togglePresence = async (checked: boolean) => {
    setPresenceOnline(checked);
    if (!token) return;
    try {
      await fetch(`${BACKEND_URL}/presence`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ status: checked ? 'ONLINE' : 'OFFLINE' }),
      });
      socket.emit('presence_update', { status: checked ? 'ONLINE' : 'OFFLINE' });
    } catch {}
  };

  if (!mounted) return null;

  return (
    <div className="h-screen w-full flex flex-col p-4 bg-gray-100 dark:bg-gray-900">
      {/* Notification banners */}
      {notifPermission === 'denied' && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 text-amber-800 px-3 py-2 text-sm">
          Notifications are blocked by the browser. Click the lock/tune icon in the address bar to enable, then reload.
        </div>
      )}
      {notifPermission === 'default' && (
        <div className="mb-3 rounded border border-sky-300 bg-sky-50 text-sky-800 px-3 py-2 text-sm flex items-center justify-between">
          <span>Enable notifications to get alerts for new chats and messages.</span>
          <Button size="sm" onClick={requestNotifications}>Enable</Button>
        </div>
      )}
      <Card className="mb-4">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-3">
              <Avatar className="h-8 w-8">
                {agentAvatarUrl ? <AvatarImage src={agentAvatarUrl} alt="avatar" /> : null}
                <AvatarFallback>{initials}</AvatarFallback>
              </Avatar>
              <span>{agentDisplayName || name || 'Agent'}</span>
            </span>
            <span className="flex items-center gap-2 text-sm">
              <Label htmlFor="presence">{presenceOnline ? 'Online' : 'Offline'}</Label>
              <Switch id="presence" checked={presenceOnline} onCheckedChange={togglePresence} />
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex items-center space-x-4 flex-wrap">
          {/* Mode toggle */}
          <div className="flex items-center space-x-2 mr-4">
            <Button variant={mode === 'login' ? 'default' : 'outline'} onClick={() => setMode('login')}>Login</Button>
            <Button variant={mode === 'register' ? 'default' : 'outline'} onClick={() => setMode('register')}>Register</Button>
          </div>

          {/* Common fields */}
          <Input placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
          {mode === 'register' && (
            <Input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          )}
          <Input placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />

          {/* Primary action */}
          {mode === 'login' ? (
            <Button onClick={loginAgent}>Login</Button>
          ) : (
            <Button onClick={registerAgent}>Create Account</Button>
          )}

          {/* Status + Agent name */}
          <div className="text-sm text-gray-500 min-w-32 flex flex-col">
            <span>{status}</span>
            <span className="text-gray-600">Agent: {agentDisplayName || '—'}</span>
          </div>
        </CardContent>
      </Card>

      {/* In-app fallback alerts */}
      {alerts.length > 0 && (
        <div className="mb-3 space-y-2">
          {alerts.map((a, i) => (
            <div key={`${i}-${a}`} className="rounded border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm">
              {a}
            </div>
          ))}
        </div>
      )}

      <Tabs value={activeTab} onValueChange={(v)=>setActiveTab(v as any)} className="flex-1">
        <TabsList>
          <TabsTrigger value="chats">Chats</TabsTrigger>
          <TabsTrigger value="profile">Profile</TabsTrigger>
        </TabsList>
        <Separator className="my-3" />

        <TabsContent value="chats" className="flex-1">
          <div className="grid grid-cols-3 gap-4">
            <Card className="col-span-1">
              <CardHeader>
                <CardTitle>Available Chats</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[60vh]">
                  <ul>
                    {availableChats.length === 0 && (
                      <li className="text-sm text-muted-foreground py-6 text-center">No available chats</li>
                    )}
                    {availableChats.map((chat) => (
                      <li key={chat.sessionId} className="mb-2">
                        <Button
                          variant={selectedSession === chat.sessionId ? 'default' : 'outline'}
                          className={`w-full justify-between text-left h-auto py-2 px-3 ${
                            selectedSession === chat.sessionId
                              ? 'ring-2 ring-blue-200'
                              : newChats[chat.sessionId]
                              ? 'ring-2 ring-blue-500 border-blue-500 bg-blue-100 dark:bg-blue-900/40'
                              : ''
                          }`}
                          aria-pressed={selectedSession === chat.sessionId}
                          onClick={() => acceptChat(chat.sessionId)}
                          disabled={!presenceOnline}
                        >
                          <div className="flex flex-col items-start">
                            {chat.visitor && (
                              <span className="text-sm text-muted-foreground">
                                {chat.visitor.name || 'Anonymous'}{chat.visitor.email && ` <${chat.visitor.email}>`}
                              </span>
                            )}
                            {chat.issueType && (
                              <span className="text-xs bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded mt-1">{chat.issueType}</span>
                            )}
                            {chat.createdAt && (
                              <span className="text-xs text-muted-foreground mt-1">
                                {(() => {
                                  const mins = Math.max(0, Math.floor((Date.now() - new Date(chat.createdAt as string).getTime()) / 60000));
                                  return mins < 1 ? 'Waiting <1 min' : `Waiting ${mins} min`;
                                })()}
                              </span>
                            )}
                          </div>
                          {selectedSession === chat.sessionId ? (
                            <span className="ml-3 inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                              <span className="h-2 w-2 rounded-full bg-green-500" />
                              Active
                            </span>
                          ) : (
                            <span className="flex items-center gap-2">
                              {newChats[chat.sessionId] && (
                                <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-blue-600 text-white dark:bg-blue-500 dark:text-white">
                                  New
                                </span>
                              )}
                              {(unreadCounts[chat.sessionId] ?? 0) > 0 && (
                                <span className="inline-flex items-center justify-center text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300 min-w-6">
                                  {unreadCounts[chat.sessionId]}
                                </span>
                              )}
                            </span>
                          )}
                        </Button>
                      </li>
                    ))}
                  </ul>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card className="col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>Active Chat</span>
                  {selectedSession && selectedSessionCreatedAt && (
                    <span className="text-sm text-muted-foreground">
                      {selectedSessionClosedAt
                        ? (() => {
                            const secs = Math.max(0, Math.floor((new Date(selectedSessionClosedAt as string).getTime() - new Date(selectedSessionCreatedAt as string).getTime()) / 1000));
                            const mm = String(Math.floor(secs / 60)).padStart(2, '0');
                            const ss = String(secs % 60).padStart(2, '0');
                            return `Total: ${mm}:${ss}`;
                          })()
                        : (() => {
                            const secs = Math.max(0, Math.floor((Date.now() - new Date(selectedSessionCreatedAt as string).getTime()) / 1000));
                            const mm = String(Math.floor(secs / 60)).padStart(2, '0');
                            const ss = String(secs % 60).padStart(2, '0');
                            return `Duration: ${mm}:${ss}`;
                          })()}
                    </span>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col h-[60vh]">
                {selectedSession ? (
                  <>
                    <ScrollArea className="flex-1 border rounded-md p-4 mb-4" ref={scrollAreaRef}>
                      {isLoadingHistory && (
                        <div className="text-center text-sm text-muted-foreground py-3">Loading messages...</div>
                      )}
                      {messages.length === 0 && !isLoadingHistory && (
                        <div className="text-center text-sm text-muted-foreground py-3">No messages yet</div>
                      )}
                      {messages.map((msg, index) => {
                        const prev = index > 0 ? messages[index - 1] : null;
                        const curDate = new Date(msg.createdAt).toDateString();
                        const prevDate = prev ? new Date(prev.createdAt).toDateString() : '';
                        const showDay = !prev || curDate !== prevDate;
                        const time = new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                        return (
                          <div key={msg.id ?? `${msg.sessionId}-${msg.createdAt ?? 't'}-${index}`}>
                            {showDay && (
                              <div className="my-2 text-center text-xs text-muted-foreground">
                                {new Date(msg.createdAt).toLocaleDateString()}
                              </div>
                            )}
                            <div className={`mb-2 text-sm ${msg.role === 'AGENT' ? 'text-right' : 'text-left'}`}>
                              <div className={`inline-block p-2 rounded-lg ${msg.role === 'AGENT' ? 'bg-blue-500 text-white' : 'bg-gray-200 dark:bg-gray-700'}`}>
                                {msg.content}
                              </div>
                              <div className={`mt-1 text-[10px] text-muted-foreground ${msg.role === 'AGENT' ? 'text-right' : 'text-left'}`}>{time}</div>
                            </div>
                          </div>
                        );
                      })}
                      {isTyping && <p className="text-sm italic">{isTyping.role === 'USER' ? 'User is typing...' : 'Agent is typing...'}</p>}
                    </ScrollArea>
                    <div className="flex space-x-2">
                      <Input
                        placeholder="Type a message..."
                        value={messageInput}
                        onChange={(e) => {
                          setMessageInput(e.target.value);
                          if (e.target.value) {
                            socket.emit('typing', { sessionId: selectedSession, role: 'AGENT' });
                          } else {
                            socket.emit('stop_typing', { sessionId: selectedSession, role: 'AGENT' });
                          }
                        }}
                        onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                      />
                      <Button onClick={sendMessage}>Send</Button>
                    </div>
                  </>
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-500">
                    Select a chat to begin.
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="profile">
          <div className="grid grid-cols-2 gap-4">
            <Card className="col-span-2 md:col-span-1">
              <CardHeader><CardTitle>Profile</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <Label>Email</Label>
                  <Input value={agentEmail || email} readOnly />
                </div>
                <div>
                  <Label>Name</Label>
                  <Input value={name} onChange={(e)=>setName(e.target.value)} />
                </div>
                <div>
                  <Label>Display Name</Label>
                  <Input value={agentDisplayName} onChange={(e)=>setAgentDisplayName(e.target.value)} />
                </div>
                <div>
                  <Label>Phone</Label>
                  <Input value={agentPhone} onChange={(e)=>setAgentPhone(e.target.value)} />
                </div>
                <div>
                  <Label>Avatar URL</Label>
                  <Input value={agentAvatarUrl} onChange={(e)=>setAgentAvatarUrl(e.target.value)} />
                </div>
                <div className="pt-2">
                  <Button onClick={saveProfile}>Save</Button>
                </div>
              </CardContent>
            </Card>

            <Card className="col-span-2 md:col-span-1">
              <CardHeader><CardTitle>Password</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <Label>Current Password</Label>
                  <Input type="password" value={pwdCurrent} onChange={(e)=>setPwdCurrent(e.target.value)} />
                </div>
                <div>
                  <Label>New Password</Label>
                  <Input type="password" value={pwdNew} onChange={(e)=>setPwdNew(e.target.value)} />
                </div>
                <div className="pt-2">
                  <Button variant="secondary" onClick={changePassword}>Change Password</Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
