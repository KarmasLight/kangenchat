"use client";
import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import type { ComponentType } from 'react';
import { useRouter } from 'next/navigation';
import { BACKEND_URL, getAgentSocket } from '@/lib/agentSocket';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Avatar, AvatarImage, AvatarFallback } from '@/components/ui/avatar';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Search, Filter, Clock, Users, Inbox, Sparkles, Activity, AlertTriangle, CheckCircle2, Info, Loader2 } from 'lucide-react';

const PRIMARY_COLOR = '#024F9E'; // Enagic water-brand blue

type ChatEvent = { sessionId: string; visitor?: { name?: string; email?: string }; issueType?: string; createdAt?: string };
type EnrichedSession = { id: string; issueType?: string; status: string; createdAt?: string; visitor?: { id: string; name?: string; email?: string } };
type SnapshotSession = {
  id: string;
  issueType?: string;
  createdAt?: string;
  status?: string;
  visitor?: { id: string; name?: string; email?: string };
  agent?: { id: string; name?: string; email?: string; displayName?: string };
};
type MessageEvent = { id: string; sessionId: string; role: 'USER' | 'AGENT'; content: string; createdAt: string };
type OfflineMessage = {
  id: string;
  issueType?: string;
  createdAt?: string;
  visitor?: { name?: string; email?: string };
  offlineHandledAt?: string | null;
  offlineHandledBy?: { id?: string; name?: string; displayName?: string; email?: string } | null;
  messagePreview?: string;
  messageCreatedAt?: string;
};

type OfflineMessageApiItem = {
  id: string;
  issueType?: string;
  createdAt?: string;
  visitor?: { name?: string; email?: string };
  offlineHandledAt?: string | null;
  offlineHandledBy?: { id?: string; name?: string; displayName?: string; email?: string } | null;
  messages?: Array<{ content: string; createdAt: string }>;
};

const socket = getAgentSocket();

export default function AgentDashboard() {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const [status, setStatus] = useState<string>('Loading...');
  const [name, setName] = useState<string>('Support Agent');
  const [token, setToken] = useState<string>('');
  const [agentDisplayName, setAgentDisplayName] = useState<string>('');
  const [agentEmail, setAgentEmail] = useState<string>('');
  const [agentPhone, setAgentPhone] = useState<string>('');
  const [agentAvatarUrl, setAgentAvatarUrl] = useState<string>('');
  const [presenceOnline, setPresenceOnline] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'chats' | 'offline' | 'profile' | 'admin'>('chats');
  const [pwdCurrent, setPwdCurrent] = useState('');
  const [pwdNew, setPwdNew] = useState('');
  const [selfAgentId, setSelfAgentId] = useState<string>('');
  const [availableChats, setAvailableChats] = useState<ChatEvent[]>([]);
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [messages, setMessages] = useState<MessageEvent[]>([]);
  const [messageInput, setMessageInput] = useState('');
  const [isTyping, setIsTyping] = useState<{ role: 'USER' | 'AGENT' } | null>(null);
  const typingTimerRef = useRef<number | null>(null);
  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({});
  const [newChats, setNewChats] = useState<Record<string, boolean>>({});
  const [endedChats, setEndedChats] = useState<Record<string, boolean>>({});
  const [closedAtMap, setClosedAtMap] = useState<Record<string, string | undefined>>({});
  const [assignedAgents, setAssignedAgents] = useState<Record<string, { id: string; name?: string; displayName?: string; email?: string }>>({});
  const [offlineMessages, setOfflineMessages] = useState<OfflineMessage[]>([]);
  const [offlineLoading, setOfflineLoading] = useState<boolean>(false);
  const [offlineHandleBusy, setOfflineHandleBusy] = useState<Record<string, boolean>>({});
  const [notifPermission, setNotifPermission] = useState<'default' | 'denied' | 'granted'>(() =>
    typeof window !== 'undefined' && 'Notification' in window ? Notification.permission : 'default'
  );
  const [alerts, setAlerts] = useState<string[]>([]);
  const [rowToasts, setRowToasts] = useState<Record<string, string>>({});
  const [transcriptEmail, setTranscriptEmail] = useState<string>('');
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false);
  // Live time ticks
  const [listTick, setListTick] = useState<number>(0);
  const [durationTick, setDurationTick] = useState<number>(0);
  const [selectedSessionCreatedAt, setSelectedSessionCreatedAt] = useState<string | undefined>(undefined);
  const [selectedSessionClosedAt, setSelectedSessionClosedAt] = useState<string | undefined>(undefined);
  const [selectedSessionAgent, setSelectedSessionAgent] = useState<{ id: string; name?: string; displayName?: string; email?: string } | null>(null);
  const [agents, setAgents] = useState<Array<{ id: string; email: string; name?: string; displayName?: string; status?: string }>>([]);
  const [transferTargetAgentId, setTransferTargetAgentId] = useState<string>('');
  const [hydrated, setHydrated] = useState<boolean>(false);
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
  const [adminPwdMap, setAdminPwdMap] = useState<Record<string, string>>({});
  const [adminPwdBusy, setAdminPwdBusy] = useState<Record<string, boolean>>({});
  const [adminLogoutBusy, setAdminLogoutBusy] = useState<Record<string, boolean>>({});
  const [mailHost, setMailHost] = useState<string>('');
  const [mailPort, setMailPort] = useState<string>('587');
  const [mailSecure, setMailSecure] = useState<boolean>(false);
  const [mailUser, setMailUser] = useState<string>('');
  const [mailPassword, setMailPassword] = useState<string>('');
  const [mailFrom, setMailFrom] = useState<string>('');
  const [mailLoading, setMailLoading] = useState<boolean>(false);
  const [mailSaving, setMailSaving] = useState<boolean>(false);
  const [showEmojiPickerAgent, setShowEmojiPickerAgent] = useState<boolean>(false);
  const [chatFilter, setChatFilter] = useState<'all' | 'mine' | 'unassigned' | 'new'>('all');
  const [chatSearch, setChatSearch] = useState<string>('');
  const [chatSort, setChatSort] = useState<'wait' | 'recent'>('wait');
  const [queueView, setQueueView] = useState<'waiting' | 'active' | 'closed'>('waiting');
  const [departments, setDepartments] = useState<Array<{ id: string; name: string }>>([]);
  const [joinedDepartments, setJoinedDepartments] = useState<string[]>([]);
  const [departmentBusyId, setDepartmentBusyId] = useState<string | null>(null);
  const [departmentsLoading, setDepartmentsLoading] = useState<boolean>(false);
  const [issueTypeFilter, setIssueTypeFilter] = useState<string>('all');

  const issueTypeOptions = [
    { value: 'all', label: 'All issues' },
    { value: 'general', label: 'General Inquiry' },
    { value: 'technical', label: 'Technical Support' },
    { value: 'billing', label: 'Billing' },
    { value: 'feedback', label: 'Feedback' },
  ];

  const onlineAgents = useMemo(() => agents.filter(a => (a.status || 'OFFLINE') === 'ONLINE'), [agents]);
  const offlineAgents = useMemo(() => agents.filter(a => (a.status || 'OFFLINE') !== 'ONLINE'), [agents]);

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

  const computeWaitMinutes = (createdAt?: string) => {
    if (!createdAt) return null;
    return Math.max(0, Math.floor((Date.now() - new Date(createdAt).getTime()) / 60000));
  };

  const downloadTranscript = async (format: 'text' | 'html') => {
    if (!selectedSession) return;
    try {
      const url = `${BACKEND_URL}/sessions/${selectedSession}/transcript${format === 'html' ? '?format=html' : ''}`;
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
      a.download = `transcript-${selectedSession}.${format === 'html' ? 'html' : 'txt'}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(href);
      setStatus('Transcript downloaded');
    } catch {
      setStatus('Failed to download transcript');
    }
  };

  const loadMailSettings = useCallback(async () => {
    if (!token || !isAdmin) return;
    setMailLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/admin/mail-settings`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return;
      const data = await res.json();
      setMailHost((data.host as string) || '');
      setMailPort(String(data.port ?? '587'));
      setMailSecure(Boolean(data.secure));
      setMailUser((data.user as string) || '');
      setMailFrom((data.fromAddress as string) || '');
    } catch {
      setStatus('Failed to load mail settings');
    } finally {
      setMailLoading(false);
    }
  }, [token, isAdmin]);

  const saveMailSettings = async () => {
    if (!token || !isAdmin) return;
    setMailSaving(true);
    setStatus('Saving mail settings...');
    try {
      const payload = {
        host: mailHost || null,
        port: mailPort ? Number(mailPort) : null,
        secure: mailSecure,
        user: mailUser || null,
        password: mailPassword || undefined,
        fromAddress: mailFrom || null,
      };
      const res = await fetch(`${BACKEND_URL}/admin/mail-settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(data?.error ? `Failed to save mail settings: ${data.error}` : 'Failed to save mail settings');
        return;
      }
      setStatus('Mail settings saved');
      setMailPassword('');
    } catch {
      setStatus('Failed to save mail settings');
    } finally {
      setMailSaving(false);
    }
  };

  const emailTranscript = async () => {
    if (!selectedSession) return;
    setStatus('Sending transcript...');
    try {
      const res = await fetch(`${BACKEND_URL}/transcripts/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: selectedSession, toEmail: transcriptEmail || undefined }),
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

  const statusBadgeTone = useMemo(() => {
    const lower = status.toLowerCase();
    if (lower.includes('disconnect') || lower.includes('error') || lower.includes('failed')) return 'error';
    if (lower.includes('reconnect') || lower.includes('connected')) return 'success';
    return 'neutral';
  }, [status]);

  const openChats = useMemo(
    () => availableChats.filter(chat => !endedChats[chat.sessionId]),
    [availableChats, endedChats]
  );

  const waitingChats = useMemo(
    () => openChats.filter(c => !assignedAgents[c.sessionId]),
    [openChats, assignedAgents]
  );

  const activeChats = useMemo(
    () => openChats.filter(c => assignedAgents[c.sessionId]?.id === selfAgentId),
    [openChats, assignedAgents, selfAgentId]
  );

  const closedChats = useMemo(
    () => availableChats.filter(c => endedChats[c.sessionId]),
    [availableChats, endedChats]
  );

  const openChatCount = openChats.length;
  const myOpenChatCount = activeChats.length;
  const newOpenChatCount = useMemo(
    () => openChats.filter(c => newChats[c.sessionId]).length,
    [openChats, newChats]
  );
  const waitingCount = waitingChats.length;
  const activeCount = activeChats.length;
  const closedCount = closedChats.length;

  const newWaitingCount = useMemo(
    () => waitingChats.filter(c => newChats[c.sessionId]).length,
    [waitingChats, newChats]
  );

  const longestWaitMinutes = useMemo(() => {
    let longest = 0;
    waitingChats.forEach(chat => {
      const wait = computeWaitMinutes(chat.createdAt) ?? 0;
      if (wait > longest) longest = wait;
    });
    return longest;
  }, [waitingChats, listTick]);

  const offlinePendingCount = useMemo(
    () => offlineMessages.filter(msg => !msg.offlineHandledAt).length,
    [offlineMessages]
  );

  const filteredOpenChats = useMemo(() => {
    const search = chatSearch.trim().toLowerCase();

    const byFilter = openChats.filter(chat => {
      const assignee = assignedAgents[chat.sessionId]?.id;
      switch (chatFilter) {
        case 'mine':
          return assignee === selfAgentId;
        case 'unassigned':
          return !assignee;
        case 'new':
          return newChats[chat.sessionId];
        default:
          return true;
      }
    });

    const byIssue = issueTypeFilter === 'all'
      ? byFilter
      : byFilter.filter(chat => chat.issueType === issueTypeFilter);

    const bySearch = search
      ? byIssue.filter(chat => {
        const composite = `${chat.sessionId} ${chat.issueType ?? ''} ${chat.visitor?.name ?? ''} ${chat.visitor?.email ?? ''}`.toLowerCase();
        return composite.includes(search);
      })
      : byIssue;

    const withWait = bySearch.map(chat => ({
      chat,
      waitMinutes: computeWaitMinutes(chat.createdAt) ?? 0,
    }));

    return withWait
      .sort((a, b) => {
        if (chatSort === 'recent') {
          const aTime = a.chat.createdAt ? new Date(a.chat.createdAt).getTime() : 0;
          const bTime = b.chat.createdAt ? new Date(b.chat.createdAt).getTime() : 0;
          return bTime - aTime;
        }
        return b.waitMinutes - a.waitMinutes;
      })
      .map(entry => entry.chat);
  }, [openChats, assignedAgents, chatFilter, chatSearch, chatSort, selfAgentId, newChats, listTick]);

  const filteredQueueChats = useMemo(() => {
    if (queueView === 'closed') {
      return [...closedChats].sort((a, b) => {
        const aClosed = closedAtMap[a.sessionId] ? new Date(closedAtMap[a.sessionId] as string).getTime() : 0;
        const bClosed = closedAtMap[b.sessionId] ? new Date(closedAtMap[b.sessionId] as string).getTime() : 0;
        return bClosed - aClosed;
      });
    }

    if (queueView === 'active') {
      return filteredOpenChats.filter(chat => assignedAgents[chat.sessionId]?.id === selfAgentId);
    }
    return filteredOpenChats.filter(chat => !assignedAgents[chat.sessionId]);
  }, [queueView, filteredOpenChats, closedChats, closedAtMap, assignedAgents, selfAgentId]);

  type WaitingMetric = { sessionId: string; waitMinutes: number; visitor?: { name?: string } };
  const slowestWaitingChat = useMemo<WaitingMetric | null>(() => {
    let target: { sessionId: string; waitMinutes: number; visitor?: { name?: string } } | null = null;
    waitingChats.forEach((chat) => {
      const wait = computeWaitMinutes(chat.createdAt);
      if (wait === null) return;
      if (!target || wait > target.waitMinutes) {
        target = { sessionId: chat.sessionId, waitMinutes: wait, visitor: chat.visitor };
      }
    });
    return target;
  }, [waitingChats]);

  const [csatStats, setCsatStats] = useState<{ average: number | null; total: number; positive: number } | null>(null);
  const csatScore = useMemo(() => {
    if (!csatStats || csatStats.average === null || csatStats.average === undefined) return null;
    const percent = (csatStats.average / 5) * 100;
    return Math.min(100, Math.max(0, Math.round(percent * 10) / 10));
  }, [csatStats]);
  const filteredQueueCount = filteredQueueChats.length;

  type BadgeMeta = { label: string; icon: ComponentType<{ className?: string }>; toneClass: string };
  type OverviewStat = { label: string; value: string; icon: ComponentType<{ className?: string }>; toneClass: string };

  const statusBadgeMeta = useMemo<BadgeMeta>(() => {
    const baseLabel = status?.trim() ? status.trim() : 'Idle';
    if (statusBadgeTone === 'error') {
      return {
        label: baseLabel,
        icon: AlertTriangle,
        toneClass: 'border border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-200',
      };
    }
    if (statusBadgeTone === 'success') {
      return {
        label: baseLabel,
        icon: CheckCircle2,
        toneClass: 'border border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-200',
      };
    }
    return {
      label: baseLabel,
      icon: Info,
      toneClass: 'border border-slate-200 bg-slate-100 text-slate-600 dark:border-slate-700 dark:bg-slate-800/40 dark:text-slate-200',
    };
  }, [status, statusBadgeTone]);

  const presenceBadgeMeta = useMemo<BadgeMeta>(() => (
    presenceOnline
      ? {
          label: 'Online',
          icon: Activity,
          toneClass: 'border border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-900/25 dark:text-emerald-200',
        }
      : {
          label: 'Offline',
          icon: Activity,
          toneClass: 'border border-slate-200 bg-slate-100 text-slate-600 dark:border-slate-700 dark:bg-slate-800/40 dark:text-slate-300',
        }
  ), [presenceOnline]);

  const overviewStats = useMemo<OverviewStat[]>(() => {
    const longestWaitLabel = openChatCount > 0 ? `${longestWaitMinutes} min` : '—';
    return [
      {
        label: 'Open',
        value: openChatCount.toString(),
        icon: Inbox,
        toneClass: 'border border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-800 dark:bg-sky-900/20 dark:text-sky-200',
      },
      {
        label: 'Assigned to you',
        value: myOpenChatCount.toString(),
        icon: Users,
        toneClass: 'border border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-200',
      },
      {
        label: 'New today',
        value: newOpenChatCount.toString(),
        icon: Sparkles,
        toneClass: 'border border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-800 dark:bg-purple-900/20 dark:text-purple-200',
      },
      {
        label: 'Longest wait',
        value: longestWaitLabel,
        icon: Clock,
        toneClass: 'border border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-200',
      },
    ];
  }, [openChatCount, myOpenChatCount, newOpenChatCount, longestWaitMinutes]);

  const StatusIcon = statusBadgeMeta.icon;
  const PresenceIcon = presenceBadgeMeta.icon;
  const longestWaitSummary = openChatCount > 0 ? `${longestWaitMinutes} min` : '—';
  const agentIdentityLabel = agentDisplayName || name || 'Agent';

  const refreshOfflineMessages = useCallback(async () => {
    if (!token) return;
    setOfflineLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/offline/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) {
          const mapped: OfflineMessage[] = data.map((item: OfflineMessageApiItem) => ({
            id: item.id,
            issueType: item.issueType,
            createdAt: item.createdAt,
            visitor: item.visitor,
            offlineHandledAt: item.offlineHandledAt,
            offlineHandledBy: item.offlineHandledBy,
            messagePreview: item.messages?.[0]?.content,
            messageCreatedAt: item.messages?.[0]?.createdAt,
          }));
          setOfflineMessages(mapped);
        } else {
          setOfflineMessages([]);
        }
      }
    } catch {
      setStatus('Failed to load offline messages');
    } finally {
      setOfflineLoading(false);
    }
  }, [token, setStatus]);

  const loadDepartments = useCallback(async () => {
    if (!token) return;
    setDepartmentsLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/departments`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        console.warn('load departments failed', res.status, body);
        setStatus('Failed to load departments');
        return;
      }
      const data = await res.json();
      if (Array.isArray(data)) {
        setDepartments(data);
      }
    } catch (err) {
      console.error('load departments error', err);
      setStatus('Failed to load departments');
    } finally {
      setDepartmentsLoading(false);
    }
  }, [token]);

  const refreshJoinedDepartments = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch(`${BACKEND_URL}/me/departments`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to load joined departments');
      const data = await res.json();
      if (Array.isArray(data)) {
        setJoinedDepartments(data.map((item: { id: string }) => item.id));
      }
    } catch (err) {
      console.error('refresh joined departments error', err);
    }
  }, [token]);

  const updateDepartmentMembership = useCallback(
    async (departmentId: string, join: boolean) => {
      if (!token) return;
      setDepartmentBusyId(departmentId);
      try {
        const res = await fetch(`${BACKEND_URL}/departments/${departmentId}/agents/me`, {
          method: join ? 'POST' : 'DELETE',
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error('Department request failed');
        setJoinedDepartments((prev) => {
          if (join) {
            return prev.includes(departmentId) ? prev : [...prev, departmentId];
          }
          return prev.filter((id) => id !== departmentId);
        });
      } catch (err) {
        console.error('update department membership error', err);
        setStatus('Failed to update department availability');
      } finally {
        setDepartmentBusyId(null);
      }
    },
    [token]
  );

  useEffect(() => {
    loadDepartments();
    refreshJoinedDepartments();
  }, [loadDepartments, refreshJoinedDepartments]);

  const markOfflineHandled = useCallback(async (sessionId: string) => {
    if (!token) return;
    setOfflineHandleBusy(prev => ({ ...prev, [sessionId]: true }));
    try {
      const res = await fetch(`${BACKEND_URL}/offline/messages/${sessionId}/handle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed');
      const payload = await res.json();
      setOfflineMessages(prev =>
        prev.map(msg =>
          msg.id === sessionId
            ? {
                ...msg,
                offlineHandledAt: payload.offlineHandledAt,
                offlineHandledBy: payload.offlineHandledBy,
              }
            : msg
        )
      );
      setStatus('Offline message marked handled');
    } catch {
      setStatus('Failed to mark offline message handled');
    } finally {
      setOfflineHandleBusy(prev => {
        const next = { ...prev };
        delete next[sessionId];
        return next;
      });
    }
  }, [token]);

  const handleLogout = async (options?: { reason?: string }) => {
    try {
      if (token) {
        await fetch(`${BACKEND_URL}/presence`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ status: 'OFFLINE' }),
        }).catch(() => {});
      }
    } catch {}
    setToken('');
    setPresenceOnline(false);
    setStatus(options?.reason === 'ADMIN_FORCE' ? 'You have been signed out by an administrator' : 'Logged out');
    setSelectedSession(null);
    setMessages([]);
    setAvailableChats([]);
    setAssignedAgents({});
    setNewChats({});
    setEndedChats({});
    setClosedAtMap({});
    setSelectedSessionAgent(null);
    setSelectedSessionCreatedAt(undefined);
    setSelectedSessionClosedAt(undefined);
    setTransferTargetAgentId('');
    setAgents([]);
    try { window.localStorage.removeItem('agent_token'); } catch {}
    try { window.localStorage.removeItem('agent_profile'); } catch {}
    try { window.localStorage.removeItem('selected_session'); } catch {}
    socket.disconnect();
    setHydrated(false);
    router.push('/agent/auth');
  };

  useEffect(() => {
    // Hydrate from storage on first mount: token, profile, selected session
    try {
      const savedToken = typeof window !== 'undefined' ? window.localStorage.getItem('agent_token') : null;
      const savedProfile = typeof window !== 'undefined' ? window.localStorage.getItem('agent_profile') : null;
      const savedSession = typeof window !== 'undefined' ? window.localStorage.getItem('selected_session') : null;
      if (savedToken) {
        setToken(savedToken);
        setStatus('Connecting...');
        socket.auth = { token: savedToken };
        socket.connect();
        socket.emit('agent_ready');
        refreshOfflineMessages();
      }
      if (!savedToken) {
        setStatus('Please log in');
      }
      if (savedProfile) {
        const p = JSON.parse(savedProfile) as {
          id?: string;
          email?: string;
          name?: string;
          displayName?: string;
          phone?: string;
          avatarUrl?: string;
          status?: string;
          isAdmin?: boolean;
        };
        setAgentEmail(p.email || '');
        setName(p.name || '');
        setAgentDisplayName(p.displayName || p.name || '');
        if (p.id) setSelfAgentId(p.id);
        setAgentPhone(p.phone || '');
        setAgentAvatarUrl(p.avatarUrl || '');
        setPresenceOnline((p.status || 'ONLINE') === 'ONLINE');
        setIsAdmin(!!p.isAdmin);
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
          headers: savedToken ? { Authorization: `Bearer ${savedToken}` } : undefined,
        })
          .then(r => (r.ok ? r.json() : null))
          .then((s) => {
            if (s?.createdAt) setSelectedSessionCreatedAt(s.createdAt);
            if (s?.agent) setSelectedSessionAgent(s.agent);
          })
          .catch(() => {});
      }
      if (!savedToken) {
        router.replace('/agent/auth');
      }
    } catch {}
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (!token) {
      setCsatStats(null);
      return;
    }
    let abort = false;
    fetch(`${BACKEND_URL}/analytics/csat`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((payload) => {
        if (abort) return;
        if (payload) {
          setCsatStats({
            average: payload.average ?? null,
            total: payload.total ?? 0,
            positive: payload.positive ?? 0,
          });
        }
      })
      .catch(() => {
        if (!abort) setCsatStats(null);
      });
    return () => {
      abort = true;
    };
  }, [token]);

  // Refresh agents when token changes
  useEffect(() => {
    if (!token) return;
    fetch(`${BACKEND_URL}/agents`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : [])
      .then(setAgents)
      .catch(() => {});
  }, [token]);

  // Load mail settings for admins
  useEffect(() => {
    if (!token || !isAdmin) return;
    loadMailSettings();
  }, [token, isAdmin, loadMailSettings]);

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

    if (socket.connected) {
      setStatus('Connected');
    }

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
        socket.auth = { token };
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
    socket.on('force_logout', (payload: { reason?: string }) => {
      handleLogout({ reason: payload?.reason });
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
    socket.on('open_sessions_snapshot', (payload: { sessions?: SnapshotSession[] }) => {
      const sessions = Array.isArray(payload?.sessions) ? payload.sessions : [];
      const mapped = sessions.map((s) => ({
        sessionId: s.id,
        visitor: s.visitor,
        issueType: s.issueType,
        createdAt: s.createdAt,
      }));
      setAvailableChats(mapped);
      setAssignedAgents(() => {
        const next: Record<string, { id: string; name?: string; displayName?: string; email?: string }> = {};
        sessions.forEach((s) => {
          if (s.agent) {
            next[s.id] = s.agent;
          }
        });
        return next;
      });
      setEndedChats(() => ({}));
      setNewChats(() => {
        const next: Record<string, boolean> = {};
        sessions.forEach((s) => {
          next[s.id] = !s.agent;
        });
        return next;
      });
    });
    socket.on('agents_snapshot', (payload: { agents?: Array<{ id: string; email: string; name?: string; displayName?: string; status?: string }> }) => {
      if (Array.isArray(payload?.agents)) {
        setAgents(payload.agents);
        const me = payload.agents.find(a => a.id === selfAgentId);
        if (me?.displayName || me?.name) {
          setAgentDisplayName(prev => prev || me.displayName || me.name || prev);
        }
      }
    });
    type SessionAgentPayload = {
      sessionId?: string;
      agent?: { id: string; name?: string; displayName?: string; email?: string };
    };

    socket.on('agent_joined', (data: SessionAgentPayload) => {
      if (!data?.sessionId || !data.agent) return;
      const sessionId = data.sessionId;
      const agent = data.agent;
      setAssignedAgents(prev => ({ ...prev, [sessionId]: agent }));
      // In-app alert
      setAlerts(prev => [...prev, `Session ${sessionId} assigned to ${agent.displayName || agent.name || agent.email}`]);
      setTimeout(() => setAlerts(prev => prev.slice(1)), 4000);
      const toast = `Accepted by ${agent.displayName || agent.name || agent.email}`;
      setRowToasts(prev => ({ ...prev, [sessionId]: toast }));
      setTimeout(() => {
        setRowToasts(prev => {
          const next = { ...prev };
          delete next[sessionId];
          return next;
        });
      }, 2500);
    });
    socket.on('session_assigned', (data: SessionAgentPayload) => {
      if (!data?.sessionId || !data.agent) return;
      const sessionId = data.sessionId;
      const agent = data.agent;
      setAssignedAgents(prev => ({ ...prev, [sessionId]: agent }));
    });
    socket.on('session_transferred', (data: SessionAgentPayload) => {
      if (!data?.sessionId || !data.agent) return;
      const sessionId = data.sessionId;
      const agent = data.agent;
      setAssignedAgents(prev => ({ ...prev, [sessionId]: agent }));
      if (agent.id === selfAgentId) {
        setAlerts(prev => [...prev, `You received transfer for session ${sessionId}`]);
        setTimeout(() => setAlerts(prev => prev.slice(1)), 4000);
      }
      const toast = `Transferred to ${agent.displayName || agent.name || agent.email}`;
      setRowToasts(prev => ({ ...prev, [sessionId]: toast }));
      setTimeout(() => {
        setRowToasts(prev => {
          const { [sessionId]: _ignored, ...rest } = prev;
          return rest;
        });
      }, 2500);
    });
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
      // Remove closed session from available list and cleanup state
      setAvailableChats((prev) => prev.filter((chat) => chat.sessionId !== data.sessionId));
      setEndedChats((prev) => {
        const next = { ...prev };
        delete next[data.sessionId];
        return next;
      });
      setNewChats((prev) => {
        const next = { ...prev };
        delete next[data.sessionId];
        return next;
      });
      setAssignedAgents((prev) => {
        if (!prev[data.sessionId]) return prev;
        const { [data.sessionId]: _removed, ...rest } = prev;
        return rest;
      });
      if (selectedSession && data.sessionId === selectedSession) {
        // fetch closedAt for accurate total duration
        try {
          const res = await fetch(`${BACKEND_URL}/sessions/${data.sessionId}`, {
            headers: token ? { Authorization: `Bearer ${token}` } : undefined,
          });
          if (res.ok) {
            const s = await res.json();
            if (s?.closedAt) setSelectedSessionClosedAt(s.closedAt);
            if (s?.closedAt) setClosedAtMap(prev => ({ ...prev, [data.sessionId]: s.closedAt }));
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
      socket.off('open_sessions_snapshot');
      socket.off('agents_snapshot');
      socket.off('agent_joined');
      socket.off('session_assigned');
      socket.off('session_transferred');
      socket.off('offline_message_created');
      socket.off('offline_message_handled');
      socket.off('user_typing');
      socket.off('user_stop_typing');
      socket.off('chat_closed');
      socket.off('force_logout');
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

  const acceptChat = async (sessionId: string) => {
    socket.emit('agent_accept', { sessionId }, async (resp: { ok?: boolean; error?: string }) => {
      if (resp?.ok) {
        setSelectedSession(sessionId);
        // clear unread count when opening the chat
        setUnreadCounts((prev) => ({ ...prev, [sessionId]: 0 }));
        // clear "New" status when accepting
        setNewChats((prev) => ({ ...prev, [sessionId]: false }));
        // inline toast feedback
        setRowToasts(prev => ({ ...prev, [sessionId]: 'Accepted by You' }));
        setTimeout(() => {
          setRowToasts(prev => { const { [sessionId]: _ignored, ...rest } = prev; return rest; });
        }, 2500);
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
            headers: token ? { Authorization: `Bearer ${token}` } : undefined,
          });
          if (resMeta.ok) {
            const sessMeta = await resMeta.json();
            if (sessMeta?.createdAt) setSelectedSessionCreatedAt(sessMeta.createdAt);
            if (sessMeta?.agent) setSelectedSessionAgent(sessMeta.agent);
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
      } else {
        setStatus(`Accept failed${resp?.error ? `: ${resp.error}` : ''}`);
      }
    });
  };

  const endChat = () => {
    if (!selectedSession) return;
    setStatus('Ending chat...');
    socket.emit('end_chat', { sessionId: selectedSession });
  };

  const sendMessage = () => {
    if (selectedSession && messageInput.trim()) {
      socket.emit('send_message', { sessionId: selectedSession, role: 'AGENT', content: messageInput }, () => {});
      setMessageInput('');
    }
  };

  const transferSession = async () => {
    if (!selectedSession || selectedSessionClosedAt || !transferTargetAgentId) return;
    setStatus('Transferring...');
    try {
      const res = await fetch(`${BACKEND_URL}/sessions/${selectedSession}/transfer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ agentId: transferTargetAgentId }),
      });
      if (!res.ok) { setStatus('Transfer failed'); return; }
      // Refresh session meta to show new agent
      try {
        const m = await fetch(`${BACKEND_URL}/sessions/${selectedSession}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
        if (m.ok) {
          const s = await m.json();
          if (s?.agent) setSelectedSessionAgent(s.agent);
        }
      } catch {}
      setTransferTargetAgentId('');
      setStatus('Transferred');
    } catch {
      setStatus('Transfer failed');
    }
  };

  const openClosedChat = async (sessionId: string) => {
    // Open a closed chat in read-only mode (no accept). Join room and fetch history/meta.
    setSelectedSession(sessionId);
    socket.emit('join_session', { sessionId }, () => {
      setIsLoadingHistory(true);
      socket.emit('get_chat_history', { sessionId }, (history: MessageEvent[]) => {
        setMessages(history);
        setIsLoadingHistory(false);
      });
    });
    try {
      const res = await fetch(`${BACKEND_URL}/sessions/${sessionId}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
      });
      if (res.ok) {
        const s = await res.json();
        if (s?.createdAt) setSelectedSessionCreatedAt(s.createdAt);
        if (s?.closedAt) {
          setSelectedSessionClosedAt(s.closedAt);
          setClosedAtMap(prev => ({ ...prev, [sessionId]: s.closedAt }));
        }
      }
    } catch {}
  };

  const initialsSource = (agentDisplayName || name || agentEmail || '').trim();
  const initials = initialsSource
    ? initialsSource
        .split(/\s+/)
        .map((part) => part?.[0] ?? '')
        .join('')
        .slice(0, 2)
        .toUpperCase()
    : 'AG';

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

  const setAgentPassword = async (agentId: string) => {
    if (!token) return;
    const newPassword = (adminPwdMap[agentId] || '').trim();
    if (!newPassword) {
      setStatus('Enter a new password');
      return;
    }
    if (newPassword.length < 8) {
      setStatus('Admin-set password must be at least 8 characters');
      return;
    }
    setAdminPwdBusy(prev => ({ ...prev, [agentId]: true }));
    setStatus('Updating password...');
    try {
      const res = await fetch(`${BACKEND_URL}/admin/agents/${agentId}/password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ newPassword }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(data?.error ? `Password update failed: ${data.error}` : 'Password update failed');
        return;
      }
      setStatus('Password updated');
      setAdminPwdMap(prev => ({ ...prev, [agentId]: '' }));
    } catch {
      setStatus('Password update failed');
    } finally {
      setAdminPwdBusy(prev => {
        const next = { ...prev };
        delete next[agentId];
        return next;
      });
    }
  };

  const logoffAgent = async (agentId: string) => {
    if (!token) return;
    if (agentId === selfAgentId) {
      setStatus('Use the regular logout button to sign yourself out');
      return;
    }
    setAdminLogoutBusy(prev => ({ ...prev, [agentId]: true }));
    setStatus('Logging agent off...');
    try {
      const res = await fetch(`${BACKEND_URL}/admin/agents/${agentId}/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(data?.error ? `Logoff failed: ${data.error}` : 'Logoff failed');
        return;
      }
      setStatus('Agent logged off');
      setAgents(prev => prev.map(a => (a.id === agentId ? { ...a, status: 'OFFLINE' } : a)));
    } catch {
      setStatus('Logoff failed');
    } finally {
      setAdminLogoutBusy(prev => {
        const next = { ...prev };
        delete next[agentId];
        return next;
      });
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
        <CardHeader className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <Avatar className="h-10 w-10">
              {agentAvatarUrl ? <AvatarImage src={agentAvatarUrl} alt="avatar" /> : null}
              <AvatarFallback>{initials}</AvatarFallback>
            </Avatar>
            <div>
              <CardTitle className="text-lg font-semibold leading-tight" style={{ color: PRIMARY_COLOR }}>
                {agentIdentityLabel}
              </CardTitle>
              {agentEmail && <div className="text-sm text-muted-foreground">{agentEmail}</div>}
              <div className="mt-2 flex flex-wrap gap-2 text-xs sm:text-sm">
                <span className={`inline-flex items-center gap-2 rounded-full px-3 py-1 ${presenceBadgeMeta.toneClass}`}>
                  <PresenceIcon className="h-4 w-4" />
                  <span>{presenceBadgeMeta.label}</span>
                  <Switch id="presence" checked={presenceOnline} onCheckedChange={togglePresence} />
                </span>
                <span className={`inline-flex items-center gap-2 rounded-full px-3 py-1 ${statusBadgeMeta.toneClass}`}>
                  <StatusIcon className="h-4 w-4" />
                  <span>{statusBadgeMeta.label}</span>
                </span>
              </div>
            </div>
          </div>
          <div className="flex flex-col gap-2 text-sm text-muted-foreground md:text-right">
            <div>Connection: {status}</div>
            <Button size="sm" variant="outline" onClick={() => handleLogout()} className="self-start md:self-end">Log out</Button>
          </div>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {overviewStats.map((stat) => {
            const StatIcon = stat.icon;
            return (
              <div
                key={stat.label}
                className={`rounded-lg p-3 transition-colors duration-150 ${stat.toneClass}`}
              >
                <div className="flex items-center justify-between text-xs font-medium uppercase tracking-wide">
                  <span>{stat.label}</span>
                  <StatIcon className="h-4 w-4" />
                </div>
                <div className="mt-1 text-2xl font-semibold text-foreground">{stat.value}</div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card className="mb-4">
        <CardHeader className="flex items-center justify-between">
          <CardTitle className="text-lg font-semibold" style={{ color: PRIMARY_COLOR }}>
            Routing & Departments
          </CardTitle>
          {departmentsLoading && <Loader2 className="h-4 w-4 text-muted-foreground" />}
        </CardHeader>
        <CardContent>
          {departments.length === 0 ? (
            <p className="text-sm text-muted-foreground">No departments configured.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {departments.map((dept) => {
                const joined = joinedDepartments.includes(dept.id);
                return (
                  <Button
                    key={dept.id}
                    size="sm"
                    variant={joined ? 'default' : 'outline'}
                    className="rounded-full px-3"
                    onClick={() => updateDepartmentMembership(dept.id, !joined)}
                    disabled={departmentBusyId === dept.id}
                  >
                    <span className="text-xs font-semibold">{dept.name}</span>
                    <span className="ml-2 text-[10px] text-muted-foreground">
                      {joined ? 'Available' : 'Join'}
                    </span>
                  </Button>
                );
              })}
            </div>
          )}
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
          <TabsTrigger value="offline">Offline Messages</TabsTrigger>
          <TabsTrigger value="profile">Profile</TabsTrigger>
          {isAdmin && <TabsTrigger value="admin">Admin</TabsTrigger>}
        </TabsList>
        <Separator className="my-3" />

        <TabsContent value="chats" className="flex-1">
          <div className="grid grid-cols-3 gap-4">
            <Card className="col-span-1">
              <CardHeader>
                <CardTitle className="text-lg font-semibold leading-tight" style={{ color: PRIMARY_COLOR }}>
                  Available Chats
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="mb-4 space-y-3">
                  <div className="flex flex-wrap gap-2">
                    {[
                      { key: 'waiting', label: `Waiting (${waitingCount})` },
                      { key: 'active', label: `Active (${activeCount})` },
                      { key: 'closed', label: `Closed (${closedCount})` },
                    ].map((tab) => (
                      <Button
                        key={tab.key}
                        variant={queueView === tab.key ? 'default' : 'outline'}
                        size="sm"
                        onClick={() => setQueueView(tab.key as typeof queueView)}
                      >
                        {tab.label}
                      </Button>
                    ))}
                  </div>
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex flex-1 flex-col gap-2 sm:flex-row sm:items-center">
                      <div className="relative flex-1">
                        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                        <Input
                          value={chatSearch}
                          onChange={(event) => setChatSearch(event.target.value)}
                          placeholder="Search visitor, email, or issue"
                          className="pl-9"
                        />
                      </div>
                      {chatSearch && (
                        <Button variant="ghost" size="sm" onClick={() => setChatSearch('')}>Clear</Button>
                      )}
                    </div>
                    {queueView !== 'closed' && (
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-2">
                        <div className="flex items-center gap-2">
                          <Filter className="h-4 w-4 text-muted-foreground" />
                          <Select value={chatFilter} onValueChange={(value: typeof chatFilter) => setChatFilter(value)}>
                            <SelectTrigger className="h-9 w-[140px]">
                              <SelectValue placeholder="Filter" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All chats</SelectItem>
                              <SelectItem value="mine">My chats</SelectItem>
                              <SelectItem value="unassigned">Unassigned</SelectItem>
                              <SelectItem value="new">New</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="flex items-center gap-2">
                          <Loader2 className="h-4 w-4 text-muted-foreground" />
                          <Select value={chatSort} onValueChange={(value: typeof chatSort) => setChatSort(value)}>
                            <SelectTrigger className="h-9 w-[150px]">
                              <SelectValue placeholder="Sort by" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="wait">Longest wait</SelectItem>
                              <SelectItem value="recent">Most recent</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="grid gap-2 text-sm">
                    <div className="flex items-center justify-between rounded-md border border-muted bg-background/80 px-3 py-2 text-muted-foreground shadow-sm">
                      <div className="flex items-center gap-2"><Inbox className="h-4 w-4" /><span>{queueView === 'waiting' ? 'Waiting' : queueView === 'active' ? 'Active' : 'Closed'} chats</span></div>
                      <span className="font-medium text-foreground">{filteredQueueChats.length}</span>
                    </div>
                    <div className="flex items-center justify-between rounded-md border border-muted bg-background/80 px-3 py-2 text-muted-foreground shadow-sm">
                      <div className="flex items-center gap-2"><Users className="h-4 w-4" /><span>Agents online</span></div>
                      <span className="font-medium text-foreground">{onlineAgents.length}</span>
                    </div>
                    <div className="flex items-center justify-between rounded-md border border-muted bg-background/80 px-3 py-2 text-muted-foreground shadow-sm">
                      <div className="flex items-center gap-2"><Clock className="h-4 w-4" /><span>Longest wait</span></div>
                      <span className="font-medium text-foreground">{longestWaitSummary}</span>
                    </div>
                    <div className="flex items-center justify-between rounded-md border border-muted bg-background/80 px-3 py-2 text-muted-foreground shadow-sm">
                      <div className="flex items-center gap-2"><Inbox className="h-4 w-4" /><span>Filtered chats</span></div>
                      <span className="font-medium text-foreground">{filteredQueueCount}</span>
                    </div>
                    <div className="flex items-center justify-between rounded-md border border-muted bg-background/80 px-3 py-2 text-muted-foreground shadow-sm">
                      <div className="flex flex-col">
                        <span className="flex items-center gap-2"><Clock className="h-4 w-4" /><span>Slowest waiting</span></span>
                        {slowestWaitingChat ? (
                          <span className="text-xs text-muted-foreground">{slowestWaitingChat.visitor?.name || slowestWaitingChat.sessionId.slice(-4)} · {slowestWaitingChat.waitMinutes} min</span>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </div>
                      <span className="font-medium text-foreground">{slowestWaitingChat ? `${slowestWaitingChat.waitMinutes}m` : '—'}</span>
                    </div>
                    <div className="flex items-center justify-between rounded-md border border-muted bg-background/80 px-3 py-2 text-muted-foreground shadow-sm">
                      <div className="flex items-center gap-2"><Sparkles className="h-4 w-4" /><span>CSAT</span></div>
                      <span className="font-medium text-foreground">{csatScore !== null ? `${csatScore.toFixed(1)}%` : '—'}</span>
                    </div>
                  </div>
                </div>
                <ScrollArea className="h-[60vh]">
                  <ul>
                    {filteredQueueChats.length === 0 && (
                      <li className="text-sm text-muted-foreground py-6 text-center">No chats match the current filters.</li>
                    )}
                    {queueView !== 'closed' && filteredQueueChats.map((chat) => {
                      const waitMinutes = computeWaitMinutes(chat.createdAt);
                      const waitLabel = waitMinutes === null
                        ? 'Waiting'
                        : waitMinutes < 1
                        ? 'Waiting <1 min'
                        : `Waiting ${waitMinutes} min`;
                      const urgencyClass = waitMinutes === null
                        ? 'hover:border-slate-300'
                        : waitMinutes >= 15
                        ? 'border-red-200 bg-red-50/60 hover:border-red-300 dark:border-red-900/40 dark:bg-red-900/20'
                        : waitMinutes >= 5
                        ? 'border-amber-200 bg-amber-50/60 hover:border-amber-300 dark:border-amber-900/40 dark:bg-amber-900/20'
                        : 'border-emerald-200 bg-emerald-50/60 hover:border-emerald-300 dark:border-emerald-900/40 dark:bg-emerald-900/10';
                      return (
                        <li key={chat.sessionId} className="mb-2">
                          <Button
                            variant={selectedSession === chat.sessionId ? 'default' : 'outline'}
                            className={`relative w-full justify-between text-left h-auto py-3 px-3 transition ${
                              selectedSession === chat.sessionId
                                ? 'ring-2 ring-blue-200'
                                : newChats[chat.sessionId]
                                ? 'ring-2 ring-blue-500 border-blue-500 bg-blue-100 dark:bg-blue-900/40'
                                : urgencyClass
                            }`}
                            aria-pressed={selectedSession === chat.sessionId}
                            onClick={() => acceptChat(chat.sessionId)}
                            disabled={queueView === 'waiting' ? (!presenceOnline || !token || !!assignedAgents[chat.sessionId]) : false}
                          >
                            <div className="flex flex-col items-start gap-1">
                              <span className="text-sm font-medium text-foreground">{chat.visitor?.name || chat.visitor?.email || chat.issueType || `Session ${chat.sessionId.slice(-4)}`}</span>
                              {chat.visitor?.email && (
                                <span className="text-xs text-muted-foreground">{chat.visitor.email}</span>
                              )}
                              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                                {chat.issueType && (
                                  <span className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2 py-0.5 dark:bg-gray-800">
                                    {chat.issueType}
                                  </span>
                                )}
                                <span className="inline-flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  {waitLabel}
                                </span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              {endedChats[chat.sessionId] ? (
                                <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-200">
                                  Ended
                                </span>
                              ) : assignedAgents[chat.sessionId] && assignedAgents[chat.sessionId].id !== selfAgentId ? (
                                <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300">
                                  Assigned: {assignedAgents[chat.sessionId].displayName || assignedAgents[chat.sessionId].name || assignedAgents[chat.sessionId].email}
                                </span>
                              ) : selectedSession === chat.sessionId ? (
                                <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">
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
                            </div>
                            {rowToasts[chat.sessionId] && (
                              <span className="absolute -top-2 right-2 inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-black/80 text-white shadow">
                                {rowToasts[chat.sessionId]}
                              </span>
                            )}
                          </Button>
                        </li>
                      );
                    })}
                    {queueView === 'closed' && filteredQueueChats.map(chat => (
                      <li key={chat.sessionId} className="mb-2">
                        <Button
                          variant="outline"
                          className="w-full justify-between text-left h-auto py-2 px-3 opacity-90"
                          onClick={() => openClosedChat(chat.sessionId)}
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
                            {chat.createdAt && closedAtMap[chat.sessionId] && (
                              <span className="text-xs text-muted-foreground mt-1">
                                {(() => {
                                  const secs = Math.max(0, Math.floor((new Date(closedAtMap[chat.sessionId] as string).getTime() - new Date(chat.createdAt as string).getTime()) / 1000));
                                  const mm = String(Math.floor(secs / 60)).padStart(2, '0');
                                  const ss = String(secs % 60).padStart(2, '0');
                                  return `Total: ${mm}:${ss}`;
                                })()}
                              </span>
                            )}
                          </div>
                          <span className="ml-3 inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-200">
                            Ended
                          </span>
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
                  <span className="flex items-center gap-3">
                    <span>Active Chat</span>
                    {selectedSessionAgent && (
                      <span className="text-xs text-muted-foreground">Assigned to: {selectedSessionAgent.displayName || selectedSessionAgent.name || selectedSessionAgent.email}</span>
                    )}
                  </span>
                  <span className="flex items-center gap-3">
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
                    {selectedSession && selectedSessionClosedAt && (
                      <>
                        <Button variant="outline" size="sm" onClick={() => downloadTranscript('text')}>Download Transcript</Button>
                        <Button variant="outline" size="sm" onClick={emailTranscript}>Email Transcript</Button>
                      </>
                    )}
                    {selectedSession && !selectedSessionClosedAt && (
                      <div className="flex items-center gap-2">
                        <Select value={transferTargetAgentId} onValueChange={setTransferTargetAgentId}>
                          <SelectTrigger className="w-52 h-8">
                            <SelectValue placeholder="Transfer to agent" />
                          </SelectTrigger>
                          <SelectContent>
                            {agents
                              .filter(a => a.id !== selectedSessionAgent?.id)
                              .map(a => (
                                <SelectItem key={a.id} value={a.id}>
                                  {(a.displayName || a.name || a.email) + (a.status ? ` (${a.status})` : '')}
                                </SelectItem>
                              ))}
                          </SelectContent>
                        </Select>
                        <Button variant="outline" size="sm" onClick={transferSession} disabled={!transferTargetAgentId}>Transfer</Button>
                        <Button variant="destructive" size="sm" onClick={endChat}>End Chat</Button>
                      </div>
                    )}
                  </span>
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
                              <div
                                className={`inline-block p-2 rounded-lg ${
                                  msg.role === 'AGENT' ? 'text-white' : 'bg-gray-200 dark:bg-gray-700'
                                }`}
                                style={msg.role === 'AGENT' ? { backgroundColor: PRIMARY_COLOR } : undefined}
                              >
                                <span
                                  className="whitespace-pre-wrap text-sm"
                                  dangerouslySetInnerHTML={{ __html: renderMessageContent(msg.content) }}
                                />
                              </div>
                              <div className={`mt-1 text-[10px] text-muted-foreground ${msg.role === 'AGENT' ? 'text-right' : 'text-left'}`}>{time}</div>
                            </div>
                          </div>
                        );
                      })}
                      {isTyping && <p className="text-sm italic">{isTyping.role === 'USER' ? 'User is typing...' : 'Agent is typing...'}</p>}
                    </ScrollArea>
                    <div className="flex flex-col gap-2">
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
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => setShowEmojiPickerAgent(prev => !prev)}
                        >
                          🙂
                        </Button>
                        <Button onClick={sendMessage}>Send</Button>
                      </div>
                      {showEmojiPickerAgent && (
                        <div className="flex flex-wrap gap-1 rounded-md border border-slate-200 bg-slate-50 p-2 text-lg shadow-sm">
                          {EMOJIS.map((emoji) => (
                            <button
                              key={emoji}
                              type="button"
                              className="px-1 hover:bg-slate-200 rounded"
                              onClick={() => {
                                setMessageInput(prev => prev + emoji);
                                setShowEmojiPickerAgent(false);
                              }}
                            >
                              {emoji}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="mt-3 flex flex-col gap-2">
                      <div className="flex items-center gap-2">
                        <Input
                          placeholder="Email transcript to... (optional)"
                          value={transcriptEmail}
                          onChange={(e) => setTranscriptEmail(e.target.value)}
                        />
                        <Button variant="outline" size="sm" onClick={emailTranscript}>Email Transcript</Button>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button size="sm" variant="ghost" onClick={() => downloadTranscript('text')}>Download .txt</Button>
                        <Button size="sm" variant="ghost" onClick={() => downloadTranscript('html')}>Download .html</Button>
                      </div>
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

        <TabsContent value="offline" className="flex-1">
          <Card className="h-full">
            <CardHeader className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <CardTitle>Offline Messages</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Follow up on visitors who left a message while we were offline.
                </p>
              </div>
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <span>Pending: <span className="font-semibold text-foreground">{offlinePendingCount}</span></span>
                <Button variant="outline" size="sm" onClick={refreshOfflineMessages} disabled={offlineLoading}>
                  {offlineLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent className="h-[65vh]">
              <ScrollArea className="h-full pr-2">
                {offlineMessages.length === 0 && !offlineLoading ? (
                  <div className="flex h-full flex-col items-center justify-center gap-2 text-sm text-muted-foreground">
                    <p>No offline messages yet.</p>
                    <p>When visitors leave messages outside staffed hours, they will appear here.</p>
                  </div>
                ) : (
                  <ul className="space-y-3">
                    {offlineMessages.map((msg) => {
                      const createdLabel = msg.createdAt
                        ? new Date(msg.createdAt).toLocaleString()
                        : 'Unknown time';
                      const handledLabel = msg.offlineHandledAt
                        ? new Date(msg.offlineHandledAt).toLocaleString()
                        : null;
                      return (
                        <li key={msg.id} className="rounded-lg border border-border bg-background/60 p-4 shadow-sm">
                          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                            <div className="space-y-2">
                              <div className="text-sm font-semibold text-foreground">
                                {msg.visitor?.name || msg.visitor?.email || 'Visitor'}
                              </div>
                              {msg.visitor?.email && (
                                <div className="text-xs text-muted-foreground">{msg.visitor.email}</div>
                              )}
                              {msg.issueType && (
                                <div className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                                  {msg.issueType}
                                </div>
                              )}
                              <div className="text-xs text-muted-foreground">Submitted: {createdLabel}</div>
                              {msg.messagePreview && (
                                <div className="rounded bg-slate-100 p-3 text-sm text-slate-700 dark:bg-slate-800 dark:text-slate-100">
                                  {msg.messagePreview}
                                </div>
                              )}
                            </div>
                            <div className="flex flex-col items-start gap-2 text-xs text-muted-foreground md:items-end">
                              {handledLabel ? (
                                <div className="inline-flex items-center gap-2 rounded-full bg-emerald-100 px-3 py-1 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-200">
                                  <span className="h-2 w-2 rounded-full bg-emerald-500" />
                                  Handled {handledLabel}
                                  {msg.offlineHandledBy && (
                                    <span>
                                      by {msg.offlineHandledBy.displayName || msg.offlineHandledBy.name || msg.offlineHandledBy.email}
                                    </span>
                                  )}
                                </div>
                              ) : (
                                <div className="inline-flex items-center gap-2 rounded-full bg-amber-100 px-3 py-1 text-amber-700 dark:bg-amber-900/30 dark:text-amber-200">
                                  <span className="h-2 w-2 rounded-full bg-amber-500" />
                                  Pending follow-up
                                </div>
                              )}
                              <div className="flex items-center gap-2 text-sm">
                                {!handledLabel && (
                                  <Button
                                    size="sm"
                                    onClick={() => markOfflineHandled(msg.id)}
                                    disabled={!!offlineHandleBusy[msg.id]}
                                  >
                                    {offlineHandleBusy[msg.id] && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                    Mark handled
                                  </Button>
                                )}
                                <Button variant="ghost" size="sm" onClick={() => openClosedChat(msg.id)}>
                                  View session
                                </Button>
                              </div>
                            </div>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {isAdmin && (
          <TabsContent value="admin" className="flex-1 space-y-4">
            <Card className="h-full">
              <CardHeader>
                <CardTitle>Admin Tools</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Set or reset passwords, or remotely log agents off. Changes take effect immediately and do not notify agents.
                </p>
              </CardHeader>
              <CardContent className="space-y-4">
                {agents.length === 0 ? (
                  <div className="text-sm text-muted-foreground">No agents found.</div>
                ) : (
                  <div className="space-y-3">
                    {agents.map((agent) => {
                      const isSelf = agent.id === selfAgentId;
                      const isOffline = (agent.status || 'OFFLINE') !== 'ONLINE';
                      return (
                        <div
                          key={agent.id}
                          className="flex flex-col gap-2 rounded-md border border-border bg-background/60 p-3 md:flex-row md:items-center md:justify-between"
                        >
                          <div className="space-y-1 text-sm">
                            <div className="font-medium text-foreground">
                              {agent.displayName || agent.name || agent.email}
                              {isSelf && <span className="ml-1 text-xs text-muted-foreground">(you)</span>}
                            </div>
                            <div className="text-xs text-muted-foreground">{agent.email}</div>
                            {agent.status && (
                              <div className="text-xs text-muted-foreground">Status: {agent.status}</div>
                            )}
                          </div>
                          <div className="flex flex-col gap-2 md:w-80">
                            <div className="flex flex-col gap-2">
                              <Label htmlFor={`admin-password-${agent.id}`} className="text-xs">
                                Set new password (min 8 chars)
                              </Label>
                              <Input
                                id={`admin-password-${agent.id}`}
                                type="password"
                                value={adminPwdMap[agent.id] || ''}
                                onChange={(e) =>
                                  setAdminPwdMap((prev) => ({ ...prev, [agent.id]: e.target.value }))
                                }
                              />
                              <div className="flex flex-wrap gap-2">
                                <Button
                                  size="sm"
                                  onClick={() => setAgentPassword(agent.id)}
                                  disabled={!!adminPwdBusy[agent.id] || !adminPwdMap[agent.id]}
                                >
                                  {adminPwdBusy[agent.id] ? 'Updating...' : 'Set password'}
                                </Button>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => logoffAgent(agent.id)}
                                  disabled={isSelf || isOffline || !!adminLogoutBusy[agent.id]}
                                >
                                  {adminLogoutBusy[agent.id]
                                    ? 'Logging off...'
                                    : isOffline
                                    ? 'Already offline'
                                    : 'Log off'}
                                </Button>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Email Settings</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Configure SMTP settings used for password reset and transcript emails. These settings override environment defaults.
                </p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="mail-host">SMTP host</Label>
                    <Input
                      id="mail-host"
                      placeholder="smtp.office365.com"
                      value={mailHost}
                      onChange={(e) => setMailHost(e.target.value)}
                      disabled={mailLoading || mailSaving}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="mail-port">SMTP port</Label>
                    <Input
                      id="mail-port"
                      type="number"
                      value={mailPort}
                      onChange={(e) => setMailPort(e.target.value)}
                      disabled={mailLoading || mailSaving}
                    />
                  </div>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <div className="space-y-1">
                    <Label htmlFor="mail-secure">Use secure connection (TLS)</Label>
                    <p className="text-xs text-muted-foreground">Enable for SMTPS/strict TLS endpoints.</p>
                  </div>
                  <Switch
                    id="mail-secure"
                    checked={mailSecure}
                    onCheckedChange={(checked) => setMailSecure(checked)}
                    disabled={mailLoading || mailSaving}
                  />
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="mail-user">SMTP user</Label>
                    <Input
                      id="mail-user"
                      placeholder="support@yourdomain.com"
                      value={mailUser}
                      onChange={(e) => setMailUser(e.target.value)}
                      disabled={mailLoading || mailSaving}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="mail-password">SMTP password</Label>
                    <Input
                      id="mail-password"
                      type="password"
                      placeholder="Leave blank to keep existing"
                      value={mailPassword}
                      onChange={(e) => setMailPassword(e.target.value)}
                      disabled={mailLoading || mailSaving}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="mail-from">From address</Label>
                  <Input
                    id="mail-from"
                    placeholder="Support <support@yourdomain.com>"
                    value={mailFrom}
                    onChange={(e) => setMailFrom(e.target.value)}
                    disabled={mailLoading || mailSaving}
                  />
                </div>
                <div className="flex items-center justify-end gap-3 pt-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={loadMailSettings}
                    disabled={mailLoading || mailSaving}
                  >
                    {mailLoading ? 'Reloading...' : 'Reload from server'}
                  </Button>
                  <Button size="sm" onClick={saveMailSettings} disabled={mailSaving || mailLoading}>
                    {mailSaving ? 'Saving...' : 'Save settings'}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
