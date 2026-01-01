"use client";
import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import type { ComponentType } from 'react';
import { useRouter } from 'next/navigation';
import { BACKEND_URL, getAgentSocket } from '@/lib/agentSocket';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Avatar, AvatarImage, AvatarFallback } from '@/components/ui/avatar';
import { Separator } from '@/components/ui/separator';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import {
  Search,
  Filter,
  Clock,
  Users,
  Inbox,
  Sparkles,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Info,
  Loader2,
  LayoutDashboard,
  Mail,
  Layers,
  Settings,
  Zap,
  Shield,
  Lock,
  KeyRound,
} from 'lucide-react';

const PRIMARY_COLOR = '#024F9E'; // Enagic water-brand blue
const MIN_AGENT_PASSWORD_LENGTH = 8;
const ROLE_LABEL: Record<AgentRole, string> = {
  ADMIN: 'Admin',
  MANAGER: 'Manager',
  AGENT: 'Agent',
};

type ShortcutItem = { id: string; title: string; text: string; createdAt: number };

const DEFAULT_SHORTCUTS: ShortcutItem[] = [
  {
    id: 'greeting',
    title: 'Greeting',
    text: "Hi! Thanks for reaching out — how can I help today?",
    createdAt: 0,
  },
  {
    id: 'handoff',
    title: 'Ask for details',
    text: "To help quickly, can you share: 1) what you're trying to do, 2) what you expected, and 3) what happened instead?",
    createdAt: 0,
  },
  {
    id: 'closing',
    title: 'Closing',
    text: "Happy to help. If anything else comes up, just message us here anytime.",
    createdAt: 0,
  },
];

const MAIL_SECRET_HEADER = 'x-mail-secret-token';

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

type AgentRole = 'ADMIN' | 'MANAGER' | 'AGENT';
type InboxSessionListItem = {
  id: string;
  status: 'OPEN' | 'CLOSED';
  issueType?: string | null;
  closedReason?: string | null;
  closedAt?: string | null;
  offlineHandledAt?: string | null;
  createdAt: string;
  updatedAt: string;
  visitor?: { id: string; name?: string | null; email?: string | null } | null;
  agent?: { id: string; name?: string | null; email?: string | null; displayName?: string | null } | null;
  messages?: Array<{ content: string; role: 'USER' | 'AGENT'; createdAt: string }>;
};

type DepartmentAgent = {
  id: string;
  email: string;
  name?: string | null;
  displayName?: string | null;
  status?: string | null;
  available?: boolean;
};

type DepartmentApi = {
  id: string;
  name: string;
  agentDepartments?: Array<{ id: string; available: boolean; agent: DepartmentAgent }>;
};

type AdminSection = 'departments' | 'agents' | 'email' | 'upcoming';
type ActiveView =
  | 'workspace'
  | 'inbox'
  | 'shortcuts'
  | 'automations'
  | 'csat'
  | 'departments'
  | 'settings'
  | 'admin';

type PrimaryNavItem = {
  id: ActiveView;
  label: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
  metric?: number;
  accent: string;
  disabled: boolean;
};

const socket = getAgentSocket();

type AgentSummary = {
  id: string;
  email: string;
  name?: string;
  displayName?: string;
  status?: string;
  phone?: string;
  role?: AgentRole;
};

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
  const [activeTab, setActiveTab] = useState<'chats' | 'offline' | 'profile'>('chats');
  const [selfAgentId, setSelfAgentId] = useState<string>('');
  const [availableChats, setAvailableChats] = useState<ChatEvent[]>([]);
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [messages, setMessages] = useState<MessageEvent[]>([]);
  const [messageInput, setMessageInput] = useState('');
  const [isTyping, setIsTyping] = useState<{ role: 'USER' | 'AGENT' } | null>(null);
  const typingTimerRef = useRef<number | null>(null);
  const toastTimerRef = useRef<number | null>(null);
  const didHydrateRef = useRef(false);
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
  const [, setDurationTick] = useState<number>(0);
  const [selectedSessionCreatedAt, setSelectedSessionCreatedAt] = useState<string | undefined>(undefined);
  const [selectedSessionClosedAt, setSelectedSessionClosedAt] = useState<string | undefined>(undefined);
  const [selectedSessionAgent, setSelectedSessionAgent] = useState<{ id: string; name?: string; displayName?: string; email?: string } | null>(null);
  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [transferTargetAgentId, setTransferTargetAgentId] = useState<string>('');
  const [selfRole, setSelfRole] = useState<AgentRole>('AGENT');
  const isAdmin = selfRole === 'ADMIN';
  const isManager = selfRole === 'MANAGER';
  const [adminPwdMap, setAdminPwdMap] = useState<Record<string, string>>({});
  const [adminPwdBusy, setAdminPwdBusy] = useState<Record<string, boolean>>({});
  const [adminLogoutBusy, setAdminLogoutBusy] = useState<Record<string, boolean>>({});
  const [adminDeleteBusy, setAdminDeleteBusy] = useState<Record<string, boolean>>({});
  const [newAgentName, setNewAgentName] = useState<string>('');
  const [newAgentDisplayName, setNewAgentDisplayName] = useState<string>('');
  const [newAgentEmail, setNewAgentEmail] = useState<string>('');
  const [newAgentPhone, setNewAgentPhone] = useState<string>('');
  const [newAgentPassword, setNewAgentPassword] = useState<string>('');
  const [newAgentRole, setNewAgentRole] = useState<AgentRole>('AGENT');
  const [newAgentBusy, setNewAgentBusy] = useState<boolean>(false);
  const [mailHost, setMailHost] = useState<string>('');
  const [mailPort, setMailPort] = useState<string>('587');
  const [mailSecure, setMailSecure] = useState<boolean>(false);
  const [mailUser, setMailUser] = useState<string>('');
  const [mailTranscriptIntro, setMailTranscriptIntro] = useState<string>('');
  const [mailPassword, setMailPassword] = useState<string>('');
  const [mailFrom, setMailFrom] = useState<string>('');
  const [mailLoading, setMailLoading] = useState<boolean>(false);
  const [mailSaving, setMailSaving] = useState<boolean>(false);
  const [mailLocked, setMailLocked] = useState<boolean>(false);
  const [mailRequiresSecret, setMailRequiresSecret] = useState<boolean>(false);
  const [mailSecretToken, setMailSecretToken] = useState<string | null>(null);
  const [showMailUnlockModal, setShowMailUnlockModal] = useState<boolean>(false);
  const [mailUnlocking, setMailUnlocking] = useState<boolean>(false);
  const [mailUnlockError, setMailUnlockError] = useState<string | null>(null);
  const [mailUnlockSecret, setMailUnlockSecret] = useState<string>('');
  const [showMailSecretModal, setShowMailSecretModal] = useState<boolean>(false);
  const [mailSecretSaving, setMailSecretSaving] = useState<boolean>(false);
  const [mailSecretNew, setMailSecretNew] = useState<string>('');
  const [mailSecretCurrent, setMailSecretCurrent] = useState<string>('');
  const [showEmojiPickerAgent, setShowEmojiPickerAgent] = useState<boolean>(false);
  const [chatFilter, setChatFilter] = useState<'all' | 'mine' | 'unassigned' | 'new'>('all');
  const [chatSearch, setChatSearch] = useState<string>('');
  const [chatSort, setChatSort] = useState<'wait' | 'recent'>('wait');
  const [queueView, setQueueView] = useState<'waiting' | 'active' | 'closed'>('waiting');
  const [departments, setDepartments] = useState<DepartmentApi[]>([]);
  const [assignedDepartments, setAssignedDepartments] = useState<Record<string, boolean>>({});
  const [departmentBusyId, setDepartmentBusyId] = useState<string | null>(null);
  const [departmentsLoading, setDepartmentsLoading] = useState<boolean>(false);
  const [newDepartmentName, setNewDepartmentName] = useState<string>('');
  const [createDepartmentBusy, setCreateDepartmentBusy] = useState<boolean>(false);
  const [departmentAssignSelection, setDepartmentAssignSelection] = useState<Record<string, string>>({});
  const [departmentAdminBusyKey, setDepartmentAdminBusyKey] = useState<string | null>(null);
  const [departmentEditName, setDepartmentEditName] = useState<Record<string, string>>({});
  const [issueTypeFilter] = useState<string>('all');
  const [activeView, setActiveView] = useState<ActiveView>('workspace');
  const [adminSection, setAdminSection] = useState<'departments' | 'agents' | 'email' | 'upcoming'>('departments');
  const [shortcuts, setShortcuts] = useState<ShortcutItem[]>(DEFAULT_SHORTCUTS);
  const [shortcutSearch, setShortcutSearch] = useState<string>('');
  const [shortcutTitle, setShortcutTitle] = useState<string>('');
  const [shortcutText, setShortcutText] = useState<string>('');
  const [toastNotification, setToastNotification] = useState<{ message: string; tone: 'success' | 'error' | 'info' } | null>(null);
  const [inboxSessions, setInboxSessions] = useState<InboxSessionListItem[]>([]);
  const [inboxLoading, setInboxLoading] = useState<boolean>(false);
  const [inboxStatus, setInboxStatus] = useState<'all' | 'open' | 'closed'>('open');
  const [inboxAssigned, setInboxAssigned] = useState<'all' | 'me' | 'unassigned' | 'assigned'>('unassigned');
  const [inboxSearch, setInboxSearch] = useState<string>('');
  const [takeNextBusy, setTakeNextBusy] = useState<boolean>(false);

  const showToast = useCallback(
    (message: string, tone: 'success' | 'error' | 'info' = 'info', duration = 2500) => {
      setToastNotification({ message, tone });
      if (toastTimerRef.current) {
        window.clearTimeout(toastTimerRef.current);
      }
      toastTimerRef.current = window.setTimeout(() => {
        setToastNotification(null);
      }, duration) as unknown as number;
    },
    []
  );

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const saved = window.sessionStorage.getItem('mail_secret_token');
    if (saved) setMailSecretToken(saved);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (mailSecretToken) {
      window.sessionStorage.setItem('mail_secret_token', mailSecretToken);
    } else {
      window.sessionStorage.removeItem('mail_secret_token');
    }
  }, [mailSecretToken]);

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

  const deleteAgent = async (agentId: string) => {
    if (!token) return;
    if (agentId === selfAgentId) {
      setStatus('You cannot delete your own account');
      return;
    }
    if (!window.confirm('Delete this agent? This cannot be undone.')) {
      return;
    }
    setAdminDeleteBusy((prev) => ({ ...prev, [agentId]: true }));
    setStatus('Deleting agent...');
    try {
      const res = await fetch(`${BACKEND_URL}/admin/agents/${agentId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(data?.error ? `Delete failed: ${data.error}` : 'Delete failed');
        return;
      }
      setAgents((prev) => prev.filter((agent) => agent.id !== agentId));
      setStatus('Agent deleted');
    } catch {
      setStatus('Delete failed');
    } finally {
      setAdminDeleteBusy((prev) => {
        const next = { ...prev };
        delete next[agentId];
        return next;
      });
    }
  };

  const updateAgentRole = async (agentId: string, newRole: AgentRole) => {
    if (!token) return;
    setStatus('Updating role...');
    try {
      const res = await fetch(`${BACKEND_URL}/agents/${agentId}/role`, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(data?.error ? `Role update failed: ${data.error}` : 'Role update failed');
        return;
      }
      setStatus('Role updated');
    } catch {
      setStatus('Role update failed');
    }
  };

  const loadMailSettings = useCallback(async (options?: { secretToken?: string | null }) => {
    if (!token || !isAdmin) return;
    setMailLoading(true);
    setMailLocked(false);
    try {
      const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
      const effectiveSecret = options?.secretToken ?? mailSecretToken;
      if (effectiveSecret) headers[MAIL_SECRET_HEADER] = effectiveSecret;
      const res = await fetch(`${BACKEND_URL}/admin/mail-settings`, { headers });
      if (res.status === 423) {
        setMailLocked(true);
        setMailRequiresSecret(true);
        setShowMailUnlockModal(true);
        return;
      }
      if (res.status === 401 && effectiveSecret) {
        setMailSecretToken(null);
        setMailLocked(true);
        setShowMailUnlockModal(true);
        return;
      }
      if (!res.ok) {
        setStatus('Failed to load mail settings');
        return;
      }
      const data = await res.json();
      setMailRequiresSecret(Boolean(data.requiresSecret));
      if (effectiveSecret && !mailSecretToken) {
        setMailSecretToken(effectiveSecret);
      }
      setMailHost((data.host as string) || '');
      setMailPort(String(data.port ?? '587'));
      setMailSecure(Boolean(data.secure));
      setMailUser((data.user as string) || '');
      setMailFrom((data.fromAddress as string) || '');
      setMailTranscriptIntro((data.transcriptIntro as string) || '');
    } catch {
      setStatus('Failed to load mail settings');
    } finally {
      setMailLoading(false);
    }
  }, [token, isAdmin, mailSecretToken]);

  const unlockMailSettings = async () => {
    if (!token || !mailUnlockSecret.trim()) {
      setMailUnlockError('Integration password is required');
      return;
    }
    setMailUnlocking(true);
    setMailUnlockError(null);
    try {
      const res = await fetch(`${BACKEND_URL}/admin/mail-settings/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ secret: mailUnlockSecret.trim() }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setMailUnlockError(data?.error || 'Invalid integration password');
        return;
      }
      const secretToken = (data?.token as string) || null;
      setMailSecretToken(secretToken);
      setShowMailUnlockModal(false);
      setMailUnlockSecret('');
      await loadMailSettings({ secretToken });
      setStatus('Mail settings unlocked');
    } catch {
      setMailUnlockError('Unable to unlock settings, please try again');
    } finally {
      setMailUnlocking(false);
    }
  };

  const saveIntegrationSecret = async () => {
    if (!token) return;
    if (mailSecretNew.trim().length < 8) {
      setStatus('Integration password must be at least 8 characters');
      return;
    }
    setMailSecretSaving(true);
    setStatus('Saving integration password...');
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      };
      if (mailSecretToken) headers[MAIL_SECRET_HEADER] = mailSecretToken;
      const res = await fetch(`${BACKEND_URL}/admin/mail-settings/secret`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({
          secret: mailSecretNew.trim(),
          currentSecret: mailSecretCurrent.trim() ? mailSecretCurrent.trim() : undefined,
        }),
      });
      const data = await res.json().catch(() => null);
      if (res.status === 423) {
        setMailLocked(true);
        setShowMailUnlockModal(true);
        return;
      }
      if (res.status === 401 && mailSecretToken) {
        setMailSecretToken(null);
        setMailLocked(true);
        setShowMailUnlockModal(true);
        return;
      }
      if (!res.ok) {
        setStatus(data?.error ? `Failed to save integration password: ${data.error}` : 'Failed to save integration password');
        return;
      }
      setMailRequiresSecret(true);
      setShowMailSecretModal(false);
      setMailSecretCurrent('');
      setMailSecretNew('');
      setStatus('Integration password saved');
    } catch {
      setStatus('Failed to save integration password');
    } finally {
      setMailSecretSaving(false);
    }
  };

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
        transcriptIntro: mailTranscriptIntro || null,
      };
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      };
      if (mailSecretToken) headers[MAIL_SECRET_HEADER] = mailSecretToken;
      const res = await fetch(`${BACKEND_URL}/admin/mail-settings`, {
        method: 'PUT',
        headers,
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      if (res.status === 423) {
        setMailLocked(true);
        setMailRequiresSecret(true);
        setShowMailUnlockModal(true);
        return;
      }
      if (res.status === 401 && mailSecretToken) {
        setMailSecretToken(null);
        setMailLocked(true);
        setShowMailUnlockModal(true);
        return;
      }
      if (!res.ok) {
        setStatus(data?.error ? `Failed to save mail settings: ${data.error}` : 'Failed to save mail settings');
        return;
      }
      setMailRequiresSecret(Boolean(data?.requiresSecret));
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

  const longestWaitMinutes = useMemo(() => {
    void listTick;
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
    void listTick;

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
  }, [openChats, assignedAgents, chatFilter, chatSearch, chatSort, selfAgentId, newChats, issueTypeFilter, listTick]);

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

  type CsatTrendPoint = { date: string; average: number | null; responses: number };
  type CsatAnalytics = {
    average: number | null;
    total: number;
    positive: number;
    distribution: Record<number, number>;
    trend: CsatTrendPoint[];
    period: { days: number; responses: number };
    agentChatCounts: { agentId: string; name: string; chatsHandled: number }[];
    agentWindowDays: number;
    averageWaitMinutes: number | null;
    averageQueueSize: number | null;
  };

  const [csatStats, setCsatStats] = useState<CsatAnalytics | null>(null);
  const [csatRefreshing, setCsatRefreshing] = useState(false);
  const csatScore = useMemo(() => {
    if (!csatStats || csatStats.average === null || csatStats.average === undefined) return null;
    const percent = (csatStats.average / 5) * 100;
    return Math.min(100, Math.max(0, Math.round(percent * 10) / 10));
  }, [csatStats]);
  const csatDistribution = useMemo(() => csatStats?.distribution ?? null, [csatStats]);
  const csatTrend = useMemo(() => csatStats?.trend ?? [], [csatStats]);
  const csatTrendMaxResponses = useMemo(() => {
    if (!csatTrend.length) return 0;
    return Math.max(...csatTrend.map((point) => point.responses));
  }, [csatTrend]);
  const agentChatCounts = useMemo(() => csatStats?.agentChatCounts ?? [], [csatStats]);
  const positiveRate = useMemo(() => {
    if (!csatStats || !csatStats.total) return null;
    return Math.round((csatStats.positive / csatStats.total) * 100);
  }, [csatStats]);
  const csatDistributionEntries = useMemo(() => {
    const entries: Array<{ rating: number; value: number; percent: number }> = [];
    if (!csatDistribution || !csatStats?.total) return entries;
    for (let rating = 5; rating >= 1; rating -= 1) {
      const value = csatDistribution[rating] ?? 0;
      const percent = csatStats.total ? Math.round((value / csatStats.total) * 100) : 0;
      entries.push({ rating, value, percent });
    }
    return entries;
  }, [csatDistribution, csatStats]);
  const csatPeriodDays = csatStats?.period?.days ?? 14;
  const csatPeriodResponses = csatStats?.period?.responses ?? csatStats?.total ?? 0;
  const displayedAgentChatCounts = useMemo(() => agentChatCounts.slice(0, 5), [agentChatCounts]);
  const averageWaitLabel = useMemo(() => {
    if (csatStats?.averageWaitMinutes === null || csatStats?.averageWaitMinutes === undefined) return '—';
    const minutes = csatStats.averageWaitMinutes;
    if (minutes < 1) {
      return `${Math.round(minutes * 60)} sec`;
    }
    if (minutes >= 60) {
      const hours = minutes / 60;
      return `${hours.toFixed(1)} hr`;
    }
    return `${minutes.toFixed(1)} min`;
  }, [csatStats]);
  const averageQueueLabel = useMemo(() => {
    if (csatStats?.averageQueueSize === null || csatStats?.averageQueueSize === undefined) return '—';
    return csatStats.averageQueueSize.toFixed(1);
  }, [csatStats]);
  const filteredQueueCount = filteredQueueChats.length;
  const onlineAgents = useMemo(() => {
    return agents.filter((agent) => (agent.status ?? '').toUpperCase() === 'ONLINE');
  }, [agents]);

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

  const longestWaitSummary = openChatCount > 0 ? `${longestWaitMinutes} min` : '—';
  const agentIdentityLabel = agentDisplayName || name || 'Agent';

  const primaryNavItems = useMemo<PrimaryNavItem[]>(() => {
    const coreItems: PrimaryNavItem[] = [
      {
        id: 'workspace' as const,
        label: 'Live Workspace',
        description: 'Queues & chats',
        icon: LayoutDashboard,
        metric: openChatCount,
        accent: 'from-sky-500/15 via-sky-500/10 to-transparent',
        disabled: false,
      },
      {
        id: 'inbox' as const,
        label: 'Visitor Inbox',
        description: 'Follow ups & CRM',
        icon: Mail,
        metric: offlinePendingCount,
        accent: 'from-rose-500/15 via-rose-500/10 to-transparent',
        disabled: false,
      },
      {
        id: 'shortcuts' as const,
        label: 'Shortcuts',
        description: 'Canned replies',
        icon: Zap,
        metric: shortcuts.length,
        accent: 'from-indigo-500/15 via-indigo-500/10 to-transparent',
        disabled: false,
      },
    ];

    if (!isAdmin) return coreItems;

    const adminItems: PrimaryNavItem[] = [
      ...coreItems,
      {
        id: 'automations' as const,
        label: 'Automations',
        description: 'Playbooks & flows',
        icon: Layers,
        metric: 0,
        accent: 'from-amber-500/15 via-amber-500/10 to-transparent',
        disabled: false,
      },
      {
        id: 'csat' as const,
        label: 'CSAT',
        description: 'Customer satisfaction',
        icon: Sparkles,
        metric: csatScore === null ? 0 : Math.round(csatScore),
        accent: 'from-sky-500/15 via-sky-500/10 to-transparent',
        disabled: false,
      },
      {
        id: 'departments' as const,
        label: 'Departments',
        description: 'Routing & assignment',
        icon: Users,
        metric: departments.length,
        accent: 'from-emerald-500/15 via-emerald-500/10 to-transparent',
        disabled: false,
      },
      {
        id: 'settings' as const,
        label: 'Org Settings',
        description: 'Branding & teams',
        icon: Settings,
        metric: undefined,
        accent: 'from-purple-500/15 via-purple-500/10 to-transparent',
        disabled: false,
      },
    ];

    if (isAdmin) {
      adminItems.push({
        id: 'admin' as const,
        label: 'Admin Tools',
        description: 'Agents & email',
        icon: Shield,
        metric: agents.length,
        accent: 'from-slate-900/15 via-slate-800/10 to-transparent',
        disabled: false,
      });
    }

    return adminItems;
  }, [openChatCount, offlinePendingCount, isAdmin, shortcuts.length, departments.length, csatScore]);

  const adminNavItems = useMemo(
    () => [
      {
        id: 'departments' as AdminSection,
        label: 'Departments',
        description: 'Routing & assignment',
        metric: departments.length,
      },
      {
        id: 'agents' as AdminSection,
        label: 'Agents',
        description: 'Passwords & availability',
        metric: agents.length,
      },
      {
        id: 'email' as AdminSection,
        label: 'Email settings',
        description: 'SMTP & alerts',
        metric: mailHost ? 1 : 0,
      },
      {
        id: 'upcoming' as AdminSection,
        label: 'Upcoming tools',
        description: 'More admin utilities',
        metric: undefined,
      },
    ],
    [departments.length, agents.length, mailHost]
  );

  useEffect(() => {
    if (
      !isAdmin &&
      (activeView === 'departments' || activeView === 'settings' || activeView === 'automations' || activeView === 'csat' || activeView === 'admin')
    ) {
      setActiveView('workspace');
    }
  }, [isAdmin, activeView]);

  useEffect(() => {
    if (activeView !== 'admin' && adminSection !== 'departments') {
      setAdminSection('departments');
    }
  }, [activeView, adminSection]);

  const refreshCsat = useCallback(async (): Promise<boolean> => {
    if (!token) return false;
    try {
      const res = await fetch(`${BACKEND_URL}/analytics/csat`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const payload = await res.json().catch(() => null);
      if (!res.ok || !payload) {
        setCsatStats(null);
        return false;
      }
      const emptyDistribution: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
      setCsatStats({
        average: payload.average ?? null,
        total: payload.total ?? 0,
        positive: payload.positive ?? 0,
        distribution: payload.distribution ?? emptyDistribution,
        trend: Array.isArray(payload.trend) ? payload.trend : [],
        period: payload.period ?? { days: 14, responses: 0 },
        agentChatCounts: Array.isArray(payload.agentChatCounts) ? payload.agentChatCounts : [],
        agentWindowDays: payload.agentWindowDays ?? 30,
        averageWaitMinutes: payload.averageWaitMinutes ?? null,
        averageQueueSize: payload.averageQueueSize ?? null,
      });
      return true;
    } catch (err) {
      console.error('refresh csat error', err);
      setCsatStats(null);
      return false;
    }
  }, [token]);

  const handleCsatRefresh = useCallback(async () => {
    if (!token || csatRefreshing) return;
    setCsatRefreshing(true);
    const ok = await refreshCsat();
    if (!ok) {
      setStatus('Failed to refresh CSAT data');
    }
    setCsatRefreshing(false);
  }, [token, refreshCsat, csatRefreshing, setStatus]);

  const StatusIcon = statusBadgeMeta.icon;
  const PresenceIcon = presenceBadgeMeta.icon;

  const refreshOfflineMessages = useCallback(async (tokenOverride?: string) => {
    const authToken = tokenOverride || token;
    if (!authToken) return;
    setOfflineLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/offline/messages`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) {
        setOfflineMessages([]);
        setStatus('Failed to load offline messages');
        return;
      }
      const payload = (await res.json().catch(() => [])) as unknown;
      const items: OfflineMessageApiItem[] = Array.isArray(payload) ? (payload as OfflineMessageApiItem[]) : [];
      const mapped: OfflineMessage[] = items.map((item) => ({
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
    } catch {
      setOfflineMessages([]);
      setStatus('Failed to load offline messages');
    } finally {
      setOfflineLoading(false);
    }
  }, [token]);

  const loadDepartments = useCallback(async () => {
    if (!token) return;
    setDepartmentsLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/departments`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const rawBody = await res.text().catch(() => '');
        console.warn('load departments failed', res.status, rawBody);
        let detail: string | undefined;
        try {
          const parsed = JSON.parse(rawBody) as { error?: string };
          if (parsed?.error) detail = parsed.error;
        } catch {
          if (rawBody) detail = rawBody;
        }
        setDepartments([]);
        setStatus(detail ? `Failed to load departments: ${detail}` : `Failed to load departments (${res.status})`);
        return;
      }
      const data = await res.json();
      if (Array.isArray(data)) {
        setDepartments(data);
      }
    } catch (err) {
      console.error('load departments error', err);
      setDepartments([]);
      setStatus('Failed to load departments');
    } finally {
      setDepartmentsLoading(false);
    }
  }, [token]);

  const createDepartment = useCallback(async () => {
    if (!token) return;
    const name = newDepartmentName.trim();
    if (!name) return;
    setCreateDepartmentBusy(true);
    try {
      const res = await fetch(`${BACKEND_URL}/departments`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name }),
      });
      const payload = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(payload?.error ? `Failed to create department: ${payload.error}` : 'Failed to create department');
        return;
      }
      setNewDepartmentName('');
      await loadDepartments();
    } catch (err) {
      console.error('create department error', err);
      setStatus('Failed to create department');
    } finally {
      setCreateDepartmentBusy(false);
    }
  }, [token, newDepartmentName, loadDepartments]);

  const assignAgentToDepartment = useCallback(
    async (departmentId: string, agentId: string) => {
      if (!token) return;
      if (!departmentId || !agentId) return;
      const key = `${departmentId}:assign`;
      setDepartmentAdminBusyKey(key);
      try {
        const res = await fetch(`${BACKEND_URL}/departments/${departmentId}/agents`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ agentId }),
        });
        const payload = await res.json().catch(() => null);
        if (!res.ok) {
          setStatus(payload?.error ? `Failed to assign agent: ${payload.error}` : 'Failed to assign agent');
          return;
        }
        setDepartmentAssignSelection((prev) => {
          const next = { ...prev };
          delete next[departmentId];
          return next;
        });
        await loadDepartments();
      } catch (err) {
        console.error('assign agent to department error', err);
        setStatus('Failed to assign agent');
      } finally {
        setDepartmentAdminBusyKey(null);
      }
    },
    [token, loadDepartments]
  );

  const renameDepartment = useCallback(
    async (departmentId: string) => {
      if (!token) return;
      const name = (departmentEditName[departmentId] ?? '').trim();
      if (!name) return;
      const key = `${departmentId}:rename`;
      setDepartmentAdminBusyKey(key);
      try {
        const res = await fetch(`${BACKEND_URL}/departments/${departmentId}`, {
          method: 'PUT',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ name }),
        });
        const payload = await res.json().catch(() => null);
        if (!res.ok) {
          setStatus(payload?.error ? `Failed to rename department: ${payload.error}` : 'Failed to rename department');
          return;
        }
        setDepartmentEditName((prev) => {
          const next = { ...prev };
          delete next[departmentId];
          return next;
        });
        await loadDepartments();
      } catch (err) {
        console.error('rename department error', err);
        setStatus('Failed to rename department');
      } finally {
        setDepartmentAdminBusyKey(null);
      }
    },
    [token, departmentEditName, loadDepartments]
  );

  const deleteDepartment = useCallback(
    async (departmentId: string) => {
      if (!token) return;
      const confirmed = typeof window !== 'undefined' ? window.confirm('Delete this department?') : false;
      if (!confirmed) return;
      const key = `${departmentId}:delete`;
      setDepartmentAdminBusyKey(key);
      try {
        const res = await fetch(`${BACKEND_URL}/departments/${departmentId}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` },
        });
        const payload = await res.json().catch(() => null);
        if (!res.ok) {
          setStatus(payload?.error ? `Failed to delete department: ${payload.error}` : 'Failed to delete department');
          return;
        }
        setDepartmentEditName((prev) => {
          const next = { ...prev };
          delete next[departmentId];
          return next;
        });
        await loadDepartments();
      } catch (err) {
        console.error('delete department error', err);
        setStatus('Failed to delete department');
      } finally {
        setDepartmentAdminBusyKey(null);
      }
    },
    [token, loadDepartments]
  );

  const unassignAgentFromDepartment = useCallback(
    async (departmentId: string, agentId: string) => {
      if (!token) return;
      if (!departmentId || !agentId) return;
      const key = `${departmentId}:${agentId}:remove`;
      setDepartmentAdminBusyKey(key);
      try {
        const res = await fetch(`${BACKEND_URL}/departments/${departmentId}/agents/${agentId}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` },
        });
        const payload = await res.json().catch(() => null);
        if (!res.ok) {
          setStatus(payload?.error ? `Failed to unassign agent: ${payload.error}` : 'Failed to unassign agent');
          return;
        }
        await loadDepartments();
      } catch (err) {
        console.error('unassign agent from department error', err);
        setStatus('Failed to unassign agent');
      } finally {
        setDepartmentAdminBusyKey(null);
      }
    },
    [token, loadDepartments]
  );

  const refreshAssignedDepartments = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch(`${BACKEND_URL}/me/departments`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        console.warn('refresh assigned departments failed', res.status);
        setAssignedDepartments({});
        return;
      }
      const data = await res.json();
      if (Array.isArray(data)) {
        const mapped = data.reduce<Record<string, boolean>>((acc, item) => {
          if (item && typeof item.id === 'string') {
            acc[item.id] = Boolean(item.available);
          }
          return acc;
        }, {});
        setAssignedDepartments(mapped);
      } else {
        setAssignedDepartments({});
      }
    } catch (err) {
      console.error('refresh assigned departments error', err);
      setAssignedDepartments({});
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
        const payload = await res.json().catch(() => null);
        if (!res.ok) {
          const message =
            typeof payload?.error === 'string' && payload.error.trim().length > 0
              ? payload.error
              : 'Department request failed';
          setStatus(message);
          return;
        }
        setAssignedDepartments((prev) => ({
          ...prev,
          [departmentId]: join,
        }));
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
    refreshAssignedDepartments();
  }, [loadDepartments, refreshAssignedDepartments]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      const raw = window.localStorage.getItem('agent_shortcuts');
      if (!raw) return;
      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed)) return;
      const next: ShortcutItem[] = parsed
        .filter((item): item is ShortcutItem =>
          Boolean(item && typeof item === 'object' && 'id' in item && 'title' in item && 'text' in item)
        )
        .map((item) => ({
          id: String(item.id),
          title: String(item.title),
          text: String(item.text),
          createdAt: typeof item.createdAt === 'number' ? item.createdAt : Date.now(),
        }));
      if (next.length > 0) setShortcuts(next);
    } catch {}
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem('agent_shortcuts', JSON.stringify(shortcuts));
    } catch {}
  }, [shortcuts]);

  const filteredShortcuts = useMemo(() => {
    const q = shortcutSearch.trim().toLowerCase();
    if (!q) return shortcuts;
    return shortcuts.filter((s) => {
      const composite = `${s.title} ${s.text}`.toLowerCase();
      return composite.includes(q);
    });
  }, [shortcuts, shortcutSearch]);

  const applyShortcut = useCallback((text: string) => {
    setMessageInput((prev) => (prev ? `${prev}\n\n${text}` : text));
    setActiveView('workspace');
    setActiveTab('chats');
  }, []);

  const copyShortcut = useCallback(async (text: string) => {
    const fallbackCopy = () => {
      try {
        if (typeof document === 'undefined') return false;
        const el = document.createElement('textarea');
        el.value = text;
        el.setAttribute('readonly', '');
        el.style.position = 'fixed';
        el.style.left = '-9999px';
        el.style.top = '0';
        document.body.appendChild(el);
        el.select();
        el.setSelectionRange(0, el.value.length);
        const ok = document.execCommand('copy');
        document.body.removeChild(el);
        return ok;
      } catch {
        return false;
      }
    };

    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(text);
        setStatus('Copied shortcut');
        showToast('Copied shortcut', 'success');
        return;
      }
    } catch {
      // fall through to fallback
    }

    const ok = fallbackCopy();
    setStatus(ok ? 'Copied shortcut' : 'Copy failed');
    showToast(ok ? 'Copied shortcut' : 'Copy failed', ok ? 'success' : 'error');
  }, [showToast]);

  const addShortcut = useCallback(() => {
    const title = shortcutTitle.trim();
    const text = shortcutText.trim();
    if (!title || !text) return;
    const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    setShortcuts((prev) => [{ id, title, text, createdAt: Date.now() }, ...prev]);
    setShortcutTitle('');
    setShortcutText('');
    setStatus('Shortcut added');
    showToast('Shortcut added', 'success');
  }, [shortcutText, shortcutTitle, showToast]);

  const deleteShortcut = useCallback((id: string) => {
    setShortcuts((prev) => prev.filter((s) => s.id !== id));
    setStatus('Shortcut removed');
    showToast('Shortcut removed', 'info');
  }, [showToast]);

  const createAgent = async () => {
    if (!token || !isAdmin) return;
    const name = newAgentName.trim();
    const email = newAgentEmail.trim();
    const password = newAgentPassword.trim();
    if (!name || !email || password.length < MIN_AGENT_PASSWORD_LENGTH) {
      setStatus(`Name, email, and password (>=${MIN_AGENT_PASSWORD_LENGTH} chars) are required`);
      showToast(`Fill name, email, password ≥ ${MIN_AGENT_PASSWORD_LENGTH} chars`, 'error');
      return;
    }
    setNewAgentBusy(true);
    setStatus('Creating agent...');
    try {
      const res = await fetch(`${BACKEND_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          name,
          displayName: newAgentDisplayName.trim() || undefined,
          email,
          phone: newAgentPhone.trim() || undefined,
          password,
          role: newAgentRole,
        }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.agent) {
        const detail = data?.error || 'Failed to create agent';
        setStatus(detail);
        showToast(detail, 'error');
        return;
      }
      setAgents((prev) => [data.agent, ...prev]);
      setStatus('Agent created');
      showToast('Agent created', 'success');
      setNewAgentName('');
      setNewAgentDisplayName('');
      setNewAgentEmail('');
      setNewAgentPhone('');
      setNewAgentPassword('');
      setNewAgentRole('AGENT');
    } catch {
      setStatus('Failed to create agent');
      showToast('Failed to create agent', 'error');
    } finally {
      setNewAgentBusy(false);
    }
  };

  const loadInbox = useCallback(async () => {
    if (!token) return;
    setInboxLoading(true);
    try {
      const qs = new URLSearchParams();
      if (inboxStatus === 'open') qs.set('status', 'OPEN');
      if (inboxStatus === 'closed') qs.set('status', 'CLOSED');
      if (inboxAssigned !== 'all') qs.set('assigned', inboxAssigned);
      if (inboxSearch.trim()) qs.set('q', inboxSearch.trim());
      qs.set('take', '75');

      const res = await fetch(`${BACKEND_URL}/sessions?${qs.toString()}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const payload = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(payload?.error ? `Inbox load failed: ${payload.error}` : 'Inbox load failed');
        setInboxSessions([]);
        return;
      }
      const sessions = Array.isArray(payload?.sessions) ? (payload.sessions as InboxSessionListItem[]) : [];
      setInboxSessions(sessions);
    } catch {
      setStatus('Inbox load failed');
      setInboxSessions([]);
    } finally {
      setInboxLoading(false);
    }
  }, [token, inboxAssigned, inboxSearch, inboxStatus]);

  useEffect(() => {
    if (activeView !== 'inbox') return;
    if (!token) return;
    const handle = window.setTimeout(() => {
      loadInbox();
    }, 200);
    return () => window.clearTimeout(handle);
  }, [activeView, token, inboxStatus, inboxAssigned, inboxSearch, loadInbox]);

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

  const handleLogout = useCallback(async (options?: { reason?: string }) => {
    const authToken = token;
    try {
      if (authToken) {
        await fetch(`${BACKEND_URL}/presence`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
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
    router.push('/agent/auth');
  }, [router, token]);

  useEffect(() => {
    // Hydrate from storage on first mount: token, profile, selected session
    if (didHydrateRef.current) return;
    didHydrateRef.current = true;
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
        refreshOfflineMessages(savedToken);
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
          role?: AgentRole;
        };
        setAgentEmail(p.email || '');
        setName(p.name || '');
        setAgentDisplayName(p.displayName || p.name || '');
        if (p.id) setSelfAgentId(p.id);
        setAgentPhone(p.phone || '');
        setAgentAvatarUrl(p.avatarUrl || '');
        setPresenceOnline((p.status || 'ONLINE') === 'ONLINE');
        setSelfRole(p.role || 'AGENT');
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
  }, [router, refreshOfflineMessages]);

  useEffect(() => {
    if (!token || !isAdmin) {
      setCsatStats(null);
      return;
    }
    refreshCsat();
  }, [token, isAdmin, refreshCsat]);

  // Refresh agents when token changes
  useEffect(() => {
    if (!token) return;
    fetch(`${BACKEND_URL}/agents`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : [])
      .then(setAgents)
      .catch(() => {});
  }, [token]);

  // Load mail settings only when the admin email section is in view
  useEffect(() => {
    if (!token || !isAdmin) return;
    if (activeView !== 'admin' || adminSection !== 'email') return;
    loadMailSettings();
  }, [token, isAdmin, activeView, adminSection, loadMailSettings]);

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
    socket.on('offline_message_created', () => {
      void refreshOfflineMessages();
    });
    socket.on('offline_message_handled', () => {
      void refreshOfflineMessages();
    });
    socket.on('new_chat_available', async (data: { sessionId: string }) => {
      // Fetch visitor and issueType for the sessionId
      if (!token) {
        // No token yet; add without visitor/issueType
        setAvailableChats((prev) => {
          if (prev.some((chat) => chat.sessionId === data.sessionId)) return prev;
          return [...prev, { sessionId: data.sessionId }];
        });
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
          setAvailableChats((prev) => {
            const idx = prev.findIndex((chat) => chat.sessionId === data.sessionId);
            if (idx === -1) return [...prev, enriched];
            const next = [...prev];
            next[idx] = { ...next[idx], ...enriched };
            return next;
          });
          setNewChats((prev) => ({ ...prev, [data.sessionId]: true }));
        } else {
          // Fallback: add without visitor/issueType
          setAvailableChats((prev) => {
            if (prev.some((chat) => chat.sessionId === data.sessionId)) return prev;
            return [...prev, { sessionId: data.sessionId }];
          });
          setNewChats((prev) => ({ ...prev, [data.sessionId]: true }));
        }
      } catch {
        // Fallback: add without visitor/issueType
        setAvailableChats((prev) => {
          if (prev.some((chat) => chat.sessionId === data.sessionId)) return prev;
          return [...prev, { sessionId: data.sessionId }];
        });
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
          const next = { ...prev };
          delete next[sessionId];
          return next;
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
        const next = { ...prev };
        delete next[data.sessionId];
        return next;
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
  }, [selectedSession, token, selfAgentId, handleLogout]);

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
  }, [selectedSession]);

  const requestNotifications = async () => {
    if (typeof window === 'undefined' || !('Notification' in window)) return;
    try {
      const perm = await Notification.requestPermission();
      setNotifPermission(perm);
    } catch {}
  };

  const openInboxSession = async (session: InboxSessionListItem) => {
    if (!session?.id) return;
    if (session.status === 'CLOSED') {
      await openClosedChat(session.id);
      setActiveView('workspace');
      setActiveTab('chats');
      return;
    }

    if (!session.agent) {
      await acceptChat(session.id);
      return;
    }

    setSelectedSessionClosedAt(undefined);
    setSelectedSessionCreatedAt(session.createdAt);
    setSelectedSessionAgent({
      id: session.agent.id,
      name: session.agent.name ?? undefined,
      displayName: session.agent.displayName ?? undefined,
      email: session.agent.email ?? undefined,
    });
    setSelectedSession(session.id);
    setUnreadCounts((prev) => ({ ...prev, [session.id]: 0 }));
    socket.emit('join_session', { sessionId: session.id }, () => {
      setIsLoadingHistory(true);
      socket.emit('get_chat_history', { sessionId: session.id }, (history: MessageEvent[]) => {
        setMessages(history);
        setIsLoadingHistory(false);
      });
    });
    setActiveView('workspace');
    setActiveTab('chats');
  };

  const takeNext = useCallback(async () => {
    if (!token) {
      setStatus('Please log in');
      return;
    }
    if (takeNextBusy) return;
    setTakeNextBusy(true);
    setStatus('Taking next chat...');
    try {
      const res = await fetch(`${BACKEND_URL}/sessions/take-next`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const payload = await res.json().catch(() => null);
      if (!res.ok) {
        setStatus(payload?.error ? `Take next failed: ${payload.error}` : 'Take next failed');
        return;
      }
      const session = payload?.session as InboxSessionListItem | undefined;
      if (!session?.id) {
        setStatus('Take next failed');
        return;
      }
      setStatus('Chat assigned');
      await openInboxSession(session);
      if (activeView === 'inbox') {
        void loadInbox();
      }
    } catch {
      setStatus('Take next failed');
    } finally {
      setTakeNextBusy(false);
    }
  }, [activeView, loadInbox, takeNextBusy, token]);

  const acceptChat = async (sessionId: string) => {
    if (!token) {
      setStatus('Please log in to accept chats');
      return;
    }
    if (!presenceOnline) {
      try {
        await togglePresence(true);
      } catch {}
    }
    socket.emit('agent_accept', { sessionId }, async (resp: { ok?: boolean; error?: string }) => {
      if (resp?.ok) {
        const sessionMeta: { createdAt?: string; closedAt?: string; agent?: { id: string; name?: string; displayName?: string; email?: string } } | null =
          await fetch(`${BACKEND_URL}/sessions/${sessionId}`, {
            headers: token ? { Authorization: `Bearer ${token}` } : {},
          })
            .then((r) => (r.ok ? r.json() : null))
            .catch(() => null);
        if (sessionMeta?.createdAt) setSelectedSessionCreatedAt(sessionMeta.createdAt);
        if (sessionMeta?.agent) setSelectedSessionAgent(sessionMeta.agent);
        if (sessionMeta?.closedAt) {
          setSelectedSessionClosedAt(sessionMeta.closedAt);
          setClosedAtMap((prev) => ({ ...prev, [sessionId]: sessionMeta.closedAt as string }));
        } else {
          setSelectedSessionClosedAt(undefined);
          setClosedAtMap((prev) => {
            if (!prev[sessionId]) return prev;
            const next = { ...prev };
            delete next[sessionId];
            return next;
          });
        }
        setSelectedSession(sessionId);
        // clear unread count when opening the chat
        setUnreadCounts((prev) => ({ ...prev, [sessionId]: 0 }));
        // clear "New" status when accepting
        setNewChats((prev) => ({ ...prev, [sessionId]: false }));
        // inline toast feedback
        setRowToasts(prev => ({ ...prev, [sessionId]: 'Accepted by You' }));
        setTimeout(() => {
          setRowToasts(prev => {
            const next = { ...prev };
            delete next[sessionId];
            return next;
          });
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
    setActiveView('workspace');
    setActiveTab('chats');
    setSelectedSession(sessionId);
    setSelectedSessionCreatedAt(undefined);
    setSelectedSessionClosedAt(undefined);
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

  const focusOfflineWorkspace = () => {
    setActiveView('inbox');
    setActiveTab('offline');
  };

  if (!mounted) return null;

  const closeUnlockModal = () => {
    setShowMailUnlockModal(false);
    setMailUnlockSecret('');
    setMailUnlockError(null);
  };

  const closeSecretModal = () => {
    setShowMailSecretModal(false);
    setMailSecretCurrent('');
    setMailSecretNew('');
  };

  return (
    <div className="min-h-screen w-full bg-slate-50 bg-[radial-gradient(circle_at_top,rgba(2,79,158,0.12),transparent_55%)] px-4 py-6 dark:bg-slate-950">
      {showMailUnlockModal && (
        <div className="fixed inset-0 z-70 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-indigo-200/60 bg-white/95 p-6 shadow-2xl dark:border-slate-800 dark:bg-slate-900">
            <div className="space-y-4">
              <div>
                <p className="text-sm font-semibold text-slate-900 dark:text-white">Unlock mail settings</p>
                <p className="text-sm text-muted-foreground">
                  Enter the integration password to reveal SMTP credentials.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="mail-unlock-secret">Integration password</Label>
                <Input
                  id="mail-unlock-secret"
                  type="password"
                  value={mailUnlockSecret}
                  onChange={(e) => setMailUnlockSecret(e.target.value)}
                  disabled={mailUnlocking}
                  autoFocus
                />
                {mailUnlockError && <p className="text-sm text-red-600">{mailUnlockError}</p>}
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="ghost" onClick={closeUnlockModal} disabled={mailUnlocking}>
                  Cancel
                </Button>
                <Button onClick={unlockMailSettings} disabled={mailUnlocking || !mailUnlockSecret.trim()}>
                  {mailUnlocking ? 'Unlocking…' : 'Unlock'}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showMailSecretModal && (
        <div className="fixed inset-0 z-70 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl border border-indigo-200/60 bg-white/95 p-6 shadow-2xl dark:border-slate-800 dark:bg-slate-900">
            <div className="space-y-5">
              <div>
                <p className="text-sm font-semibold text-slate-900 dark:text-white">Set integration password</p>
                <p className="text-sm text-muted-foreground">
                  This shared secret is required before anyone can edit SMTP credentials. Use at least 8 characters.
                </p>
              </div>
              {mailSecretToken && (
                <>
                  <div className="rounded-xl border border-amber-200 bg-amber-50/70 p-3 text-sm text-amber-900 dark:border-amber-900/40 dark:bg-amber-900/20 dark:text-amber-100">
                    <p className="font-medium">Already unlocked</p>
                    <p>You may change the password by providing the current value below.</p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="mail-transcript-intro">Transcript email intro</Label>
                    <Textarea
                      id="mail-transcript-intro"
                      placeholder="Thanks for chatting with us today..."
                      value={mailTranscriptIntro}
                      onChange={(e) => setMailTranscriptIntro(e.target.value)}
                      disabled={mailLoading || mailSaving}
                      rows={4}
                    />
                    <p className="text-xs text-muted-foreground">
                      This optional message appears above every emailed transcript.
                    </p>
                  </div>
                </>
              )}
              <div className="grid gap-3">
                <div className="space-y-2">
                  <Label htmlFor="mail-secret-current">Current integration password (optional)</Label>
                  <Input
                    id="mail-secret-current"
                    type="password"
                    value={mailSecretCurrent}
                    onChange={(e) => setMailSecretCurrent(e.target.value)}
                    disabled={mailSecretSaving}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="mail-secret-new">New integration password</Label>
                  <Input
                    id="mail-secret-new"
                    type="password"
                    value={mailSecretNew}
                    onChange={(e) => setMailSecretNew(e.target.value)}
                    disabled={mailSecretSaving}
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="ghost" onClick={closeSecretModal} disabled={mailSecretSaving}>
                  Cancel
                </Button>
                <Button onClick={saveIntegrationSecret} disabled={mailSecretSaving || mailSecretNew.trim().length < 8}>
                  {mailSecretSaving ? 'Saving…' : 'Save password'}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 md:flex-row">
        <aside className="md:w-64">
          <div className="sticky top-6 flex flex-col gap-6 rounded-3xl border border-slate-200/80 bg-white/70 p-5 shadow-xl ring-1 ring-slate-100 backdrop-blur dark:border-slate-800 dark:bg-slate-900/60 dark:ring-slate-800">
            <div className="space-y-1">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Agent Console</p>
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Kangenchat</h1>
              <p className="text-sm text-muted-foreground">Navigate tools and workspaces</p>
            </div>
            <div className="space-y-2">
              {primaryNavItems.map((item) => {
                const Icon = item.icon;
                const isActive = activeView === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      if (item.disabled) return;
                      if (item.id === 'inbox') {
                        setActiveView('inbox');
                        setActiveTab('offline');
                        return;
                      }
                      setActiveView(item.id);
                    }}
                    disabled={item.disabled}
                    className={`group w-full rounded-2xl border px-4 py-3 text-left transition disabled:opacity-50 ${
                      isActive
                        ? 'border-transparent bg-linear-to-r from-primary/90 to-sky-500/80 text-white shadow-lg'
                        : 'border-slate-200 bg-white/70 text-slate-600 hover:border-slate-300 hover:bg-white dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span
                          className={`flex h-9 w-9 items-center justify-center rounded-xl bg-linear-to-br ${item.accent}`}
                        >
                          <Icon className={`h-4 w-4 ${isActive ? 'text-slate-900/80 dark:text-white' : 'text-slate-600 dark:text-slate-300'}`} />
                        </span>
                        <div>
                          <p className={`text-sm font-semibold ${isActive ? 'text-white' : 'text-slate-700 dark:text-slate-100'}`}>{item.label}</p>
                          <p className={`text-xs ${isActive ? 'text-white/80' : 'text-slate-500 dark:text-slate-400'}`}>{item.description}</p>
                        </div>
                      </div>
                      {typeof item.metric === 'number' && (
                        <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${isActive ? 'bg-white/20 text-white' : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-200'}`}>
                          {item.metric}
                        </span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
            <div className="rounded-2xl border border-dashed border-slate-200/80 bg-slate-50/80 p-4 text-sm text-slate-500 dark:border-slate-700 dark:bg-slate-900/40 dark:text-slate-300">
              <p className="font-semibold text-slate-700 dark:text-white">Need another tool?</p>
              <p className="mt-1">Use the nav to preview upcoming modules like Automations and Org Settings.</p>
              <Button variant="outline" size="sm" className="mt-3 w-full" onClick={focusOfflineWorkspace}>
                Jump to inbox ↗
              </Button>
            </div>
          </div>
        </aside>

        <main className="flex-1 space-y-6">
          {activeView === 'workspace' || activeView === 'inbox' ? (
            <div className="flex flex-col gap-4">
              {/* Notification banners */}
              {notifPermission === 'denied' && (
                <div className="rounded-xl border border-amber-200 bg-amber-50/80 px-4 py-3 text-sm font-medium text-amber-900 shadow-sm">
                  Notifications are blocked by the browser. Click the lock/tune icon in the address bar to enable, then reload.
                </div>
              )}
              {notifPermission === 'default' && (
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-sky-200 bg-sky-50/80 px-4 py-3 text-sm text-sky-900 shadow-sm">
                  <span className="font-medium">Enable notifications to get alerts for new chats and messages.</span>
                  <Button size="sm" variant="default" onClick={requestNotifications}>
                    Enable desktop alerts
                  </Button>
                </div>
              )}
              <Card className="border border-white/70 bg-linear-to-br from-white/95 via-slate-50/90 to-slate-100/80 shadow-[0_25px_70px_rgba(15,23,42,0.08)] ring-1 ring-slate-100/70 backdrop-blur-xl dark:border-slate-800/70 dark:bg-linear-to-br dark:from-slate-950/70 dark:via-slate-900/60 dark:to-slate-900/40 dark:ring-slate-900/70">
                <CardHeader className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                  <div className="flex flex-1 flex-col gap-4 sm:flex-row sm:items-center">
                    <Avatar className="h-14 w-14 border border-slate-200 shadow-sm">
                      {agentAvatarUrl ? <AvatarImage src={agentAvatarUrl} alt="avatar" /> : null}
                      <AvatarFallback className="text-base font-semibold">{initials}</AvatarFallback>
                    </Avatar>
                    <div className="space-y-1">
                      <CardTitle className="text-2xl font-semibold text-slate-900 dark:text-white">
                        {agentIdentityLabel}
                      </CardTitle>
                      {agentEmail && <div className="text-sm text-muted-foreground">{agentEmail}</div>}
                      {agentPhone && (
                        <div className="text-xs uppercase tracking-wide text-slate-400">{agentPhone}</div>
                      )}
                      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs sm:text-sm">
                        <div className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 shadow-sm ${presenceBadgeMeta.toneClass}`}>
                          <PresenceIcon className="h-4 w-4" />
                          <span className="font-semibold">{presenceBadgeMeta.label}</span>
                          <Switch id="presence" checked={presenceOnline} onCheckedChange={togglePresence} />
                        </div>
                        <div className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 shadow-sm ${statusBadgeMeta.toneClass}`}>
                          <StatusIcon className="h-4 w-4" />
                          <span>{statusBadgeMeta.label}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-col gap-3 text-sm text-muted-foreground md:w-64 md:text-right">
                    <div className="rounded-lg border border-slate-200/80 bg-slate-50 px-3 py-2 text-left text-slate-600 dark:border-slate-800 dark:bg-slate-900/40 dark:text-slate-200 md:text-right">
                      <span className="text-xs uppercase tracking-wide">Connection</span>
                      <div className="text-sm font-medium text-slate-900 dark:text-white">{status}</div>
                    </div>
                    <div className="flex flex-wrap gap-2 md:justify-end">
                      <Button size="sm" variant="ghost" onClick={() => refreshOfflineMessages()}>
                        Refresh inbox
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => handleLogout()}>
                        Log out
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  {overviewStats.map((stat) => {
                    const StatIcon = stat.icon;
                    return (
                      <div
                        key={stat.label}
                        className={`rounded-2xl border bg-white/70 p-4 text-slate-800 shadow-md transition hover:-translate-y-0.5 hover:shadow-lg dark:bg-slate-900/60 dark:text-slate-100 ${stat.toneClass}`}
                      >
                        <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide">
                          <span>{stat.label}</span>
                          <StatIcon className="h-4 w-4" />
                        </div>
                        <div className="mt-2 text-3xl font-bold">{stat.value}</div>
                      </div>
                    );
                  })}
                </CardContent>
              </Card>

              <Card className="border border-amber-100/80 bg-linear-to-br from-amber-50/90 via-white to-amber-50/70 shadow-xl ring-1 ring-amber-100/70 dark:border-amber-900/40 dark:bg-linear-to-br dark:from-amber-950/30 dark:via-slate-900/60 dark:to-amber-950/10 dark:ring-amber-900/40">
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
                        const isAssigned = Object.prototype.hasOwnProperty.call(assignedDepartments, dept.id);
                        const isAvailable = isAssigned ? assignedDepartments[dept.id] : false;
                        const buttonDisabled = departmentBusyId === dept.id || !isAssigned;
                        return (
                          <Button
                            key={dept.id}
                            size="sm"
                            variant={!isAssigned ? 'secondary' : isAvailable ? 'default' : 'outline'}
                            className="rounded-full px-3"
                            onClick={() => {
                              if (!isAssigned) {
                                setStatus('Ask an admin to assign you to this department before going available.');
                                return;
                              }
                              updateDepartmentMembership(dept.id, !isAvailable);
                            }}
                            disabled={buttonDisabled}
                          >
                            <span className="text-xs font-semibold">{dept.name}</span>
                            <span className="ml-2 text-[10px] text-muted-foreground">
                              {!isAssigned ? 'Not assigned' : isAvailable ? 'Available' : 'Go available'}
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
                <div className="space-y-2">
                  {alerts.map((a, i) => (
                    <div key={`${i}-${a}`} className="rounded border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm">
                      {a}
                    </div>
                  ))}
                </div>
              )}

              <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as typeof activeTab)} className="flex-1">
                <TabsList className="flex flex-wrap gap-2 rounded-full bg-slate-50/80 px-2 py-1 shadow-[inset_0_1px_8px_rgba(15,23,42,0.08)] ring-1 ring-slate-200/70 backdrop-blur dark:bg-slate-900/70 dark:ring-slate-800">
                  <TabsTrigger value="chats" className="rounded-full px-4 py-2 text-sm font-semibold text-slate-500 data-[state=active]:bg-indigo-600 data-[state=active]:text-white dark:text-slate-300">Chats</TabsTrigger>
                  <TabsTrigger value="offline" className="rounded-full px-4 py-2 text-sm font-semibold text-slate-500 data-[state=active]:bg-rose-500 data-[state=active]:text-white dark:text-slate-300">Offline Messages</TabsTrigger>
                  <TabsTrigger value="profile" className="rounded-full px-4 py-2 text-sm font-semibold text-slate-500 data-[state=active]:bg-emerald-500 data-[state=active]:text-white dark:text-slate-300">Profile</TabsTrigger>
                </TabsList>
                <div className="mt-4 rounded-[32px] border border-white/70 bg-linear-to-br from-white/95 via-slate-50/85 to-blue-50/70 p-6 shadow-[0_35px_120px_rgba(15,23,42,0.12)] ring-1 ring-slate-100/80 backdrop-blur dark:border-slate-900/60 dark:bg-linear-to-br dark:from-slate-950/80 dark:via-slate-900/70 dark:to-slate-900/50 dark:ring-slate-900/70">
                  <Separator className="my-4" />

                  <TabsContent value="chats" className="flex-1">
                    <div className="space-y-5">
                      <Card className="border border-slate-100/70 bg-linear-to-b from-slate-50 via-white to-slate-100 shadow-lg ring-1 ring-slate-200/60 dark:border-slate-800 dark:bg-linear-to-b dark:from-slate-900/70 dark:via-slate-950/40 dark:to-slate-950/30 dark:ring-slate-800">
                        <CardHeader className="rounded-2xl bg-sky-100/70 px-5 py-4">
                          <CardTitle className="text-lg font-semibold leading-tight" style={{ color: PRIMARY_COLOR }}>
                            Available Chats
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-6 px-5 pb-6 pt-4">
                          <div className="space-y-4">
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
                            <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
                              <div className="flex flex-1 flex-wrap gap-2">
                                <div className="relative min-w-[220px] flex-1">
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
                                <div className="flex flex-1 flex-wrap gap-2">
                                  <div className="flex flex-1 min-w-[200px] items-center gap-2">
                                    <Filter className="h-4 w-4 text-muted-foreground" />
                                    <Select value={chatFilter} onValueChange={(value: typeof chatFilter) => setChatFilter(value)}>
                                      <SelectTrigger className="h-9 w-full sm:w-[160px]">
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
                                  <div className="flex flex-1 min-w-[200px] items-center gap-2">
                                    <Loader2 className="h-4 w-4 text-muted-foreground" />
                                    <Select value={chatSort} onValueChange={(value: typeof chatSort) => setChatSort(value)}>
                                      <SelectTrigger className="h-9 w-full sm:w-[200px]">
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
                          </div>
                          <div className="space-y-6">
                            <div className="flex gap-3 overflow-x-auto pb-2 text-sm sm:flex-wrap sm:overflow-visible sm:pb-0 [&>*]:min-w-[200px] [&>*]:flex-1">
                              <div className="rounded-xl border border-muted bg-background/80 px-4 py-3 shadow-sm snap-start">
                                <div className="flex items-center gap-2 text-muted-foreground">
                                  <Inbox className="h-4 w-4" />
                                  <span>{queueView === 'waiting' ? 'Waiting' : queueView === 'active' ? 'Active' : 'Closed'} chats</span>
                                </div>
                                <div className="mt-1 text-2xl font-semibold text-foreground">{filteredQueueChats.length}</div>
                                <p className="text-xs text-muted-foreground">Currently visible in this tab</p>
                              </div>
                              <div className="rounded-xl border border-muted bg-background/80 px-4 py-3 shadow-sm snap-start">
                                <div className="flex items-center gap-2 text-muted-foreground">
                                  <Users className="h-4 w-4" />
                                  <span>Agents online</span>
                                </div>
                                <div className="mt-1 text-2xl font-semibold text-foreground">{onlineAgents.length}</div>
                                <p className="text-xs text-muted-foreground">Ready to take chats</p>
                              </div>
                              <div className="rounded-xl border border-muted bg-background/80 px-4 py-3 shadow-sm snap-start">
                                <div className="flex items-center gap-2 text-muted-foreground">
                                  <Clock className="h-4 w-4" />
                                  <span>Longest wait</span>
                                </div>
                                <div className="mt-1 text-2xl font-semibold text-foreground">{longestWaitSummary}</div>
                                <p className="text-xs text-muted-foreground">Updates every minute</p>
                              </div>
                              <div className="rounded-xl border border-muted bg-background/80 px-4 py-3 shadow-sm snap-start">
                                <div className="flex items-center gap-2 text-muted-foreground">
                                  <Inbox className="h-4 w-4" />
                                  <span>Filtered chats</span>
                                </div>
                                <div className="mt-1 text-2xl font-semibold text-foreground">{filteredQueueCount}</div>
                                <p className="text-xs text-muted-foreground">After search & filters</p>
                              </div>
                              <div className="rounded-xl border border-muted bg-background/80 px-4 py-3 shadow-sm snap-start">
                                <div className="flex items-center gap-2 text-muted-foreground">
                                  <Clock className="h-4 w-4" />
                                  <span>Slowest waiting</span>
                                </div>
                                <div className="mt-1 flex items-center justify-between text-sm text-foreground">
                                  <div>
                                    {slowestWaitingChat ? (
                                      <>
                                        <div className="font-medium">
                                          {slowestWaitingChat.visitor?.name || slowestWaitingChat.sessionId.slice(-4)}
                                        </div>
                                        <div className="text-xs text-muted-foreground">{slowestWaitingChat.waitMinutes} min in queue</div>
                                      </>
                                    ) : (
                                      <div className="text-xs text-muted-foreground">No waiting chats</div>
                                    )}
                                  </div>
                                  <span className="text-lg font-semibold">
                                    {slowestWaitingChat ? `${slowestWaitingChat.waitMinutes} min` : '—'}
                                  </span>
                                </div>
                              </div>
                            </div>
                            <div className="rounded-3xl border border-slate-200/70 bg-linear-to-b from-white via-slate-50 to-slate-100 p-4 shadow-inner dark:border-slate-800 dark:bg-linear-to-b dark:from-slate-950/60 dark:via-slate-900/50 dark:to-slate-900/40">
                              <div className="flex items-center justify-between">
                                <div>
                                  <p className="text-base font-semibold text-foreground">Live Queue</p>
                                  <p className="text-xs text-muted-foreground">
                                    {queueView === 'closed'
                                      ? 'Browse transcripts from recently ended chats'
                                      : 'Select a chat to preview, accept, or transfer'}
                                  </p>
                                </div>
                                <span className="text-xs rounded-full bg-slate-200/70 px-2 py-0.5 text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                                  {queueView === 'closed' ? 'Closed' : queueView === 'active' ? 'Active' : 'Waiting'} view
                                </span>
                              </div>
                              <ScrollArea className="mt-3 h-[40vh] rounded-2xl border border-slate-100/70 bg-white/80 p-3 shadow-inner dark:border-slate-800 dark:bg-slate-950/30">
                                <ul>
                                  {queueView !== 'closed'
                                    ? filteredQueueChats.map((chat) => {
                                        const waitMinutes = computeWaitMinutes(chat.createdAt);
                                        const waitLabel =
                                          waitMinutes === null
                                            ? 'Waiting'
                                            : waitMinutes < 1
                                            ? 'Waiting <1 min'
                                            : `Waiting ${waitMinutes} min`;
                                        const urgencyClass =
                                          waitMinutes === null
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
                                              disabled={queueView === 'waiting' ? (!token || !!assignedAgents[chat.sessionId]) : false}
                                            >
                                              <div className="flex flex-col items-start gap-1">
                                                <span className="text-sm font-medium text-foreground">
                                                  {chat.visitor?.name || chat.visitor?.email || chat.issueType || `Session ${chat.sessionId.slice(-4)}`}
                                                </span>
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
                                      })
                                    : filteredQueueChats.map((chat) => (
                                        <li key={chat.sessionId} className="mb-2">
                                          <Button
                                            variant="outline"
                                            className="w-full justify-between text-left h-auto py-2 px-3 opacity-90"
                                            onClick={() => openClosedChat(chat.sessionId)}
                                          >
                                            <div className="flex flex-col items-start">
                                              {chat.visitor && (
                                                <span className="text-sm text-muted-foreground">
                                                  {chat.visitor.name || 'Anonymous'}
                                                  {chat.visitor.email && ` <${chat.visitor.email}>`}
                                                </span>
                                              )}
                                              {chat.issueType && (
                                                <span className="text-xs bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded mt-1">{chat.issueType}</span>
                                              )}
                                              {chat.createdAt && closedAtMap[chat.sessionId] && (
                                                <span className="text-xs text-muted-foreground mt-1">
                                                  {(() => {
                                                    const secs = Math.max(
                                                      0,
                                                      Math.floor(
                                                        (new Date(closedAtMap[chat.sessionId] as string).getTime() -
                                                          new Date(chat.createdAt as string).getTime()) /
                                                          1000
                                                      )
                                                    );
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
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card className="flex flex-col overflow-hidden border border-indigo-100/70 bg-linear-to-b from-white via-indigo-50/80 to-white/90 shadow-xl ring-1 ring-indigo-100/70 dark:border-slate-800 dark:bg-linear-to-b dark:from-slate-950/70 dark:via-slate-900/60 dark:to-slate-900/40 dark:ring-slate-900/60">
              <CardHeader className="rounded-2xl bg-indigo-100/70 px-5 py-4">
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
              <CardContent className="flex h-[60vh] max-h-[60vh] min-h-0 flex-col gap-4 overflow-hidden rounded-2xl bg-linear-to-b from-white/95 via-slate-50/70 to-white/90 px-5 py-5 shadow-inner dark:bg-linear-to-b dark:from-slate-950/70 dark:via-slate-900/60 dark:to-slate-900/40">
                {selectedSession ? (
                  <>
                    <div className="flex-1 min-h-0 overflow-hidden rounded-2xl border border-indigo-100/70 bg-linear-to-b from-white via-indigo-50/60 to-white/85 shadow-inner dark:border-slate-800 dark:bg-linear-to-b dark:from-slate-950/70 dark:via-slate-900/60 dark:to-slate-900/50">
                      <div className="h-full max-h-full overflow-y-auto p-4 pr-5" ref={scrollAreaRef}>
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
                        {isTyping && (
                          <div className="mt-3 inline-flex items-center gap-2 rounded-full bg-slate-100 px-3 py-1 text-[11px] italic text-slate-600 shadow-sm">
                            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" aria-hidden="true" />
                            {isTyping.role === 'USER' ? 'User is typing…' : 'Agent is typing…'}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex flex-col gap-3 rounded-2xl bg-slate-50/70 p-3">
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:space-x-2">
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
                        <div className="flex gap-2">
                          <Button
                            type="button"
                            variant="outline"
                            onClick={() => setShowEmojiPickerAgent(prev => !prev)}
                          >
                            🙂
                          </Button>
                          <Button onClick={sendMessage}>Send</Button>
                        </div>
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
                    {selectedSession && !selectedSessionClosedAt && (
                      <div className="sticky bottom-2 mt-2 flex justify-end">
                        <Button variant="destructive" size="sm" onClick={endChat}>
                          End chat
                        </Button>
                      </div>
                    )}
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
          <Card className="h-full border border-rose-100/70 bg-linear-to-b from-white via-rose-50/70 to-white/90 shadow-xl ring-1 ring-rose-100/70 dark:border-rose-900/40 dark:bg-linear-to-b dark:from-slate-950/70 dark:via-rose-950/30 dark:to-slate-900/40 dark:ring-rose-900/50">
            <CardHeader className="flex flex-col gap-3 rounded-2xl bg-rose-100/70 px-5 py-4 md:flex-row md:items-center md:justify-between">
              <div>
                <CardTitle>Offline Messages</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Follow up on visitors who left a message while we were offline.
                </p>
              </div>
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <span>Pending: <span className="font-semibold text-foreground">{offlinePendingCount}</span></span>
                <Button variant="outline" size="sm" onClick={() => refreshOfflineMessages()} disabled={offlineLoading}>
                  {offlineLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent className="h-[65vh] rounded-2xl bg-linear-to-b from-white via-rose-50/50 to-white/90 px-5 py-5 shadow-inner dark:bg-linear-to-b dark:from-slate-950/70 dark:via-rose-950/30 dark:to-slate-900/50">
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

      </div>
      </Tabs>
    </div>
  ) : activeView === 'admin' ? (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-[260px,1fr]">
        <Card className="border border-purple-100/70 bg-white/85 shadow-sm dark:border-purple-900/40 dark:bg-slate-900/60">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Admin Tools</CardTitle>
            <p className="text-sm text-muted-foreground">Switch between org-level tasks.</p>
          </CardHeader>
          <CardContent className="space-y-3">
            {adminNavItems.map((item) => (
              <button
                key={item.id}
                type="button"
                aria-pressed={adminSection === item.id}
                onClick={() => setAdminSection(item.id)}
                className={`w-full rounded-2xl border px-4 py-3 text-left transition ${
                  adminSection === item.id
                    ? 'border-transparent bg-purple-600 text-white shadow-lg'
                    : 'border-slate-200 bg-white/70 text-slate-600 hover:border-slate-300 hover:bg-white dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className={`text-sm font-semibold ${adminSection === item.id ? 'text-white' : 'text-slate-600 dark:text-slate-300'}`}>
                      {item.label}
                    </p>
                    <p className={`text-xs ${adminSection === item.id ? 'text-white/80' : 'text-slate-500 dark:text-slate-400'}`}>
                      {item.description}
                    </p>
                  </div>
                  {typeof item.metric === 'number' && (
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs font-semibold ${
                        adminSection === item.id ? 'bg-white/20 text-white' : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-200'
                      }`}
                    >
                      {item.metric}
                    </span>
                  )}
                </div>
              </button>
            ))}
          </CardContent>
        </Card>

        <div className="space-y-6">
          {adminSection === 'departments' && (
            <Card className="border border-white/70 bg-linear-to-b from-white via-slate-50/60 to-white/85 shadow-xl ring-1 ring-purple-100/60 dark:border-slate-800 dark:bg-linear-to-b dark:from-slate-950/70 dark:via-slate-900/60 dark:to-slate-900/40 dark:ring-slate-900/70">
              <CardHeader className="rounded-2xl bg-purple-100/60 px-5 py-4">
                <CardTitle>Departments</CardTitle>
                <p className="text-sm text-muted-foreground">Create routing groups and manage membership.</p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                  <Input
                    value={newDepartmentName}
                    onChange={(e) => setNewDepartmentName(e.target.value)}
                    placeholder="New department name"
                    disabled={createDepartmentBusy}
                  />
                  <Button
                    size="sm"
                    onClick={createDepartment}
                    disabled={createDepartmentBusy || !newDepartmentName.trim()}
                  >
                    {createDepartmentBusy ? 'Creating…' : 'Create'}
                  </Button>
                  <Button size="sm" variant="outline" onClick={loadDepartments} disabled={departmentsLoading}>
                    {departmentsLoading ? 'Loading…' : 'Reload'}
                  </Button>
                </div>
                {departments.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-4 text-sm text-slate-600 dark:border-slate-800 dark:bg-slate-900/40 dark:text-slate-300">
                    No departments configured yet.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {departments.map((dept) => {
                      const members: DepartmentAgent[] = (dept.agentDepartments ?? []).map((m) => m.agent);
                      const selectedAgentId = departmentAssignSelection[dept.id] || '';
                      const isEditingName = typeof departmentEditName[dept.id] === 'string';
                      const editNameValue = isEditingName ? departmentEditName[dept.id] : '';
                      return (
                        <div key={dept.id} className="rounded-lg border border-border bg-background p-3">
                          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                            <div className="flex flex-col gap-2">
                              {isEditingName ? (
                                <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                                  <Input
                                    value={editNameValue}
                                    onChange={(e) =>
                                      setDepartmentEditName((prev) => ({ ...prev, [dept.id]: e.target.value }))
                                    }
                                    className="h-8 w-64"
                                    disabled={departmentAdminBusyKey === `${dept.id}:rename`}
                                  />
                                  <div className="flex gap-2">
                                    <Button
                                      size="sm"
                                      onClick={() => renameDepartment(dept.id)}
                                      disabled={
                                        departmentAdminBusyKey === `${dept.id}:rename` || !editNameValue.trim()
                                      }
                                    >
                                      {departmentAdminBusyKey === `${dept.id}:rename` ? 'Saving…' : 'Save'}
                                    </Button>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() =>
                                        setDepartmentEditName((prev) => {
                                          const next = { ...prev };
                                          delete next[dept.id];
                                          return next;
                                        })
                                      }
                                      disabled={departmentAdminBusyKey === `${dept.id}:rename`}
                                    >
                                      Cancel
                                    </Button>
                                  </div>
                                </div>
                              ) : (
                                <div className="flex items-center gap-2">
                                  <div className="text-sm font-semibold text-foreground">{dept.name}</div>
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className="h-7 px-2"
                                    onClick={() => setDepartmentEditName((prev) => ({ ...prev, [dept.id]: dept.name }))}
                                    disabled={departmentAdminBusyKey === `${dept.id}:delete`}
                                  >
                                    Rename
                                  </Button>
                                  <Button
                                    size="sm"
                                    variant="destructive"
                                    className="h-7 px-2"
                                    onClick={() => deleteDepartment(dept.id)}
                                    disabled={departmentAdminBusyKey === `${dept.id}:delete`}
                                  >
                                    {departmentAdminBusyKey === `${dept.id}:delete` ? 'Deleting…' : 'Delete'}
                                  </Button>
                                </div>
                              )}
                            </div>
                            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                              <Select
                                value={selectedAgentId}
                                onValueChange={(value) =>
                                  setDepartmentAssignSelection((prev) => ({ ...prev, [dept.id]: value }))
                                }
                              >
                                <SelectTrigger className="h-8 w-56">
                                  <SelectValue placeholder="Add agent" />
                                </SelectTrigger>
                                <SelectContent>
                                  {agents.map((a) => (
                                    <SelectItem key={a.id} value={a.id}>
                                      {(a.displayName || a.name || a.email) + (a.status ? ` (${a.status})` : '')}
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                              <Button
                                size="sm"
                                onClick={() => assignAgentToDepartment(dept.id, selectedAgentId)}
                                disabled={!selectedAgentId || departmentAdminBusyKey === `${dept.id}:assign`}
                              >
                                {departmentAdminBusyKey === `${dept.id}:assign` ? 'Adding…' : 'Add'}
                              </Button>
                            </div>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {members.length === 0 ? (
                              <div className="text-xs text-muted-foreground">No agents assigned.</div>
                            ) : (
                              members.map((agent: DepartmentAgent) => {
                                const key = `${dept.id}:${agent.id}:remove`;
                                return (
                                  <div
                                    key={agent.id}
                                    className="inline-flex items-center gap-2 rounded-full border border-border bg-background px-3 py-1 text-xs"
                                  >
                                    <span>
                                      {agent.displayName || agent.name || agent.email}
                                      {agent.status ? ` (${agent.status})` : ''}
                                    </span>
                                    <Button
                                      size="sm"
                                      variant="ghost"
                                      className="h-6 px-2"
                                      onClick={() => unassignAgentFromDepartment(dept.id, agent.id)}
                                      disabled={departmentAdminBusyKey === key}
                                    >
                                      {departmentAdminBusyKey === key ? 'Removing…' : 'Remove'}
                                    </Button>
                                  </div>
                                );
                              })
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
              {mailLocked && (
                <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-4 rounded-2xl bg-white/80 backdrop-blur-sm dark:bg-slate-900/60">
                  <div className="flex flex-col items-center gap-2 text-center">
                    <div className="inline-flex h-12 w-12 items-center justify-center rounded-full bg-indigo-100 text-indigo-900 dark:bg-indigo-900/40 dark:text-indigo-100">
                      <Lock className="h-5 w-5" />
                    </div>
                    <div>
                      <p className="font-semibold text-slate-900 dark:text-white">Mail settings are locked</p>
                      <p className="text-sm text-muted-foreground">
                        Enter the integration password to edit SMTP credentials.
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-wrap justify-center gap-3">
                    <Button variant="outline" onClick={() => setShowMailUnlockModal(true)}>
                      Unlock settings
                    </Button>
                    <Button variant="ghost" onClick={() => setShowMailSecretModal(true)}>
                      Forgot / rotate password
                    </Button>
                  </div>
                </div>
              )}
            </Card>
          )}

          {adminSection === 'agents' && (
            <Card className="border border-white/70 bg-linear-to-b from-white via-slate-50/60 to-white/85 shadow-xl ring-1 ring-purple-100/60 dark:border-slate-800 dark:bg-linear-to-b dark:from-slate-950/70 dark:via-slate-900/60 dark:to-slate-900/40 dark:ring-slate-900/70">
              <CardHeader className="rounded-2xl bg-purple-100/60 px-5 py-4">
                <CardTitle>Agent management</CardTitle>
                <p className="text-sm text-muted-foreground">Invite teammates, reset passwords, or remotely sign them out.</p>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="rounded-2xl border border-dashed border-purple-200/80 bg-white/70 p-4 shadow-sm dark:border-purple-900/40 dark:bg-slate-950/40">
                  <form
                    className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between"
                    onSubmit={(event) => {
                      event.preventDefault();
                      createAgent();
                    }}
                  >
                    <div className="flex-1 grid gap-3 sm:grid-cols-2">
                      <div className="space-y-1.5">
                        <Label htmlFor="new-agent-name">Full name</Label>
                        <Input
                          id="new-agent-name"
                          placeholder="Taylor Agent"
                          value={newAgentName}
                          onChange={(e) => setNewAgentName(e.target.value)}
                          disabled={newAgentBusy}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="new-agent-display-name">Display name (optional)</Label>
                        <Input
                          id="new-agent-display-name"
                          placeholder="Taylor @ HQ"
                          value={newAgentDisplayName}
                          onChange={(e) => setNewAgentDisplayName(e.target.value)}
                          disabled={newAgentBusy}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="new-agent-email">Email</Label>
                        <Input
                          id="new-agent-email"
                          type="email"
                          placeholder="taylorsupport@company.com"
                          value={newAgentEmail}
                          onChange={(e) => setNewAgentEmail(e.target.value)}
                          disabled={newAgentBusy}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="new-agent-phone">Phone (optional)</Label>
                        <Input
                          id="new-agent-phone"
                          placeholder="+1 (555) 000-1234"
                          value={newAgentPhone}
                          onChange={(e) => setNewAgentPhone(e.target.value)}
                          disabled={newAgentBusy}
                        />
                      </div>
                      <div className="space-y-1.5 sm:col-span-2">
                        <Label htmlFor="new-agent-password">Temporary password</Label>
                        <Input
                          id="new-agent-password"
                          type="password"
                          placeholder={`min ${MIN_AGENT_PASSWORD_LENGTH} characters`}
                          value={newAgentPassword}
                          onChange={(e) => setNewAgentPassword(e.target.value)}
                          disabled={newAgentBusy}
                        />
                      </div>
                      <div className="flex items-center gap-3 sm:col-span-2">
                        <Select value={newAgentRole} onValueChange={(value) => setNewAgentRole(value as AgentRole)} disabled={newAgentBusy}>
                          <SelectTrigger id="new-agent-role" className="w-48">
                            <SelectValue placeholder="Select role" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="AGENT">Agent</SelectItem>
                            <SelectItem value="MANAGER">Manager</SelectItem>
                            <SelectItem value="ADMIN">Admin</SelectItem>
                          </SelectContent>
                        </Select>
                        <div>
                          <Label htmlFor="new-agent-role" className="text-sm font-medium">
                            Role
                          </Label>
                          <p className="text-xs text-muted-foreground">Admins manage org settings; Managers oversee analytics/chats.</p>
                        </div>
                      </div>
                    </div>
                    <div className="flex w-full flex-col gap-2 md:w-48">
                      <Button type="submit" disabled={newAgentBusy}>
                        {newAgentBusy ? 'Creating…' : 'Create agent'}
                      </Button>
                      <Button
                        variant="ghost"
                        type="button"
                        onClick={() => {
                          setNewAgentName('');
                          setNewAgentDisplayName('');
                          setNewAgentEmail('');
                          setNewAgentPhone('');
                          setNewAgentPassword('');
                          setNewAgentRole('AGENT');
                        }}
                        disabled={newAgentBusy}
                      >
                        Clear form
                      </Button>
                      <p className="text-xs text-muted-foreground">
                        New agents receive no automated email yet—share the temporary password manually.
                      </p>
                    </div>
                  </form>
                </div>
                {agents.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-4 text-sm text-slate-600 dark:border-slate-800 dark:bg-slate-900/40 dark:text-slate-300">
                    No agents found.
                  </div>
                ) : (
                  agents.map((agent) => {
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
                            {(agent.role === 'ADMIN' || agent.role === 'MANAGER') && (
                              <span className="ml-2 inline-flex items-center rounded-full bg-purple-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-purple-800 dark:bg-purple-900/30 dark:text-purple-200">
                                {ROLE_LABEL[agent.role]}
                              </span>
                            )}
                            {isSelf && <span className="ml-1 text-xs text-muted-foreground">(you)</span>}
                          </div>
                          <div className="text-xs text-muted-foreground">{agent.email}</div>
                          {agent.phone && <div className="text-xs text-muted-foreground">{agent.phone}</div>}
                          {agent.status && <div className="text-xs text-muted-foreground">Status: {agent.status}</div>}
                        </div>
                        <div className="flex flex-col gap-2 md:w-80">
                          <div className="flex items-center gap-2">
                            <Label htmlFor={`role-${agent.id}`} className="text-xs">Role:</Label>
                            <Select
                              value={agent.role || 'AGENT'}
                              onValueChange={(value) => updateAgentRole(agent.id, value as AgentRole)}
                            >
                              <SelectTrigger className="w-24 h-8">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="AGENT">Agent</SelectItem>
                                <SelectItem value="MANAGER">Manager</SelectItem>
                                <SelectItem value="ADMIN">Admin</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <form
                            className="flex flex-col gap-2"
                            onSubmit={(event) => {
                              event.preventDefault();
                              setAgentPassword(agent.id);
                            }}
                          >
                            <Label htmlFor={`admin-password-${agent.id}`} className="text-xs">
                              Set new password (min {MIN_AGENT_PASSWORD_LENGTH} chars)
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
                                type="submit"
                                disabled={!!adminPwdBusy[agent.id] || !(adminPwdMap[agent.id] || '').trim()}
                              >
                                {adminPwdBusy[agent.id] ? 'Updating…' : 'Set password'}
                              </Button>
                              <Button
                                size="sm"
                                type="button"
                                variant="outline"
                                onClick={() => logoffAgent(agent.id)}
                                disabled={isSelf || isOffline || !!adminLogoutBusy[agent.id]}
                              >
                                {adminLogoutBusy[agent.id]
                                  ? 'Logging off…'
                                  : isOffline
                                  ? 'Already offline'
                                  : 'Log off'}
                              </Button>
                              <Button
                                size="sm"
                                type="button"
                                variant="destructive"
                                onClick={() => deleteAgent(agent.id)}
                                disabled={isSelf || !!adminDeleteBusy[agent.id]}
                              >
                                {adminDeleteBusy[agent.id] ? 'Deleting…' : 'Delete'}
                              </Button>
                            </div>
                          </form>
                        </div>
                      </div>
                    );
                  })
                )}
              </CardContent>
            </Card>
          )}

          {adminSection === 'email' && (
            <Card className="relative border-none bg-indigo-50/70 shadow-md ring-1 ring-indigo-100 dark:bg-slate-900/70 dark:ring-slate-800">
              <CardHeader className="rounded-2xl bg-indigo-100/60 px-5 py-4">
                <CardTitle>Email settings</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Configure SMTP credentials for password reset and transcript messages. These override env defaults.
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
                    <p className="text-xs text-muted-foreground">Enable for SMTPS / TLS-only endpoints.</p>
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
                <div className="space-y-2">
                  <Label htmlFor="mail-transcript-intro-field">Transcript email intro</Label>
                  <Textarea
                    id="mail-transcript-intro-field"
                    placeholder="Thanks for chatting with us today..."
                    value={mailTranscriptIntro}
                    onChange={(e) => setMailTranscriptIntro(e.target.value)}
                    disabled={mailLoading || mailSaving}
                    rows={4}
                  />
                  <p className="text-xs text-muted-foreground">
                    Shown above every emailed transcript. Leave blank for no intro.
                  </p>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                    {mailRequiresSecret && (
                      <div className="inline-flex items-center gap-1 rounded-full border border-indigo-200 bg-white/80 px-3 py-1 text-xs text-indigo-900 dark:border-indigo-800/60 dark:bg-slate-900/50 dark:text-indigo-200">
                        <Lock className="h-3 w-3" />
                        Integration password enforced
                      </div>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-xs text-indigo-900 hover:text-indigo-900 dark:text-indigo-200"
                      onClick={() => setShowMailSecretModal(true)}
                      disabled={mailLoading || mailSaving}
                    >
                      <KeyRound className="mr-2 h-3.5 w-3.5" /> Set integration password
                    </Button>
                  </div>
                  <div className="flex items-center gap-3">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => loadMailSettings()}
                      disabled={mailLoading || mailSaving}
                    >
                      {mailLoading ? 'Reloading…' : 'Reload from server'}
                    </Button>
                    <Button size="sm" onClick={saveMailSettings} disabled={mailSaving || mailLoading}>
                      {mailSaving ? 'Saving…' : 'Save settings'}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {adminSection === 'upcoming' && (
            <Card className="border border-dashed border-purple-200 bg-white/80 p-6 text-center shadow-sm dark:border-purple-900/40 dark:bg-slate-900/60">
              <div className="space-y-3">
                <CardTitle className="text-lg">More tools coming soon</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Billing, org branding, and automation controls will land here as they are built.
                </p>
                <Button variant="outline" onClick={() => setAdminSection('departments')}>
                  Back to departments
                </Button>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  ) : activeView === 'shortcuts' ? (
    <div className="space-y-6">
      <div className="rounded-3xl border border-slate-200/80 bg-white/80 p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900/50">
        <h2 className="text-xl font-bold text-slate-900 dark:text-white">Shortcuts</h2>
        <p className="mt-1 text-sm text-muted-foreground">Create canned replies and insert them into the chat composer.</p>
      </div>

      {toastNotification && (
        <div
          className={`fixed bottom-6 right-6 z-50 rounded-xl px-4 py-2 text-sm font-medium shadow-lg ring-1 transition-all ${
            toastNotification.tone === 'success'
              ? 'bg-emerald-600 text-white ring-emerald-700/40'
              : toastNotification.tone === 'error'
              ? 'bg-red-600 text-white ring-red-700/40'
              : 'bg-slate-900 text-white ring-slate-700/40'
          }`}
          role="status"
        >
          {toastNotification.message}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="border-none bg-white/90 shadow-xl ring-1 ring-slate-100 dark:bg-slate-900/70 dark:ring-slate-800">
          <CardHeader className="space-y-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">Your shortcuts</CardTitle>
              <span className="text-xs text-muted-foreground">{filteredShortcuts.length} items</span>
            </div>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={shortcutSearch}
                onChange={(e) => setShortcutSearch(e.target.value)}
                placeholder="Search shortcuts"
                className="pl-9"
              />
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[60vh] pr-2">
              <div className="space-y-3">
                {filteredShortcuts.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-4 text-sm text-slate-600 dark:border-slate-800 dark:bg-slate-900/40 dark:text-slate-300">
                    No shortcuts match your search.
                  </div>
                ) : (
                  filteredShortcuts.map((s) => (
                    <div key={s.id} className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950/30">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-semibold text-slate-900 dark:text-white">{s.title}</div>
                          <div className="mt-1 line-clamp-3 text-sm text-muted-foreground">{s.text}</div>
                        </div>
                        <div className="flex flex-col gap-2">
                          <Button size="sm" onClick={() => applyShortcut(s.text)}>
                            Use
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => copyShortcut(s.text)}>
                            Copy
                          </Button>
                          <Button size="sm" variant="destructive" onClick={() => deleteShortcut(s.id)}>
                            Delete
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card className="border-none bg-white/90 shadow-xl ring-1 ring-slate-100 dark:bg-slate-900/70 dark:ring-slate-800">
          <CardHeader>
            <CardTitle className="text-lg">Add a shortcut</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="shortcut-title">Title</Label>
              <Input
                id="shortcut-title"
                value={shortcutTitle}
                onChange={(e) => setShortcutTitle(e.target.value)}
                placeholder="e.g. Pricing overview"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="shortcut-text">Message</Label>
              <textarea
                id="shortcut-text"
                value={shortcutText}
                onChange={(e) => setShortcutText(e.target.value)}
                placeholder="Write the reply you want to reuse..."
                className="min-h-40 w-full resize-none rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              />
            </div>
            <div className="flex items-center justify-end gap-2">
              <Button
                variant="outline"
                onClick={() => {
                  setShortcutTitle('');
                  setShortcutText('');
                }}
                disabled={!shortcutTitle && !shortcutText}
              >
                Clear
              </Button>
              <Button onClick={addShortcut} disabled={!shortcutTitle.trim() || !shortcutText.trim()}>
                Add shortcut
              </Button>
            </div>
            <Separator />
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600 dark:border-slate-800 dark:bg-slate-900/40 dark:text-slate-300">
              Tip: After clicking <span className="font-semibold">Use</span>, you’ll be returned to the workspace with the message inserted into your composer.
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  ) : activeView === 'csat' ? (
    <div className="space-y-6">
      <div className="rounded-3xl border border-sky-200/70 bg-white/80 p-6 shadow-sm dark:border-sky-900/40 dark:bg-slate-900/50">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white">Customer Satisfaction (CSAT)</h2>
            <p className="text-sm text-muted-foreground">
              Monitor customer satisfaction metrics. More detailed reporting will be added here.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={handleCsatRefresh} disabled={!token || csatRefreshing}>
              {csatRefreshing ? 'Refreshing…' : 'Refresh'}
            </Button>
            <Button size="sm" variant="outline" onClick={() => setActiveView('workspace')}>
              Back to workspace
            </Button>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl border border-slate-200 bg-linear-to-br from-blue-50 to-blue-100 p-5 text-slate-800 shadow-md dark:border-slate-800 dark:from-slate-800 dark:to-slate-900 dark:text-white">
          <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide">
            <span>Customer satisfaction score</span>
            <Sparkles className="h-4 w-4" />
          </div>
          <div className="mt-2 text-3xl font-bold">{csatScore !== null ? `${csatScore.toFixed(1)}%` : '—'}</div>
          <div className="mt-3 h-2 w-full rounded-full bg-white/60 dark:bg-white/10">
            <div
              className="h-full rounded-full bg-linear-to-r from-sky-500 to-blue-600 transition-all"
              style={{ width: csatScore !== null ? `${Math.min(100, Math.max(0, csatScore))}%` : '0%' }}
            />
          </div>
          <p className="mt-2 text-xs text-slate-600 dark:text-slate-300">
            {csatStats?.total ? `${csatStats.total} surveys this week` : 'No survey submissions yet'}
          </p>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 text-slate-800 shadow-sm dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-100">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Average rating</div>
          <div className="mt-2 text-3xl font-bold">
            {csatStats?.average !== null && csatStats?.average !== undefined ? csatStats.average.toFixed(2) : '—'}
            <span className="ml-2 text-base font-semibold text-slate-500 dark:text-slate-400">/ 5</span>
          </div>
          <div className="mt-2 text-sm text-muted-foreground">Average survey rating for the current period.</div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 text-slate-800 shadow-sm dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-100">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Positive surveys</div>
          <div className="mt-2 text-3xl font-bold">
            {csatStats?.positive ?? 0}
            {positiveRate !== null && (
              <span className="ml-2 text-base font-semibold text-slate-500 dark:text-slate-400">{positiveRate}%</span>
            )}
          </div>
          <div className="mt-2 text-sm text-muted-foreground">Count of ratings 4–5.</div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 text-slate-800 shadow-sm dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-100">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Avg wait to agent</div>
          <div className="mt-2 text-3xl font-bold">{averageWaitLabel}</div>
          <div className="mt-2 text-sm text-muted-foreground">
            Time from visitor first message to first assignment over last {csatStats?.agentWindowDays ?? 30} days.
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white/80 p-5 text-slate-800 shadow-sm dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-100">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Avg queue size</div>
          <div className="mt-2 text-3xl font-bold">{averageQueueLabel}</div>
          <div className="mt-2 text-sm text-muted-foreground">Estimated concurrent chats waiting for agents.</div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-200 bg-white/85 p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900/60">
          <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            <span>Rating distribution</span>
            <span>{csatStats?.total ? `${csatStats.total} total` : 'No data'}</span>
          </div>
          <div className="mt-4 space-y-3">
            {csatDistributionEntries.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-200/80 p-6 text-center text-sm text-muted-foreground dark:border-slate-800/60">
                No CSAT responses yet.
              </div>
            ) : (
              csatDistributionEntries.map((entry) => (
                <div key={entry.rating}>
                  <div className="flex items-center justify-between text-sm font-medium text-slate-700 dark:text-slate-200">
                    <span>{entry.rating} star{entry.rating === 1 ? '' : 's'}</span>
                    <span className="text-xs text-muted-foreground">
                      {entry.value} ({entry.percent}%)
                    </span>
                  </div>
                  <div className="mt-1 h-2 rounded-full bg-slate-100 dark:bg-slate-800">
                    <div
                      className="h-full rounded-full bg-linear-to-r from-indigo-500 via-sky-500 to-emerald-400 transition-all"
                      style={{ width: `${entry.percent}%` }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white/85 p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900/60">
          <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            <span>Trend (last {csatPeriodDays} days)</span>
            <span>{csatPeriodResponses} responses</span>
          </div>
          <div className="mt-4 space-y-2">
            {csatTrend.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-200/80 p-6 text-center text-sm text-muted-foreground dark:border-slate-800/60">
                No recent trend data.
              </div>
            ) : (
              csatTrend.map((point) => {
                const maxResponses = Math.max(csatTrendMaxResponses, 1);
                const widthPercent = Math.round((point.responses / maxResponses) * 100);
                return (
                  <div key={point.date} className="rounded-xl border border-slate-100/80 bg-slate-50/60 p-3 dark:border-slate-800 dark:bg-slate-900/40">
                    <div className="flex items-center justify-between text-xs font-semibold text-slate-600 dark:text-slate-300">
                      <span>{point.date}</span>
                      <span>
                        {point.average !== null && point.average !== undefined ? point.average.toFixed(2) : '—'} / 5
                      </span>
                    </div>
                    <div className="mt-2 h-1.5 rounded-full bg-white/70 dark:bg-slate-800">
                      <div
                        className="h-full rounded-full bg-linear-to-r from-blue-500 via-sky-500 to-emerald-400 transition-all"
                        style={{ width: `${widthPercent}%` }}
                      />
                    </div>
                    <div className="mt-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-400">
                      {point.responses} responses
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white/85 p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900/60">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Agent chat handling</div>
            <p className="text-sm text-muted-foreground">
              Chats closed in the last {csatStats?.agentWindowDays ?? 30} days.
            </p>
          </div>
          <Button size="sm" variant="outline" onClick={handleCsatRefresh} disabled={!token || csatRefreshing}>
            {csatRefreshing ? 'Refreshing…' : 'Refresh'}
          </Button>
        </div>
        <div className="mt-4 divide-y divide-slate-200 text-sm dark:divide-slate-800">
          {displayedAgentChatCounts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200/80 p-6 text-center text-sm text-muted-foreground dark:border-slate-800/60">
              No chats handled in this window.
            </div>
          ) : (
            displayedAgentChatCounts.map((agent, index) => {
              const sharePercent =
                csatStats?.total && csatStats.total > 0
                  ? Math.round((agent.chatsHandled / csatStats.total) * 100)
                  : null;
              return (
                <div key={agent.agentId} className="flex items-center justify-between py-3">
                  <div className="flex items-center gap-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-100 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                      #{index + 1}
                    </div>
                    <div>
                      <div className="font-semibold text-slate-800 dark:text-slate-100">{agent.name}</div>
                      <div className="text-xs text-muted-foreground">{sharePercent !== null ? `${sharePercent}% of surveys` : '—'}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-lg font-semibold text-slate-900 dark:text-white">{agent.chatsHandled}</div>
                    <div className="text-xs text-muted-foreground">Chats handled</div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  ) : activeView === 'departments' ? (
    <div className="space-y-6">
      <div className="rounded-3xl border border-emerald-200/70 bg-white/80 p-6 shadow-sm dark:border-emerald-900/40 dark:bg-slate-900/50">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white">Departments</h2>
            <p className="text-sm text-muted-foreground">
              Configure departments for routing and assign agents to each department.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={loadDepartments} disabled={departmentsLoading}>
              {departmentsLoading ? 'Loading…' : 'Reload'}
            </Button>
            <Button size="sm" variant="outline" onClick={() => setActiveView('workspace')}>
              Back to workspace
            </Button>
          </div>
        </div>
      </div>

      <Card className="border-none bg-emerald-50/70 shadow-md ring-1 ring-emerald-100 dark:bg-slate-900/70 dark:ring-slate-800">
        <CardHeader className="rounded-2xl bg-emerald-100/60 px-5 py-4">
          <CardTitle>Department Configuration</CardTitle>
          <p className="text-sm text-muted-foreground">
            Create, rename, or delete departments and assign agents. Changes apply immediately.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <Input
              value={newDepartmentName}
              onChange={(e) => setNewDepartmentName(e.target.value)}
              placeholder="New department name"
              disabled={createDepartmentBusy}
            />
            <Button
              size="sm"
              onClick={createDepartment}
              disabled={createDepartmentBusy || !newDepartmentName.trim()}
            >
              {createDepartmentBusy ? 'Creating…' : 'Create'}
            </Button>
          </div>

          {departments.length === 0 ? (
            <div className="text-sm text-muted-foreground">No departments configured.</div>
          ) : (
            <div className="space-y-3">
              {departments.map((dept) => {
                const members: DepartmentAgent[] = (dept.agentDepartments ?? []).map((m) => m.agent);
                const selectedAgentId = departmentAssignSelection[dept.id] || '';
                const isEditingName = typeof departmentEditName[dept.id] === 'string';
                const editNameValue = isEditingName ? departmentEditName[dept.id] : '';
                return (
                  <div key={dept.id} className="rounded-lg border border-border bg-background p-3">
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                      <div className="flex flex-col gap-2">
                        {isEditingName ? (
                          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                            <Input
                              value={editNameValue}
                              onChange={(e) => setDepartmentEditName((prev) => ({ ...prev, [dept.id]: e.target.value }))}
                              className="h-8 w-64"
                              disabled={departmentAdminBusyKey === `${dept.id}:rename`}
                            />
                            <div className="flex gap-2">
                              <Button
                                size="sm"
                                onClick={() => renameDepartment(dept.id)}
                                disabled={departmentAdminBusyKey === `${dept.id}:rename` || !editNameValue.trim()}
                              >
                                {departmentAdminBusyKey === `${dept.id}:rename` ? 'Saving…' : 'Save'}
                              </Button>
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() =>
                                  setDepartmentEditName((prev) => {
                                    const next = { ...prev };
                                    delete next[dept.id];
                                    return next;
                                  })
                                }
                                disabled={departmentAdminBusyKey === `${dept.id}:rename`}
                              >
                                Cancel
                              </Button>
                            </div>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2">
                            <div className="text-sm font-semibold text-foreground">{dept.name}</div>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2"
                              onClick={() => setDepartmentEditName((prev) => ({ ...prev, [dept.id]: dept.name }))}
                              disabled={departmentAdminBusyKey === `${dept.id}:delete`}
                            >
                              Rename
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              className="h-7 px-2"
                              onClick={() => deleteDepartment(dept.id)}
                              disabled={departmentAdminBusyKey === `${dept.id}:delete`}
                            >
                              {departmentAdminBusyKey === `${dept.id}:delete` ? 'Deleting…' : 'Delete'}
                            </Button>
                          </div>
                        )}
                      </div>

                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                        <Select
                          value={selectedAgentId}
                          onValueChange={(value) => setDepartmentAssignSelection((prev) => ({ ...prev, [dept.id]: value }))}
                        >
                          <SelectTrigger className="h-8 w-56">
                            <SelectValue placeholder="Add agent" />
                          </SelectTrigger>
                          <SelectContent>
                            {agents.map((a) => (
                              <SelectItem key={a.id} value={a.id}>
                                {(a.displayName || a.name || a.email) + (a.status ? ` (${a.status})` : '')}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Button
                          size="sm"
                          onClick={() => assignAgentToDepartment(dept.id, selectedAgentId)}
                          disabled={!selectedAgentId || departmentAdminBusyKey === `${dept.id}:assign`}
                        >
                          {departmentAdminBusyKey === `${dept.id}:assign` ? 'Adding…' : 'Add'}
                        </Button>
                      </div>
                    </div>

                    <div className="mt-3 flex flex-wrap gap-2">
                      {members.length === 0 ? (
                        <div className="text-xs text-muted-foreground">No agents assigned.</div>
                      ) : (
                        members.map((agent: DepartmentAgent) => {
                          const key = `${dept.id}:${agent.id}:remove`;
                          return (
                            <div
                              key={agent.id}
                              className="inline-flex items-center gap-2 rounded-full border border-border bg-background px-3 py-1 text-xs"
                            >
                              <span>
                                {agent.displayName || agent.name || agent.email}
                                {agent.status ? ` (${agent.status})` : ''}
                              </span>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-6 px-2"
                                onClick={() => unassignAgentFromDepartment(dept.id, agent.id)}
                                disabled={departmentAdminBusyKey === key}
                              >
                                {departmentAdminBusyKey === key ? 'Removing…' : 'Remove'}
                              </Button>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  ) : (
    <div className="rounded-3xl border border-dashed border-slate-200/80 bg-white/70 p-8 text-center text-slate-500 shadow-inner dark:border-slate-800 dark:bg-slate-900/40 dark:text-slate-300">
      <p className="text-base font-semibold text-slate-700 dark:text-white">
        {activeView === 'automations'
          ? 'Automations module in progress'
          : 'Organization settings coming soon'}
      </p>
      <p className="mt-2 text-sm text-muted-foreground">
        Switch back to the workspace to handle live chats and routing while we finish building the {activeView} experience.
      </p>
      <Button variant="outline" className="mt-4" onClick={() => setActiveView('workspace')}>
        Return to workspace
      </Button>
    </div>
  )}
      </main>
    </div>
  </div>
  );
}
