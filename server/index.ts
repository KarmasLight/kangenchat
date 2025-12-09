import 'dotenv/config';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { prisma } from './prisma';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import nodemailer from 'nodemailer';
import { randomBytes, createHash } from 'crypto';
import { isM365AgentEnabled, startM365Conversation, sendMessageToM365 } from './m365AgentClient';

const JWT_SECRET: string = process.env.JWT_SECRET || 'dev-secret';
const COPILOT_API_KEY: string | undefined = process.env.COPILOT_API_KEY;

const STALE_SESSION_MINUTES = parseInt(process.env.STALE_SESSION_MINUTES ?? '480', 10); // default 8 hours
const CLEANUP_INTERVAL_MINUTES =
  Number.isNaN(STALE_SESSION_MINUTES) || STALE_SESSION_MINUTES <= 0
    ? 0
    : Math.min(Math.max(Math.floor(STALE_SESSION_MINUTES / 2), 5), STALE_SESSION_MINUTES);
const FORCE_LOGOUT_SECRET = process.env.FORCE_LOGOUT_SECRET;
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
const SMTP_SECURE = process.env.SMTP_SECURE === 'true';
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@localhost';
const MIN_PASSWORD_LENGTH = 8;
const PASSWORD_RESET_TOKEN_EXP_MINUTES = (() => {
  const raw = parseInt(process.env.PASSWORD_RESET_TOKEN_EXP_MINUTES ?? '60', 10);
  return Number.isFinite(raw) && raw > 0 ? raw : 60;
})();
const FRONTEND_URL_BASE = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');

const app = express();
// Allow CORS for REST endpoints (e.g., /login) from the frontend origin
const normalizeOrigin = (s: string) => s.replace(/\/$/, '');
const baseAllowed = process.env.FRONTEND_URL
  ? [normalizeOrigin(process.env.FRONTEND_URL)]
  : ['http://localhost:3000', 'http://localhost:3001'];
const allowedOrigins = Array.from(
  new Set([
    ...baseAllowed,
    // Always allow common local dev variants
    'http://localhost:3000',
    'http://localhost:3001',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:3001',
  ].map((v) => normalizeOrigin(v)))
);

const isLocalhostAllowed = (origin: string) => {
  try {
    const u = new URL(origin);
    const hostOk = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    const portOk = u.port === '3000' || u.port === '3001';
    return hostOk && portOk;
  } catch {
    return false;
  }
};

// CORS must be applied before any body parsers to ensure preflight isn't blocked
const devMode = (process.env.NODE_ENV || 'development') !== 'production';
app.use(
  cors({
    origin: (origin, callback) => {
      if (devMode) return callback(null, true);
      if (!origin) return callback(null, true); // allow non-browser clients
      const norm = normalizeOrigin(origin) as string;
      if (allowedOrigins.includes(norm) || isLocalhostAllowed(norm)) return callback(null, true);
      return callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    credentials: true,
    // Let cors reflect requested headers automatically by not forcing allowedHeaders
    optionsSuccessStatus: 204,
  })
);

// Body parsers after CORS
app.use(express.json());

const hashResetToken = (token: string) => createHash('sha256').update(token).digest('hex');
const isPasswordValid = (password?: string | null) =>
  typeof password === 'string' && password.length >= MIN_PASSWORD_LENGTH;

type MailConfig = {
  host: string | null;
  port: number;
  secure: boolean;
  user: string | null;
  password: string | null;
  fromAddress: string | null;
};

const resolveMailConfig = async (): Promise<MailConfig> => {
  try {
    const db = await prisma.mailSettings.findUnique({ where: { id: 'default' } });
    const host = db?.host || SMTP_HOST || null;
    const port = db?.port || SMTP_PORT || 587;
    const secure = typeof db?.secure === 'boolean' ? db.secure : SMTP_SECURE;
    const user = db?.user || SMTP_USER || null;
    const password = db?.password || SMTP_PASS || null;
    const fromAddress = db?.fromAddress || EMAIL_FROM || null;
    return { host, port, secure, user, password, fromAddress };
  } catch (err) {
    console.error('resolveMailConfig error', err);
    return {
      host: SMTP_HOST || null,
      port: SMTP_PORT || 587,
      secure: SMTP_SECURE,
      user: SMTP_USER || null,
      password: SMTP_PASS || null,
      fromAddress: EMAIL_FROM || null,
    };
  }
};

const getEmailTransporter = async () => {
  const config = await resolveMailConfig();
  if (!config.host) {
    return { transporter: null as nodemailer.Transporter | null, config };
  }
  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: config.user ? { user: config.user, pass: config.password ?? '' } : undefined,
  });
  return { transporter, config };
};

// Helpers
type JwtAgentPayload = { agentId: string };
const authMiddleware = (req: any, res: any, next: any) => {
  const auth = req.headers.authorization as string | undefined;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.slice('Bearer '.length);
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtAgentPayload;
    (req as any).agentId = decoded.agentId;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

const requireAdmin: express.RequestHandler = async (req, res, next) => {
  try {
    const agentId = (req as any).agentId as string | undefined;
    if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
    const agent = await prisma.agent.findUnique({ where: { id: agentId }, select: { isAdmin: true } });
    if (!agent?.isAdmin) return res.status(403).json({ error: 'Forbidden' });
    return next();
  } catch (err) {
    console.error('requireAdmin error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

const escapeHtml = (s: string) =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const buildTranscript = async (sessionId: string): Promise<{ text: string; html: string } | null> => {
  const session = await prisma.chatSession.findUnique({
    where: { id: sessionId },
    select: {
      id: true,
      issueType: true,
      createdAt: true,
      closedAt: true,
      visitor: { select: { name: true, email: true } },
      agent: { select: { displayName: true, name: true, email: true } },
      messages: { orderBy: { createdAt: 'asc' }, select: { role: true, content: true, createdAt: true } },
    },
  });
  if (!session) return null;
  const headerLines = [
    `Session: ${session.id}`,
    session.issueType ? `Issue: ${session.issueType}` : undefined,
    `Visitor: ${session.visitor?.name || ''} ${session.visitor?.email || ''}`.trim(),
    `Started: ${session.createdAt.toISOString()}`,
    session.closedAt ? `Ended: ${session.closedAt.toISOString()}` : undefined,
  ].filter(Boolean) as string[];

  const textBody = session.messages
    .map((m) => `[${new Date(m.createdAt).toISOString()}] ${m.role}: ${m.content}`)
    .join('\n');
  const text = headerLines.join('\n') + '\n\n' + textBody + '\n';

  const htmlHeader = headerLines.map((l) => `<div>${escapeHtml(l)}</div>`).join('');
  const htmlBody = session.messages
    .map(
      (m) =>
        `<div><span style="color:#888">[${escapeHtml(new Date(m.createdAt).toISOString())}]</span> <strong>${escapeHtml(
          m.role
        )}:</strong> ${escapeHtml(m.content)}</div>`
    )
    .join('');
  const html = `<!doctype html><html><head><meta charset="utf-8" /><title>Transcript ${escapeHtml(
    session.id
  )}</title></head><body>${htmlHeader}<hr/>${htmlBody}</body></html>`;
  return { text, html };
};

// Simple health endpoint
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

// GET /agents/online: check if any agent is ONLINE
app.get('/agents/online', async (_req, res) => {
  const count = await prisma.agent.count({ where: { status: 'ONLINE' } });
  res.json({ online: count > 0, count });
});

// POST /sessions: create a pending session (for widget pre-chat)
app.post('/sessions', async (req, res) => {
  const { visitorId, message, issueType, name, email } = req.body as {
    visitorId?: string;
    message?: string;
    issueType?: string;
    name?: string;
    email?: string };
  console.log('[HTTP] POST /sessions body', { hasVisitorId: !!visitorId, hasMessage: !!message, issueType, name, email });
  const visitor = await prisma.visitor.create({ data: { name, email } });

  let botConversationId: string | null = null;
  if (isM365AgentEnabled) {
    try {
      botConversationId = await startM365Conversation();
    } catch (err) {
      console.error('startM365Conversation in /sessions error', err);
    }
  }

  const session = await prisma.chatSession.create({
    data: {
      visitorId: visitor.id,
      issueType,
      status: 'OPEN',
      botConversationId: botConversationId ?? null,
      botMode: botConversationId ? 'BOT' : null,
    },
    select: { id: true, visitorId: true, issueType: true, status: true, createdAt: true },
  });
  const trimmed = typeof message === 'string' ? message.trim() : '';
  if (trimmed.length > 0) {
    await prisma.message.create({
      data: { chatSessionId: session.id, role: 'USER', content: trimmed },
    });
  }
  console.log('[HTTP] POST /sessions created', {
    sessionId: session.id,
    visitorId: visitor.id,
    botConversationId,
    isM365AgentEnabled,
  });
  cleanupStaleSessions().catch((err) => console.error('cleanupStaleSessions post start error', err));
  // Only advertise the chat to live agents immediately if there is no active bot
  if (!botConversationId) {
    io.to(agentsRoom).emit('new_chat_available', { sessionId: session.id });
  }
  res.json({ sessionId: session.id, visitorId: visitor.id, session });
});

// POST /admin/force-logout: require shared secret, disconnect all agents
app.post('/admin/force-logout', async (req, res) => {
  if (!FORCE_LOGOUT_SECRET) {
    return res.status(503).json({ error: 'Force logout is not configured' });
  }
  const provided = (req.headers['x-force-logout-secret'] as string | undefined) ?? (req.body?.secret as string | undefined);
  if (!provided || provided !== FORCE_LOGOUT_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  await forceLogoutAllAgents();
  res.json({ ok: true });
});

// Admin: set another agent's password
app.post('/admin/agents/:id/password', authMiddleware, requireAdmin, async (req, res) => {
  const { newPassword } = req.body as { newPassword?: string };
  if (!isPasswordValid(newPassword)) {
    return res
      .status(400)
      .json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }
  try {
    const hashed = await bcrypt.hash(newPassword!, 10);
    const updated = await prisma.agent.update({
      where: { id: req.params.id },
      data: { password: hashed },
    });
    await prisma.passwordResetToken.deleteMany({ where: { agentId: req.params.id } });
    return res.json({ ok: true, agentId: updated.id });
  } catch (err) {
    if ((err as any)?.code === 'P2025') {
      return res.status(404).json({ error: 'Agent not found' });
    }
    console.error('admin password update error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin: remotely log an agent off
app.post('/admin/agents/:id/logout', authMiddleware, requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  try {
    const existing = await prisma.agent.findUnique({ where: { id: targetId }, select: { id: true } });
    if (!existing) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    await forceLogoutAgent(targetId);
    return res.json({ ok: true });
  } catch (err) {
    console.error('admin agent logout error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin: view current mail / SMTP settings (DB overrides env, but env used as fallback)
app.get('/admin/mail-settings', authMiddleware, requireAdmin, async (_req, res) => {
  try {
    const db = await prisma.mailSettings.findUnique({ where: { id: 'default' } });
    const cfg = await resolveMailConfig();
    res.json({
      host: db?.host ?? cfg.host ?? '',
      port: db?.port ?? cfg.port,
      secure: typeof db?.secure === 'boolean' ? db.secure : cfg.secure,
      user: db?.user ?? cfg.user ?? '',
      fromAddress: db?.fromAddress ?? cfg.fromAddress ?? '',
      hasPassword: Boolean(db?.password || cfg.password),
    });
  } catch (err) {
    console.error('get /admin/mail-settings error', err);
    res.status(500).json({ error: 'Failed to load mail settings' });
  }
});

// Admin: update mail / SMTP settings
app.put('/admin/mail-settings', authMiddleware, requireAdmin, async (req, res) => {
  const { host, port, secure, user, password, fromAddress } = req.body as {
    host?: string | null;
    port?: number | null;
    secure?: boolean | null;
    user?: string | null;
    password?: string | null;
    fromAddress?: string | null;
  };
  try {
    const data: any = {
      host: host && host.trim().length > 0 ? host.trim() : null,
      port: typeof port === 'number' && Number.isFinite(port) ? port : null,
      secure: typeof secure === 'boolean' ? secure : false,
      user: user && user.trim().length > 0 ? user.trim() : null,
      fromAddress: fromAddress && fromAddress.trim().length > 0 ? fromAddress.trim() : null,
    };
    if (typeof password === 'string' && password.trim().length > 0) {
      data.password = password;
    }
    await prisma.mailSettings.upsert({
      where: { id: 'default' },
      update: data,
      create: { id: 'default', ...data },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('put /admin/mail-settings error', err);
    res.status(500).json({ error: 'Failed to save mail settings' });
  }
});

// GET /sessions/:id: fetch session with visitor (for agents)
app.get('/sessions/:id', authMiddleware, async (req, res) => {
  const session = await prisma.chatSession.findUnique({
    where: { id: req.params.id },
    select: {
      id: true,
      issueType: true,
      status: true,
      createdAt: true,
      closedAt: true,
      closedReason: true,
      offlineHandledAt: true,
      offlineHandledBy: { select: { id: true, name: true, displayName: true, email: true } },
      visitor: { select: { id: true, name: true, email: true } },
      agent: { select: { id: true, name: true, email: true, displayName: true } },
      messages: {
        orderBy: { createdAt: 'asc' },
        select: { id: true, content: true, role: true, createdAt: true },
      },
    },
  });
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session);
});

// GET /sessions/:id/transcript: returns transcript as text or HTML (?format=html)
app.get('/sessions/:id/transcript', async (req, res) => {
  const built = await buildTranscript(req.params.id);
  if (!built) return res.status(404).json({ error: 'Session not found' });
  // Cache text version in Transcript table for auditing/quick email later
  try {
    await prisma.transcript.upsert({
      where: { sessionId: req.params.id },
      update: { content: built.text },
      create: { sessionId: req.params.id, content: built.text },
    });
  } catch {}
  const format = (req.query.format as string | undefined)?.toLowerCase();
  if (format === 'html') {
    res.set('Content-Type', 'text/html; charset=utf-8');
    return res.send(built.html);
  }
  res.set('Content-Type', 'text/plain; charset=utf-8');
  return res.send(built.text);
});

// POST /transcripts/email: { sessionId, toEmail? } emails transcript and records emailedAt
app.post('/transcripts/email', async (req, res) => {
  const { sessionId, toEmail } = req.body as { sessionId?: string; toEmail?: string };
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
  const session = await prisma.chatSession.findUnique({
    where: { id: sessionId },
    select: { id: true, visitor: { select: { email: true, name: true } } },
  });
  if (!session) return res.status(404).json({ error: 'Session not found' });
  const emailTarget = toEmail || session.visitor?.email;
  if (!emailTarget) return res.status(400).json({ error: 'No destination email available' });

  const built = await buildTranscript(sessionId);
  if (!built) return res.status(404).json({ error: 'Session not found' });

  // Ensure cached text content exists
  await prisma.transcript.upsert({
    where: { sessionId },
    update: { content: built.text, emailedTo: emailTarget, emailedAt: new Date() },
    create: { sessionId, content: built.text, emailedTo: emailTarget, emailedAt: new Date() },
  });

  const { transporter, config } = await getEmailTransporter();
  if (!transporter) {
    return res.status(503).json({ error: 'Email service not configured' });
  }
  const subject = `Chat transcript ${sessionId}`;
  try {
    await transporter.sendMail({
      from: config.fromAddress || EMAIL_FROM,
      to: emailTarget,
      subject,
      text: built.text,
      html: built.html,
    });
  } catch (e) {
    return res.status(502).json({ error: 'Failed to send email' });
  }
  res.json({ ok: true });
});

// POST /offline/message: store offline message for follow-up
app.post('/offline/message', async (req, res) => {
  const { name, email, issueType, message } = req.body as { name?: string; email?: string; issueType?: string; message: string };
  const visitor = await prisma.visitor.create({ data: { name, email } });
  // Store as a closed session with an initial message
  const session = await prisma.chatSession.create({
    data: { visitorId: visitor.id, issueType, status: 'CLOSED', closedReason: 'OFFLINE_MESSAGE', closedAt: new Date() },
  });
  await prisma.message.create({
    data: { chatSessionId: session.id, role: 'USER', content: message },
  });
  io.to(agentsRoom).emit('offline_message_created', { sessionId: session.id });
  res.json({ ok: true, sessionId: session.id, visitorId: visitor.id });
});

type CopilotTranscriptEntry = {
  from: 'user' | 'bot';
  text: string;
  timestamp?: string;
};

type CopilotEscalatePayload = {
  conversationId?: string;
  user?: {
    name?: string;
    email?: string;
  };
  issueType?: string;
  latestUserMessage?: string;
  transcript?: CopilotTranscriptEntry[];
  channel?: string;
  locale?: string;
  metadata?: Record<string, unknown>;
};

// Endpoint for Copilot Studio to escalate to a live KangenChat agent
app.post('/copilot/escalate', async (req, res) => {
  try {
    const providedKey = (req.headers['x-api-key'] as string | undefined) ?? undefined;
    if (!COPILOT_API_KEY || !providedKey || providedKey !== COPILOT_API_KEY) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const body = req.body as CopilotEscalatePayload;
    const { user, issueType, latestUserMessage, transcript } = body;

    const primaryUserText = latestUserMessage || transcript?.find((t) => t.from === 'user')?.text;
    if (!primaryUserText || !primaryUserText.trim()) {
      return res.status(400).json({ error: 'latestUserMessage or a user transcript entry is required' });
    }

    // Find or create visitor
    let visitor = null as Awaited<ReturnType<typeof prisma.visitor.create>> | null;
    if (user?.email) {
      visitor = await prisma.visitor.findFirst({ where: { email: user.email }, orderBy: { createdAt: 'asc' } });
    }
    if (!visitor) {
      visitor = await prisma.visitor.create({
        data: {
          name: user?.name,
          email: user?.email,
        },
      });
    }

    // Create a new open chat session
    const session = await prisma.chatSession.create({
      data: {
        visitorId: visitor.id,
        issueType: issueType || 'Copilot escalation',
        status: 'OPEN',
      },
      select: { id: true, visitorId: true },
    });

    // Seed initial messages so agents see context
    const messagesToSeed: { role: 'USER' | 'AGENT'; content: string }[] = [];

    if (Array.isArray(transcript) && transcript.length > 0) {
      transcript.forEach((entry) => {
        const normalizedText = (entry.text || '').trim();
        if (!normalizedText) return;
        const role = entry.from === 'user' ? 'USER' : 'AGENT';
        messagesToSeed.push({ role, content: normalizedText });
      });
    } else if (primaryUserText?.trim()) {
      messagesToSeed.push({ role: 'USER', content: primaryUserText.trim() });
    }

    for (const m of messagesToSeed) {
      await prisma.message.create({
        data: {
          chatSessionId: session.id,
          role: m.role,
          content: m.content,
        },
      });
    }

    // Notify agents that a new chat is available
    io.to(agentsRoom).emit('new_chat_available', { sessionId: session.id });

    const baseUrl = FRONTEND_URL_BASE;
    const webChatUrl = `${baseUrl}/widget?sessionId=${encodeURIComponent(session.id)}&visitorId=${encodeURIComponent(
      session.visitorId || ''
    )}`;
    const agentDashboardUrl = `${baseUrl}/agent?sessionId=${encodeURIComponent(session.id)}`;

    const queueMessage = 'I have created a live chat session. An agent will join shortly.';

    return res.json({
      status: 'created',
      sessionId: session.id,
      visitorId: session.visitorId,
      queueMessage,
      webChatUrl,
      agentDashboardUrl,
    });
  } catch (err) {
    console.error('copilot/escalate error', err);
    return res.status(500).json({ error: 'Failed to create live chat session' });
  }
});

// GET /offline/messages: list offline submissions for agents to follow-up
app.get('/offline/messages', authMiddleware, async (_req, res) => {
  const offlineSessions = await prisma.chatSession.findMany({
    where: { closedReason: 'OFFLINE_MESSAGE' },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      issueType: true,
      createdAt: true,
      offlineHandledAt: true,
      offlineHandledBy: { select: { id: true, name: true, displayName: true, email: true } },
      visitor: { select: { name: true, email: true } },
      messages: {
        where: { role: 'USER' },
        orderBy: { createdAt: 'asc' },
        select: { id: true, content: true, createdAt: true },
        take: 1,
      },
    },
  });
  res.json(offlineSessions);
});

// POST /offline/messages/:id/handle: mark offline submission handled
app.post('/offline/messages/:id/handle', authMiddleware, async (req: any, res) => {
  const agentId = req.agentId as string | undefined;
  if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
  const session = await prisma.chatSession.findUnique({ where: { id: req.params.id }, select: { closedReason: true } });
  if (!session || session.closedReason !== 'OFFLINE_MESSAGE') {
    return res.status(404).json({ error: 'Offline message not found' });
  }
  const updated = await prisma.chatSession.update({
    where: { id: req.params.id },
    data: { offlineHandledAt: new Date(), offlineHandledById: agentId },
    select: {
      id: true,
      offlineHandledAt: true,
      offlineHandledBy: { select: { id: true, name: true, displayName: true, email: true } },
    },
  });
  io.to(agentsRoom).emit('offline_message_handled', { sessionId: updated.id, agent: updated.offlineHandledBy });
  res.json(updated);
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { email, password, name, displayName, phone, avatarUrl } = req.body as {
    email: string; password: string; name: string; displayName?: string; phone?: string; avatarUrl?: string;
  };
  if (!email || !password || !name) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPasswordValid(password)) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }
  const existing = await prisma.agent.findUnique({ where: { email }, select: { id: true } });
  if (existing) return res.status(409).json({ error: 'Email already registered' });
  const hashed = await bcrypt.hash(password, 10);
  const agent = await prisma.agent.create({
    data: { email, name, password: hashed, displayName: displayName ?? name, phone, avatarUrl },
    select: { id: true, email: true, name: true, displayName: true, phone: true, avatarUrl: true, status: true, isAdmin: true }
  });
  const token = jwt.sign({ agentId: agent.id }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, agent });
});

// Login endpoint for agents
app.post('/login', async (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };
  if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });
  const agent = await prisma.agent.findUnique({ where: { email } });
  if (!agent || !(await bcrypt.compare(password, agent.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ agentId: agent.id }, JWT_SECRET, { expiresIn: '1h' });
  const agentPublic = {
    id: agent.id,
    email: agent.email,
    name: agent.name,
    displayName: agent.displayName,
    phone: agent.phone,
    avatarUrl: agent.avatarUrl,
    status: agent.status,
    isAdmin: agent.isAdmin,
  };
  res.json({ token, agent: agentPublic });
});

app.post('/password/forgot', async (req, res) => {
  const { email } = req.body as { email?: string };
  const trimmed = email?.trim();
  if (!trimmed) return res.status(400).json({ error: 'Email is required' });
  const { transporter, config } = await getEmailTransporter();
  if (!transporter) {
    return res.status(503).json({ error: 'Email service not configured' });
  }
  const agent = await prisma.agent.findUnique({ where: { email: trimmed } });
  if (!agent) {
    return res.json({ ok: true });
  }
  await prisma.passwordResetToken.deleteMany({ where: { agentId: agent.id } });
  const plainToken = randomBytes(32).toString('hex');
  const tokenHash = hashResetToken(plainToken);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_EXP_MINUTES * 60 * 1000);
  await prisma.passwordResetToken.create({
    data: { agentId: agent.id, tokenHash, expiresAt },
  });
  const resetUrl = `${FRONTEND_URL_BASE}/agent/auth/reset?token=${encodeURIComponent(plainToken)}&email=${encodeURIComponent(
    trimmed
  )}`;
  const subject = 'Reset your agent password';
  const textBody = `You requested a password reset. Use the link below to set a new password. If you did not request this, you can ignore this email.

${resetUrl}

This link will expire in ${PASSWORD_RESET_TOKEN_EXP_MINUTES} minutes.`;
  const htmlBody = `<!doctype html><html><body><p>You requested a password reset.</p><p><a href="${escapeHtml(
    resetUrl
  )}">Reset your password</a></p><p>If you did not request this, you can ignore this email.</p><p>This link will expire in ${PASSWORD_RESET_TOKEN_EXP_MINUTES} minutes.</p></body></html>`;
  try {
    await transporter.sendMail({ from: config.fromAddress || EMAIL_FROM, to: agent.email, subject, text: textBody, html: htmlBody });
  } catch (err) {
    console.error('password/forgot sendMail error', err);
    return res.status(502).json({ error: 'Failed to send reset email' });
  }
  res.json({ ok: true });
});

app.post('/password/reset', async (req, res) => {
  const { token, email, newPassword } = req.body as { token?: string; email?: string; newPassword?: string };
  if (!token) return res.status(400).json({ error: 'Token is required' });
  if (!isPasswordValid(newPassword)) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }
  const tokenHash = hashResetToken(token);
  const now = new Date();
  const record = await prisma.passwordResetToken.findFirst({
    where: { tokenHash, usedAt: null, expiresAt: { gt: now } },
    include: { agent: true },
  });
  if (!record || !record.agent) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }
  if (email && record.agent.email.toLowerCase() !== email.trim().toLowerCase()) {
    return res.status(400).json({ error: 'Invalid reset token for this email' });
  }
  const hashed = await bcrypt.hash(newPassword!, 10);
  await prisma.agent.update({ where: { id: record.agentId }, data: { password: hashed } });
  await prisma.passwordResetToken.update({ where: { id: record.id }, data: { usedAt: now } });
  await prisma.passwordResetToken.deleteMany({ where: { agentId: record.agentId, id: { not: record.id } } });
  res.json({ ok: true });
});

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: devMode
      ? true
      : (process.env.FRONTEND_URL
          ? [process.env.FRONTEND_URL]
          : ['http://localhost:3000', 'http://localhost:3001']),
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

const emitAgentsDirectory = async () => {
  try {
    const agents = await prisma.agent.findMany({
      orderBy: { displayName: 'asc' },
      select: { id: true, email: true, name: true, displayName: true, status: true },
    });
    io.to(agentsRoom).emit('agents_snapshot', { agents });
  } catch (err) {
    console.error('emitAgentsDirectory error', err);
  }
};

// Optional JWT for Socket.IO connections: if provided, attach agentId, otherwise allow
io.use((socket, next) => {
  const token = socket.handshake.auth?.token as string | undefined;
  if (!token) return next();
  jwt.verify(token, JWT_SECRET as string, (err: unknown, decoded: any) => {
    if (!err && decoded?.agentId) {
      socket.data.agentId = decoded.agentId as string;
    }
    next();
  });
});

// Room name helper
const sessionRoom = (sessionId: string) => `session:${sessionId}`;

// Agents room to notify available chats
const agentsRoom = 'agents';

const emitOpenSessionsSnapshot = async () => {
  try {
    const openSessions = await prisma.chatSession.findMany({
      where: { status: 'OPEN' },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        issueType: true,
        createdAt: true,
        visitor: { select: { id: true, name: true, email: true } },
        agent: { select: { id: true, name: true, email: true, displayName: true } },
      },
    });
    io.to(agentsRoom).emit('open_sessions_snapshot', { sessions: openSessions });
  } catch (err) {
    console.error('emitOpenSessionsSnapshot error', err);
  }
};

const agentConnectionIds = new Map<string, Set<string>>();

const forceLogoutAgent = async (agentId: string) => {
  // Disconnect all sockets for a specific agent and mark them OFFLINE
  for (const [socketId, activeSocket] of io.sockets.sockets) {
    const agentIdForSocket = activeSocket.data.agentId as string | undefined;
    if (!agentIdForSocket || agentIdForSocket !== agentId) continue;
    activeSocket.emit('force_logout', { reason: 'ADMIN_AGENT' });
    activeSocket.disconnect(true);
    const connections = agentConnectionIds.get(agentIdForSocket);
    if (connections) {
      connections.delete(socketId);
      if (connections.size === 0) {
        agentConnectionIds.delete(agentIdForSocket);
      } else {
        agentConnectionIds.set(agentIdForSocket, connections);
      }
    }
  }

  await prisma.agent.updateMany({
    where: { id: agentId },
    data: { status: 'OFFLINE' },
  });
  await emitAgentsDirectory();
};

const forceLogoutAllAgents = async () => {
  const affectedAgentIds = new Set<string>();
  for (const [socketId, activeSocket] of io.sockets.sockets) {
    const agentIdForSocket = activeSocket.data.agentId as string | undefined;
    if (!agentIdForSocket) continue;
    affectedAgentIds.add(agentIdForSocket);
    activeSocket.emit('force_logout', { reason: 'ADMIN_FORCE' });
    activeSocket.disconnect(true);
    const connections = agentConnectionIds.get(agentIdForSocket);
    if (connections) {
      connections.delete(socketId);
      if (connections.size === 0) {
        agentConnectionIds.delete(agentIdForSocket);
      } else {
        agentConnectionIds.set(agentIdForSocket, connections);
      }
    }
  }
  if (affectedAgentIds.size > 0) {
    await prisma.agent.updateMany({
      where: { id: { in: Array.from(affectedAgentIds) } },
      data: { status: 'OFFLINE' },
    });
    await emitAgentsDirectory();
  }
};

const cleanupStaleSessions = async () => {
  if (Number.isNaN(STALE_SESSION_MINUTES) || STALE_SESSION_MINUTES <= 0) return;
  try {
    const cutoff = new Date(Date.now() - STALE_SESSION_MINUTES * 60 * 1000);
    const staleSessions = await prisma.chatSession.findMany({
      where: {
        status: 'OPEN',
        createdAt: { lt: cutoff },
      },
      select: { id: true },
    });
    if (staleSessions.length === 0) return;
    await prisma.chatSession.updateMany({
      where: {
        status: 'OPEN',
        createdAt: { lt: cutoff },
      },
      data: {
        status: 'CLOSED',
        closedAt: new Date(),
        closedReason: 'STALE_TIMEOUT',
      },
    });
    staleSessions.forEach(({ id }) => {
      io.to(sessionRoom(id)).emit('chat_closed', { sessionId: id });
      io.to(agentsRoom).emit('chat_closed', { sessionId: id });
    });
    await emitOpenSessionsSnapshot();
  } catch (err) {
    console.error('cleanupStaleSessions error', err);
  }
};

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  const agentId = socket.data.agentId as string | undefined;
  if (agentId) {
    const existingConnections = agentConnectionIds.get(agentId) ?? new Set<string>();
    existingConnections.add(socket.id);
    agentConnectionIds.set(agentId, existingConnections);
  }

  // Agent registers themselves (for now we accept minimal payload and upsert Agent)
  socket.on('agent_register', async (payload: { email: string; name: string; password: string }, callback) => {
    try {
      const { email, name, password } = payload;
      const hashedPassword = await bcrypt.hash(password, 10);
      await prisma.agent.upsert({
        where: { email },
        create: { email, name, password: hashedPassword },
        update: { name, password: hashedPassword },
      });
      socket.join(agentsRoom);
      callback({ ok: true });
    } catch (err) {
      console.error('agent_register error', err);
      callback({ ok: false, error: 'failed' });
    }
  });

  // Agent declares readiness to receive chats (joins agents room)
  socket.on('agent_ready', async () => {
    socket.join(agentsRoom);
    try {
      await emitAgentsDirectory();
      await cleanupStaleSessions();
      const openSessions = await prisma.chatSession.findMany({
        where: { status: 'OPEN' },
        orderBy: { createdAt: 'asc' },
        select: {
          id: true,
          issueType: true,
          createdAt: true,
          visitor: { select: { id: true, name: true, email: true } },
          agent: { select: { id: true, name: true, email: true, displayName: true } },
        },
      });
      socket.emit('open_sessions_snapshot', { sessions: openSessions });
    } catch (err) {
      console.error('agent_ready snapshot error', err);
    }
  });

  // Agent updates presence: join/leave agents room accordingly
  socket.on('presence_update', (payload: { status: 'ONLINE' | 'OFFLINE' }) => {
    try {
      if (payload.status === 'ONLINE') {
        socket.join(agentsRoom);
      } else {
        socket.leave(agentsRoom);
      }
      emitAgentsDirectory();
    } catch (err) {
      console.error('presence_update error', err);
    }
  });

  // Visitor joins a session after pre-chat (passes sessionId and visitorId)
  socket.on('visitor_join', async (data: { sessionId: string; visitorId: string }, callback) => {
    try {
      socket.data.sessionId = data.sessionId;
      socket.data.visitorId = data.visitorId;
      socket.join(`session:${data.sessionId}`);
      // Optionally, you could verify the session exists and belongs to this visitor
      callback?.({ status: 'joined' });
    } catch (err) {
      console.error('visitor_join error', err);
      callback?.({ error: 'failed' });
    }
  });

  // Customer starts a chat (legacy, unused after pre-chat refactor)
  socket.on('start_chat', async (payload: { initialMessage?: string }) => {
    try {
      const session = await prisma.chatSession.create({ data: {} });
      const room = sessionRoom(session.id);
      socket.join(room);
      if (payload?.initialMessage) {
        await prisma.message.create({
          data: {
            chatSessionId: session.id,
            role: 'USER',
            content: payload.initialMessage,
          },
        });
        io.to(room).emit('new_message', {
          sessionId: session.id,
          role: 'USER',
          content: payload.initialMessage,
          createdAt: new Date().toISOString(),
        });
      }
      // Notify all agents that a new chat is available
      io.to(agentsRoom).emit('new_chat_available', { sessionId: session.id });
      socket.emit('chat_started', { sessionId: session.id });
    } catch (err) {
      console.error('start_chat error', err);
      socket.emit('chat_started', { error: 'failed' });
    }
  });

  // Any participant joins a session room (customer reconnect or agent after accepting)
  socket.on('join_session', async (payload: { sessionId: string }, callback?: (resp: { status?: string; error?: string }) => void) => {
    try {
      const room = sessionRoom(payload.sessionId);
      socket.join(room);
      socket.emit('session_joined', { sessionId: payload.sessionId });
      if (typeof callback === 'function') callback({ status: 'joined' });
    } catch (err) {
      console.error('join_session error', err);
      socket.emit('session_joined', { error: 'failed' });
      if (typeof callback === 'function') callback({ error: 'failed' });
    }
  });

  // Agent accepts a chat
  socket.on('agent_accept', async (payload: { sessionId: string }, callback) => {
    try {
      const agentId = socket.data.agentId; // From JWT middleware
      if (!agentId) return callback({ error: 'Unauthenticated' });
      await prisma.chatSession.update({
        where: { id: payload.sessionId },
        data: { agentId },
      });
      const room = sessionRoom(payload.sessionId);
      socket.join(room);
      // Fetch agent public info
      const agent = await prisma.agent.findUnique({ where: { id: agentId }, select: { id: true, name: true, email: true, displayName: true } });
      io.to(room).emit('agent_joined', { sessionId: payload.sessionId, agent });
      io.to(agentsRoom).emit('session_assigned', { sessionId: payload.sessionId, agent });
      callback({ ok: true });
    } catch (err) {
      console.error('agent_accept error', err);
      callback({ error: 'failed' });
    }
  });

  // Send a message in a session
  socket.on(
    'send_message',
    async (
      payload: { sessionId: string; role: 'USER' | 'AGENT'; content: string },
      callback?: (resp: { ok?: boolean; error?: string }) => void
    ) => {
      try {
        console.log('[send_message] payload', { sessionId: payload.sessionId, role: payload.role }, 'isM365AgentEnabled =', isM365AgentEnabled);
        const agentId = socket.data.agentId; // Ensure agent is authenticated if role is AGENT
        if (payload.role === 'AGENT' && !agentId) {
          if (typeof callback === 'function') callback({ error: 'Unauthenticated' });
          return;
        }
        if (payload.role === 'AGENT') {
          // Verify agent is assigned to this session
          const sess = await prisma.chatSession.findUnique({ where: { id: payload.sessionId }, select: { agentId: true } });
          if (!sess || sess.agentId !== agentId) {
            if (typeof callback === 'function') callback({ error: 'Not assigned to this session' });
            return;
          }
        }
        const msg = await prisma.message.create({
          data: {
            chatSessionId: payload.sessionId,
            role: payload.role,
            content: payload.content,
            agentId: payload.role === 'AGENT' ? agentId : undefined,
          },
        });
        io.to(sessionRoom(payload.sessionId)).emit('new_message', {
          ...msg,
          sessionId: msg.chatSessionId,
        });
        if (payload.role === 'USER' && isM365AgentEnabled) {
          try {
            console.log('[M365] send_message: USER message received for session', payload.sessionId);
            const chatSession = await prisma.chatSession.findUnique({
              where: { id: payload.sessionId },
              select: { id: true, botConversationId: true, botMode: true },
            });
            if (!chatSession) {
              console.log('[M365] send_message: no chatSession found for', payload.sessionId);
            } else if (!chatSession.botConversationId) {
              console.log('[M365] send_message: session has no botConversationId; skipping bot send', chatSession.id);
            } else if (chatSession.botMode !== 'BOT') {
              console.log('[M365] send_message: botMode is not BOT; current mode =', chatSession.botMode);
            } else if (chatSession.botConversationId) {
              console.log('[M365] send_message: forwarding message to Copilot conversation', chatSession.botConversationId);
              const replies = await sendMessageToM365(chatSession.botConversationId, payload.content);
              console.log('[M365] send_message: Copilot returned', replies.length, 'bot replies');
              for (const reply of replies) {
                if (!reply || typeof reply.text !== 'string' || !reply.text.trim()) continue;
                const botMsg = await prisma.message.create({
                  data: {
                    chatSessionId: payload.sessionId,
                    role: 'AGENT',
                    content: reply.text,
                  },
                });
                io.to(sessionRoom(payload.sessionId)).emit('new_message', {
                  ...botMsg,
                  sessionId: botMsg.chatSessionId,
                });
              }
            }
          } catch (botErr) {
            console.error('send_message M365 bot integration error', botErr);
          }
        }
        if (typeof callback === 'function') callback({ ok: true });
      } catch (err) {
        console.error('send_message error', err);
        if (typeof callback === 'function') callback({ error: 'failed' });
      }
    }
  );

  // User requests handoff from bot to live agent
  socket.on(
    'request_handoff',
    async (payload: { sessionId: string }, callback?: (resp: { ok?: boolean; error?: string }) => void) => {
      try {
        const updated = await prisma.chatSession.update({
          where: { id: payload.sessionId },
          data: { botMode: 'HUMAN' },
          select: { id: true },
        });
        io.to(agentsRoom).emit('new_chat_available', { sessionId: updated.id });
        if (typeof callback === 'function') callback({ ok: true });
      } catch (err) {
        console.error('request_handoff error', err);
        if (typeof callback === 'function') callback({ error: 'failed' });
      }
    }
  );

  // End a chat session
  socket.on('end_chat', async (payload: { sessionId: string }) => {
    try {
      await prisma.chatSession.update({ where: { id: payload.sessionId }, data: { status: 'CLOSED', closedAt: new Date() } });
      io.to(sessionRoom(payload.sessionId)).emit('chat_closed', { sessionId: payload.sessionId });
      io.to(agentsRoom).emit('chat_closed', { sessionId: payload.sessionId });
    } catch (err) {
      console.error('end_chat error', err);
      socket.emit('chat_closed', { error: 'failed' });
    }
  });

  // Fetch chat history for a session
  socket.on('get_chat_history', async (payload: { sessionId: string }, callback) => {
    try {
      const messages = await prisma.message.findMany({
        where: { chatSessionId: payload.sessionId },
        orderBy: { createdAt: 'asc' },
      });
      callback(
        messages.map((m) => ({
          ...m,
          sessionId: m.chatSessionId,
        }))
      );
    } catch (err) {
      console.error('get_chat_history error', err);
      callback([]);
    }
  });

  // Typing indicator events
  socket.on('typing', (payload: { sessionId: string; role: 'USER' | 'AGENT' }) => {
    socket.to(sessionRoom(payload.sessionId)).emit('user_typing', { sessionId: payload.sessionId, role: payload.role });
  });

  socket.on('stop_typing', (payload: { sessionId: string; role: 'USER' | 'AGENT' }) => {
    socket.to(sessionRoom(payload.sessionId)).emit('user_stop_typing', { sessionId: payload.sessionId, role: payload.role });
  });

  // Add notification events (simplified browser notifications)
  socket.on('notify_new_chat', (payload: { sessionId: string }) => {
    // For server-side, we emit events; client handles notification
    io.to(agentsRoom).emit('new_chat_notification', payload);
  });

  socket.on('notify_new_message', (payload: { sessionId: string; content: string }) => {
    io.to(sessionRoom(payload.sessionId)).emit('new_message_notification', payload);
  });

  socket.on('disconnect', async () => {
    console.log('User disconnected:', socket.id);
    const agentIdOnSocket = socket.data.agentId as string | undefined;
    if (agentIdOnSocket) {
      const connections = agentConnectionIds.get(agentIdOnSocket);
      if (connections) {
        connections.delete(socket.id);
        if (connections.size === 0) {
          agentConnectionIds.delete(agentIdOnSocket);
          try {
            await prisma.agent.update({ where: { id: agentIdOnSocket }, data: { status: 'OFFLINE' } });
          } catch (err) {
            console.error('disconnect status update error', err);
          }
        } else {
          agentConnectionIds.set(agentIdOnSocket, connections);
        }
      }
    }
    await emitAgentsDirectory();
  });
});

// REST endpoints requiring auth
app.get('/me', authMiddleware, async (req: any, res) => {
  const me = await prisma.agent.findUnique({ where: { id: req.agentId }, select: { id: true, email: true, name: true, displayName: true, phone: true, avatarUrl: true, status: true } });
  if (!me) return res.status(404).json({ error: 'Not found' });
  res.json(me);
});

app.put('/me', authMiddleware, async (req: any, res) => {
  const { name, displayName, phone, avatarUrl } = req.body as { name?: string; displayName?: string; phone?: string; avatarUrl?: string };
  const updated = await prisma.agent.update({ where: { id: req.agentId }, data: { name, displayName, phone, avatarUrl }, select: { id: true, email: true, name: true, displayName: true, phone: true, avatarUrl: true, status: true } });
  res.json(updated);
});

app.post('/me/password', authMiddleware, async (req: any, res) => {
  const { currentPassword, newPassword } = req.body as { currentPassword: string; newPassword: string };
  const agent = await prisma.agent.findUnique({ where: { id: req.agentId } });
  if (!agent) return res.status(404).json({ error: 'Not found' });
  const ok = await bcrypt.compare(currentPassword, agent.password);
  if (!ok) return res.status(400).json({ error: 'Current password incorrect' });
  if (!isPasswordValid(newPassword)) {
    return res.status(400).json({ error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }
  const hashed = await bcrypt.hash(newPassword, 10);
  await prisma.agent.update({ where: { id: req.agentId }, data: { password: hashed } });
  res.json({ ok: true });
});

app.post('/presence', authMiddleware, async (req: any, res) => {
  const { status } = req.body as { status: 'ONLINE' | 'OFFLINE' };
  if (status !== 'ONLINE' && status !== 'OFFLINE') return res.status(400).json({ error: 'Invalid status' });
  const updated = await prisma.agent.update({ where: { id: req.agentId }, data: { status } });
  res.json({ ok: true, status: updated.status });
});

// ===== Routing & Directory Endpoints =====
// List agents (for transfer UI)
app.get('/agents', authMiddleware, async (_req, res) => {
  const agents = await prisma.agent.findMany({ select: { id: true, email: true, name: true, displayName: true, status: true } });
  res.json(agents);
});

// Departments minimal
app.post('/departments', authMiddleware, async (req, res) => {
  const { name } = req.body as { name?: string };
  if (!name) return res.status(400).json({ error: 'name required' });
  const dept = await prisma.department.create({ data: { name } });
  res.json(dept);
});

app.get('/departments', authMiddleware, async (_req, res) => {
  const depts = await prisma.department.findMany({ orderBy: { name: 'asc' } });
  res.json(depts);
});

app.post('/departments/:id/agents', authMiddleware, async (req, res) => {
  const { agentId } = req.body as { agentId?: string };
  if (!agentId) return res.status(400).json({ error: 'agentId required' });
  try {
    const map = await prisma.agentDepartment.create({ data: { agentId, departmentId: req.params.id } });
    res.json(map);
  } catch (e) {
    res.status(400).json({ error: 'Failed to assign agent to department' });
  }
});

app.get('/me/departments', authMiddleware, async (req: any, res) => {
  const agentId = req.agentId as string | undefined;
  if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
  const assigned = await prisma.agentDepartment.findMany({
    where: { agentId },
    include: { department: true },
  });
  res.json(assigned.map((a) => a.department));
});

app.post('/departments/:id/agents/me', authMiddleware, async (req: any, res) => {
  const agentId = req.agentId as string | undefined;
  if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const existing = await prisma.agentDepartment.findFirst({
      where: { agentId, departmentId: req.params.id },
    });
    if (existing) return res.status(200).json(existing);
    const map = await prisma.agentDepartment.create({ data: { agentId, departmentId: req.params.id } });
    res.json(map);
  } catch (err) {
    console.error('assign self department error', err);
    res.status(500).json({ error: 'Failed to join department' });
  }
});

app.delete('/departments/:id/agents/me', authMiddleware, async (req: any, res) => {
  const agentId = req.agentId as string | undefined;
  if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await prisma.agentDepartment.deleteMany({ where: { agentId, departmentId: req.params.id } });
    res.json({ ok: true });
  } catch (err) {
    console.error('leave department error', err);
    res.status(500).json({ error: 'Failed to leave department' });
  }
});

// Assign/Transfer session to an agent
app.post('/sessions/:id/assign', authMiddleware, async (req, res) => {
  const { agentId } = req.body as { agentId?: string };
  if (!agentId) return res.status(400).json({ error: 'agentId required' });
  try {
    await prisma.chatSession.update({ where: { id: req.params.id }, data: { agentId } });
    await prisma.sessionAssignment.create({ data: { sessionId: req.params.id, agentId } });
    const agent = await prisma.agent.findUnique({ where: { id: agentId }, select: { id: true, name: true, email: true, displayName: true } });
    io.to(sessionRoom(req.params.id)).emit('agent_joined', { sessionId: req.params.id, agent });
    io.to(agentsRoom).emit('session_assigned', { sessionId: req.params.id, agent });
    const room = sessionRoom(req.params.id);
    try {
      const socketsInRoom = io.sockets.adapter.rooms.get(room);
      if (socketsInRoom) {
        for (const sid of socketsInRoom) {
          const s = io.sockets.sockets.get(sid);
          if (s && s.data?.agentId && s.data.agentId !== agentId) {
            s.leave(room);
          }
        }
      }
      for (const [sid, s] of io.sockets.sockets) {
        if (s.data?.agentId === agentId) {
          s.join(room);
        }
      }
    } catch (err) {
      console.error('assign sockets sync error', err);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('assign session error', e);
    res.status(400).json({ error: 'Failed to assign session' });
  }
});

app.post('/sessions/:id/csat', async (req, res) => {
  const { rating, comment } = req.body as { rating?: number; comment?: string };
  if (typeof rating !== 'number' || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'rating must be between 1 and 5' });
  }
  try {
    const existing = await prisma.csatFeedback.findUnique({ where: { sessionId: req.params.id } });
    if (existing) {
      await prisma.csatFeedback.update({
        where: { sessionId: req.params.id },
        data: { rating, comment },
      });
    } else {
      await prisma.csatFeedback.create({ data: { sessionId: req.params.id, rating, comment } });
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error('csat submission error', err);
    return res.status(500).json({ error: 'Failed to save rating' });
  }
});

app.get('/analytics/csat', authMiddleware, async (_req, res) => {
  try {
    const aggregate = await prisma.csatFeedback.aggregate({
      _avg: { rating: true },
      _count: { rating: true },
    });
    const positive = await prisma.csatFeedback.count({ where: { rating: { gte: 4 } } });
    return res.json({
      average: aggregate._avg.rating ?? null,
      total: aggregate._count.rating,
      positive,
    });
  } catch (err) {
    console.error('analytics csat error', err);
    return res.status(500).json({ error: 'Failed to load CSAT data' });
  }
});

app.post('/sessions/:id/transfer', authMiddleware, async (req, res) => {
  const { agentId, agentEmail } = req.body as { agentId?: string; agentEmail?: string };
  try {
    let targetId = agentId;
    if (!targetId && agentEmail) {
      const agent = await prisma.agent.findUnique({ where: { email: agentEmail }, select: { id: true } });
      if (!agent) return res.status(404).json({ error: 'Target agent not found' });
      targetId = agent.id;
    }
    if (!targetId) return res.status(400).json({ error: 'agentId or agentEmail required' });
    await prisma.chatSession.update({ where: { id: req.params.id }, data: { agentId: targetId } });
    await prisma.sessionAssignment.create({ data: { sessionId: req.params.id, agentId: targetId } });
    const agent = await prisma.agent.findUnique({ where: { id: targetId }, select: { id: true, name: true, email: true, displayName: true } });
    io.to(sessionRoom(req.params.id)).emit('agent_joined', { sessionId: req.params.id, agent });
    io.to(agentsRoom).emit('session_transferred', { sessionId: req.params.id, agent });
    // Move sockets: remove other agents from room, add target agent sockets
    const room = sessionRoom(req.params.id);
    try {
      const socketsInRoom = io.sockets.adapter.rooms.get(room);
      if (socketsInRoom) {
        for (const sid of socketsInRoom) {
          const s = io.sockets.sockets.get(sid);
          if (s && s.data?.agentId && s.data.agentId !== targetId) {
            s.leave(room);
          }
        }
      }
      // Join target agent sockets
      for (const [sid, s] of io.sockets.sockets) {
        if (s.data?.agentId === targetId) {
          s.join(room);
        }
      }
    } catch {}
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'Failed to transfer session' });
  }
});

const PORT = process.env.PORT || 3010;

httpServer.listen(PORT, () => {
  console.log(`Server listening on *:${PORT}`);
});

if (CLEANUP_INTERVAL_MINUTES > 0) {
  cleanupStaleSessions().catch((err) => console.error('initial cleanupStaleSessions error', err));
  setInterval(() => {
    cleanupStaleSessions().catch((err) => console.error('interval cleanupStaleSessions error', err));
  }, CLEANUP_INTERVAL_MINUTES * 60 * 1000);
}
