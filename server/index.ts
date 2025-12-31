import 'dotenv/config';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { prisma } from './prisma';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import nodemailer from 'nodemailer';
import { Status, AgentRole, type Prisma } from '@prisma/client';
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
const MAIL_SECRET_TOKEN_TTL_SECONDS = 10 * 60; // 10 minutes
const MAIL_SECRET_HEADER = 'x-mail-secret-token';
const MAIL_SECRET_SCOPE = 'mail-secret';
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
  transcriptIntro: string | null;
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
    const transcriptIntro = db?.transcriptIntro || null;
    return { host, port, secure, user, password, fromAddress, transcriptIntro };
  } catch (err) {
    console.error('resolveMailConfig error', err);
    return {
      host: SMTP_HOST || null,
      port: SMTP_PORT || 587,
      secure: SMTP_SECURE,
      user: SMTP_USER || null,
      password: SMTP_PASS || null,
      fromAddress: EMAIL_FROM || null,
      transcriptIntro: null,
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
type AuthenticatedRequest = express.Request & { agentId?: string };
type MailSecretTokenPayload = { agentId: string; scope: typeof MAIL_SECRET_SCOPE; iat: number; exp: number };

const signMailSecretToken = (agentId: string) =>
  jwt.sign({ agentId, scope: MAIL_SECRET_SCOPE } as const, JWT_SECRET, {
    expiresIn: MAIL_SECRET_TOKEN_TTL_SECONDS,
  });

const ensureMailSecretAccess = async (
  req: AuthenticatedRequest,
  res: express.Response,
  existing?: { integrationSecretHash: string | null } | null
): Promise<{ ok: boolean; hasSecret: boolean }> => {
  const record =
    existing ??
    (await prisma.mailSettings.findUnique({
      where: { id: 'default' },
      select: { integrationSecretHash: true },
    }));
  const hasSecret = Boolean(record?.integrationSecretHash);
  if (!hasSecret) return { ok: true, hasSecret: false };

  const token = (req.headers[MAIL_SECRET_HEADER] as string | undefined) ?? null;
  if (!token) {
    res.status(423).json({ error: 'Mail settings locked', hasSecret: true });
    return { ok: false, hasSecret: true };
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET) as MailSecretTokenPayload;
    if (payload.scope !== MAIL_SECRET_SCOPE || payload.agentId !== req.agentId) {
      res.status(401).json({ error: 'Invalid mail secret token', hasSecret: true });
      return { ok: false, hasSecret: true };
    }
    return { ok: true, hasSecret: true };
  } catch {
    res.status(401).json({ error: 'Invalid mail secret token', hasSecret: true });
    return { ok: false, hasSecret: true };
  }
};

const authMiddleware: express.RequestHandler = (req, res, next) => {
  const auth = req.headers.authorization as string | undefined;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.slice('Bearer '.length);
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtAgentPayload;
    (req as AuthenticatedRequest).agentId = decoded.agentId;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

const requireAdmin: express.RequestHandler = async (req, res, next) => {
  try {
    const agentId = (req as AuthenticatedRequest).agentId;
    if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
    const agent = await prisma.agent.findUnique({ where: { id: agentId }, select: { role: true } });
    if (!agent || agent.role !== AgentRole.ADMIN) return res.status(403).json({ error: 'Forbidden' });
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

app.get('/sessions', authMiddleware, async (req, res) => {
  const agentId = (req as any).agentId as string | undefined;
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  const statusRaw = typeof req.query.status === 'string' ? req.query.status.trim().toUpperCase() : '';
  const assignedRaw = (req.query.assigned as string | undefined)?.toLowerCase();
  const takeRaw = parseInt((req.query.take as string | undefined) ?? '25', 10);
  const take = Number.isFinite(takeRaw) ? Math.min(Math.max(takeRaw, 1), 200) : 25;

  const where: Prisma.ChatSessionWhereInput = {};
  if (statusRaw === 'OPEN' || statusRaw === 'CLOSED') {
    where.status = statusRaw as Status;
  }

  if (assignedRaw === 'me') {
    if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
    where.agentId = agentId;
  } else if (assignedRaw === 'unassigned') {
    where.agentId = null;
  } else if (assignedRaw === 'assigned') {
    where.agentId = { not: null };
  }

  if (q) {
    where.OR = [
      { issueType: { contains: q, mode: 'insensitive' } },
      {
        visitor: {
          is: {
            OR: [
              { name: { contains: q, mode: 'insensitive' } },
              { email: { contains: q, mode: 'insensitive' } },
            ],
          },
        },
      },
      { messages: { some: { content: { contains: q, mode: 'insensitive' } } } },
    ];
  }

  const sessions = await prisma.chatSession.findMany({
    where,
    orderBy: [{ updatedAt: 'desc' }],
    take,
    select: {
      id: true,
      status: true,
      issueType: true,
      closedReason: true,
      closedAt: true,
      offlineHandledAt: true,
      createdAt: true,
      updatedAt: true,
      visitor: { select: { id: true, name: true, email: true } },
      agent: { select: { id: true, name: true, email: true, displayName: true } },
      messages: {
        orderBy: { createdAt: 'desc' },
        take: 1,
        select: { content: true, role: true, createdAt: true },
      },
    },
  });

  res.json({ sessions });
});

app.post('/sessions/take-next', authMiddleware, async (req, res) => {
  const agentId = (req as any).agentId as string | undefined;
  if (!agentId) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const claimedSessionId = await prisma.$transaction(async (tx) => {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const next = await tx.chatSession.findFirst({
          where: {
            status: 'OPEN',
            agentId: null,
            botConversationId: null,
          },
          orderBy: { createdAt: 'asc' },
          select: { id: true },
        });
        if (!next?.id) return null;

        const updated = await tx.chatSession.updateMany({
          where: { id: next.id, status: 'OPEN', agentId: null },
          data: { agentId },
        });
        if (updated.count === 1) {
          await tx.sessionAssignment.create({ data: { sessionId: next.id, agentId } });
          return next.id;
        }
      }
      return null;
    });

    if (!claimedSessionId) return res.status(404).json({ error: 'No unassigned chats available' });

    const agent = await prisma.agent.findUnique({
      where: { id: agentId },
      select: { id: true, name: true, email: true, displayName: true },
    });

    io.to(sessionRoom(claimedSessionId)).emit('agent_joined', { sessionId: claimedSessionId, agent });
    io.to(agentsRoom).emit('session_assigned', { sessionId: claimedSessionId, agent });

    const room = sessionRoom(claimedSessionId);
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
      console.error('take-next sockets sync error', err);
    }

    const session = await prisma.chatSession.findUnique({
      where: { id: claimedSessionId },
      select: {
        id: true,
        status: true,
        issueType: true,
        closedReason: true,
        closedAt: true,
        offlineHandledAt: true,
        createdAt: true,
        updatedAt: true,
        visitor: { select: { id: true, name: true, email: true } },
        agent: { select: { id: true, name: true, email: true, displayName: true } },
        messages: {
          orderBy: { createdAt: 'desc' },
          take: 1,
          select: { content: true, role: true, createdAt: true },
        },
      },
    });

    return res.json({ ok: true, session });
  } catch (err) {
    console.error('take-next error', err);
    return res.status(500).json({ error: 'Failed to take next chat' });
  }
});

const buildVisitorName = (firstName?: string, lastName?: string, name?: string) => {
  const f = typeof firstName === 'string' ? firstName.trim() : '';
  const l = typeof lastName === 'string' ? lastName.trim() : '';
  const combined = `${f} ${l}`.trim();
  if (combined) return combined;
  const legacy = typeof name === 'string' ? name.trim() : '';
  return legacy || undefined;
};

const NAME_STOP_WORDS = new Set([
  'a',
  'an',
  'and',
  'are',
  'agent',
  'am',
  'be',
  'because',
  'but',
  'call',
  'called',
  'can',
  'cannot',
  'cant',
  'could',
  'do',
  'dont',
  'for',
  'from',
  'hello',
  'help',
  'hey',
  'hi',
  'how',
  'im',
  'i',
  'is',
  'its',
  'ive',
  'live',
  'me',
  'my',
  'name',
  'need',
  'never',
  'no',
  'not',
  'please',
  'so',
  'thanks',
  'thank',
  'then',
  'this',
  'to',
  'want',
  'wanna',
  'what',
  'when',
  'where',
  'who',
  'why',
  'with',
  'wont',
  'would',
  'you',
  'your',
]);

const NAME_LEAD_IN_WORDS = new Set(['my', 'name', 'is', 'im', 'i', 'am', 'this', 'its', 'it', 'call', 'called', 'me']);
const NAME_BOUNDARY_WORDS = new Set(['and', 'but', 'because', 'so', 'then', 'from', 'with', 'for', 'thanks', 'thank']);

const normalizeTokenKey = (word: string) => word.toLowerCase().replace(/[^a-z]/g, '');

const capitalizeWord = (word: string) => {
  if (!word) return '';
  return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
};

const extractNameFromMessage = (input: string): { first: string; fullName: string } | null => {
  if (!input) return null;
  const cleaned = input.replace(/[^a-zA-Z\s'-]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!cleaned) return null;
  const rawTokens = cleaned.split(' ').filter(Boolean);
  if (rawTokens.length < 2) return null;
  const tokens = [...rawTokens];
  while (tokens.length && NAME_LEAD_IN_WORDS.has(normalizeTokenKey(tokens[0]))) {
    tokens.shift();
  }
  if (tokens.length < 2) return null;
  const nameTokens: string[] = [];
  for (const token of tokens) {
    const normalizedKey = normalizeTokenKey(token);
    if (!normalizedKey) continue;
    if (NAME_BOUNDARY_WORDS.has(normalizedKey)) break;
    if (!/^[a-zA-Z][a-zA-Z'-]*$/.test(token)) continue;
    nameTokens.push(token);
    if (nameTokens.length === 4) break;
  }
  if (nameTokens.length < 2) return null;
  const normalized = nameTokens.map(capitalizeWord);
  const stopwordHits = normalized.filter((word) => NAME_STOP_WORDS.has(normalizeTokenKey(word)));
  if (stopwordHits.length > 0) return null;
  const [first, ...rest] = normalized;
  if (!first || rest.length === 0) return null;
  const fullName = `${first} ${rest.join(' ')}`.trim();
  return { first, fullName };
};

const QUICK_REPLY_LABELS = new Set(
  ['order status', 'warranty & repairs', 'warranty and repairs', 'machine setup'].map((label) => label.trim().toLowerCase())
);

const isQuickReplyMessage = (content: string | undefined | null) => {
  if (!content) return false;
  return QUICK_REPLY_LABELS.has(content.trim().toLowerCase());
};

const EMAIL_REGEX = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const EMAIL_VALIDATION_REGEX = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
const PHONE_REGEX = /(\+?\d[\d\s().-]{6,}\d)/;
const PHONE_VALIDATION_REGEX = /^\+?\d{10,15}$/;

const extractEmailFromMessage = (input: string): string | null => {
  if (!input) return null;
  const matches = input.match(EMAIL_REGEX);
  if (!matches || matches.length === 0) return null;
  const email = matches[0].trim().toLowerCase();
  return EMAIL_VALIDATION_REGEX.test(email) ? email : null;
};

const normalizePhoneNumber = (raw: string): string => {
  if (!raw) return raw;
  let normalized = raw.trim();
  normalized = normalized.replace(/[^\d+]/g, '');
  if (normalized.startsWith('00')) {
    normalized = `+${normalized.slice(2)}`;
  }
  return normalized;
};

const extractPhoneFromMessage = (input: string): string | null => {
  if (!input) return null;
  const match = input.match(PHONE_REGEX);
  if (!match) return null;
  const normalized = normalizePhoneNumber(match[1]);
  return PHONE_VALIDATION_REGEX.test(normalized) ? normalized : null;
};

const isValidEmail = (value?: string | null) => Boolean(value && EMAIL_VALIDATION_REGEX.test(value));
const isValidPhone = (value?: string | null) => Boolean(value && PHONE_VALIDATION_REGEX.test(normalizePhoneNumber(value)));

const looksLikeEmailInput = (input: string): boolean => Boolean(input && input.includes('@'));
const looksLikePhoneInput = (input: string): boolean => {
  if (!input) return false;
  const match = input.match(PHONE_REGEX);
  if (!match) return false;
  const normalized = normalizePhoneNumber(match[1]);
  return normalized.length >= 7;
};

const hintedPhoneInput = (input: string): boolean => {
  if (!input) return false;
  const digits = input.replace(/\D/g, '');
  return digits.length >= 3;
};

const requiresName = (session: { visitor?: { name?: string | null } | null }) => !session.visitor?.name;

const hasContactEmail = (session: { visitor?: { email?: string | null } | null }) =>
  isValidEmail(session.visitor?.email ?? null);

const hasContactPhone = (session: { contactPhone?: string | null; visitor?: { phone?: string | null } | null }) => {
  const candidate = session.contactPhone || session.visitor?.phone || null;
  return isValidPhone(candidate);
};

const markInitialEmailRequested = async (sessionId: string) => {
  const requestedAt = new Date();
  await prisma.chatSession.update({
    where: { id: sessionId },
    data: { initialEmailRequestedAt: requestedAt },
  });
  return requestedAt;
};

const markInitialPhoneRequested = async (sessionId: string) => {
  const requestedAt = new Date();
  await prisma.chatSession.update({
    where: { id: sessionId },
    data: { initialPhoneRequestedAt: requestedAt },
  });
  return requestedAt;
};

const promptForContactEmail = async (sessionId: string) => {
  const requestedAt = await markInitialEmailRequested(sessionId);
  await sendAgentSystemMessage(
    sessionId,
    "Before I loop in a teammate, what's the best email address to send updates?"
  );
  return requestedAt;
};

const promptForContactPhone = async (sessionId: string) => {
  const requestedAt = await markInitialPhoneRequested(sessionId);
  await sendAgentSystemMessage(
    sessionId,
    'Thanks! Could you also share the best phone number to reach you in case we get disconnected?'
  );
  return requestedAt;
};

const remindEmailNeeded = async (sessionId: string, alreadyRequested: boolean) => {
  if (alreadyRequested) {
    await sendAgentSystemMessage(sessionId, 'I still need an email address before I can bring in a live agent.');
    return null;
  }
  return promptForContactEmail(sessionId);
};

const remindPhoneNeeded = async (sessionId: string, alreadyRequested: boolean) => {
  if (alreadyRequested) {
    await sendAgentSystemMessage(sessionId, 'Please drop a phone number we can reach you at so I can connect you.');
    return null;
  }
  return promptForContactPhone(sessionId);
};

const needsEmail = (session: { visitor?: { email?: string | null } | null }) => !hasContactEmail(session);

const needsPhone = (session: { contactPhone?: string | null; visitor?: { phone?: string | null } | null }) =>
  !hasContactPhone(session);

const LIVE_AGENT_KEYWORDS = [
  'live agent',
  'human agent',
  'human help',
  'real person',
  'speak to an agent',
  'talk to an agent',
  'need live help',
  'need agent help',
  'connect me to an agent',
  'talk to a person',
];

const shouldAutoRequestHandoff = (message: string): boolean => {
  if (!message) return false;
  const normalized = message.toLowerCase();
  return LIVE_AGENT_KEYWORDS.some((keyword) => normalized.includes(keyword));
};

const requestHandoffForSession = async (sessionId: string) => {
  const session = await prisma.chatSession.findUnique({
    where: { id: sessionId },
    select: { id: true, createdAt: true, botMode: true, agentId: true, status: true },
  });
  if (!session) throw new Error('Session not found');
  if (session.status !== 'OPEN') throw new Error('Session is not open');
  const alreadyAssigned = Boolean(session.agentId);
  if (session.botMode !== 'HUMAN') {
    await prisma.chatSession.update({ where: { id: sessionId }, data: { botMode: 'HUMAN' } });
  }
  let queuePosition = 0;
  if (!alreadyAssigned) {
    const waitingSessions = await prisma.chatSession.findMany({
      where: { status: 'OPEN', botMode: 'HUMAN', agentId: null },
      orderBy: { createdAt: 'asc' },
      select: { id: true },
    });
    const index = waitingSessions.findIndex((s) => s.id === sessionId);
    queuePosition = index >= 0 ? index + 1 : waitingSessions.length > 0 ? waitingSessions.length : 1;
    console.log('[handoff] new_chat_available emitted', { sessionId, queuePosition });
    io.to(agentsRoom).emit('new_chat_available', { sessionId });
  }
  return { queuePosition, alreadyAssigned };
};

// POST /sessions: create a pending session (for widget pre-chat)
app.post('/sessions', async (req, res) => {
  const { visitorId, message, issueType, firstName, lastName, name, email } = req.body as {
    visitorId?: string;
    message?: string;
    issueType?: string;
    firstName?: string;
    lastName?: string;
    name?: string;
    email?: string };
  const visitorName = buildVisitorName(firstName, lastName, name);
  console.log('[HTTP] POST /sessions body', { hasVisitorId: !!visitorId, hasMessage: !!message, issueType, name: visitorName, email });
  const visitor = await prisma.visitor.create({ data: { name: visitorName, email } });

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
  await prisma.message.createMany({
    data: [
      {
        chatSessionId: session.id,
        role: 'AGENT',
        content: 'Hello! Welcome to Kangen Care Bot.',
      },
      {
        chatSessionId: session.id,
        role: 'AGENT',
        content: 'May I have your first and last name?',
      },
    ],
  });
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

// Admin: delete an agent
app.delete('/admin/agents/:id', authMiddleware, requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  try {
    if ((req as AuthenticatedRequest).agentId === targetId) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }
    const existing = await prisma.agent.findUnique({
      where: { id: targetId },
      select: { id: true },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Agent not found' });
    }

    await prisma.$transaction(async (tx) => {
      await tx.chatSession.updateMany({
        where: { agentId: targetId },
        data: { agentId: null },
      });
      await tx.message.updateMany({
        where: { agentId: targetId },
        data: { agentId: null },
      });
      await tx.sessionAssignment.deleteMany({
        where: { agentId: targetId },
      });
      await tx.agentDepartment.deleteMany({
        where: { agentId: targetId },
      });
      await tx.passwordResetToken.deleteMany({
        where: { agentId: targetId },
      });
      await tx.agent.delete({ where: { id: targetId } });
    });

    forceLogoutAgent(targetId).catch(() => {});
    return res.json({ ok: true });
  } catch (err) {
    console.error('admin agent delete error', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin: view current mail / SMTP settings (DB overrides env, but env used as fallback)
app.get('/admin/mail-settings', authMiddleware, requireAdmin, async (req, res) => {
  const guard = await ensureMailSecretAccess(req as AuthenticatedRequest, res);
  if (!guard.ok) return;
  try {
    const db = await prisma.mailSettings.findUnique({ where: { id: 'default' } });
    const cfg = await resolveMailConfig();
    res.json({
      host: db?.host ?? cfg.host ?? '',
      port: db?.port ?? cfg.port,
      secure: typeof db?.secure === 'boolean' ? db.secure : cfg.secure,
      user: db?.user ?? cfg.user ?? '',
      fromAddress: db?.fromAddress ?? cfg.fromAddress ?? '',
      transcriptIntro: db?.transcriptIntro ?? cfg.transcriptIntro ?? '',
      hasPassword: Boolean(db?.password || cfg.password),
      requiresSecret: guard.hasSecret,
    });
  } catch (err) {
    console.error('get /admin/mail-settings error', err);
    res.status(500).json({ error: 'Failed to load mail settings' });
  }
});

// Admin: update mail / SMTP settings
app.put('/admin/mail-settings', authMiddleware, requireAdmin, async (req, res) => {
  const guard = await ensureMailSecretAccess(req as AuthenticatedRequest, res);
  if (!guard.ok) return;
  const { host, port, secure, user, password, fromAddress, transcriptIntro } = req.body as {
    host?: string | null;
    port?: number | null;
    secure?: boolean | null;
    user?: string | null;
    password?: string | null;
    fromAddress?: string | null;
    transcriptIntro?: string | null;
  };
  try {
    const data: any = {
      host: host && host.trim().length > 0 ? host.trim() : null,
      port: typeof port === 'number' && Number.isFinite(port) ? port : null,
      secure: typeof secure === 'boolean' ? secure : false,
      user: user && user.trim().length > 0 ? user.trim() : null,
      fromAddress: fromAddress && fromAddress.trim().length > 0 ? fromAddress.trim() : null,
      transcriptIntro: transcriptIntro && transcriptIntro.trim().length > 0 ? transcriptIntro.trim() : null,
    };
    if (typeof password === 'string' && password.trim().length > 0) {
      data.password = password;
    }
    const createData = { id: 'default', ...data };
    await prisma.mailSettings.upsert({
      where: { id: 'default' },
      update: data,
      create: createData,
    });
    res.json({ ok: true, requiresSecret: guard.hasSecret });
  } catch (err) {
    console.error('put /admin/mail-settings error', err);
    res.status(500).json({ error: 'Failed to save mail settings' });
  }
});

app.post('/admin/mail-settings/unlock', authMiddleware, requireAdmin, async (req, res) => {
  const { secret } = req.body as { secret?: string };
  if (!secret || secret.trim().length === 0) {
    return res.status(400).json({ error: 'Integration password required' });
  }
  const record = await prisma.mailSettings.findUnique({
    where: { id: 'default' },
    select: { integrationSecretHash: true },
  });
  if (!record?.integrationSecretHash) {
    return res.status(404).json({ error: 'Integration password not configured' });
  }
  const ok = await bcrypt.compare(secret, record.integrationSecretHash);
  if (!ok) return res.status(401).json({ error: 'Invalid integration password' });
  const agentId = (req as AuthenticatedRequest).agentId!;
  const token = signMailSecretToken(agentId);
  res.json({ token, expiresIn: MAIL_SECRET_TOKEN_TTL_SECONDS });
});

app.put('/admin/mail-settings/secret', authMiddleware, requireAdmin, async (req, res) => {
  const { secret, currentSecret } = req.body as { secret?: string; currentSecret?: string | null };
  if (!secret || secret.trim().length < 8) {
    return res.status(400).json({ error: 'Integration password must be at least 8 characters' });
  }
  const record = await prisma.mailSettings.findUnique({
    where: { id: 'default' },
    select: { integrationSecretHash: true },
  });
  const hasSecret = Boolean(record?.integrationSecretHash);
  if (hasSecret) {
    let authorized = false;
    if (currentSecret && record?.integrationSecretHash) {
      authorized = await bcrypt.compare(currentSecret, record.integrationSecretHash);
    }
    if (!authorized) {
      const guard = await ensureMailSecretAccess(req as AuthenticatedRequest, res, record);
      if (!guard.ok) return;
    }
  }
  const hashed = await bcrypt.hash(secret.trim(), 12);
  await prisma.mailSettings.upsert({
    where: { id: 'default' },
    update: { integrationSecretHash: hashed },
    create: { id: 'default', integrationSecretHash: hashed },
  });
  res.json({ ok: true, requiresSecret: true });
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
  if (!transporter || !config.user || !config.password || !config.host) {
    console.error('transcripts/email missing SMTP config', { host: config.host, user: config.user });
    return res
      .status(503)
      .json({ error: 'Email service not configured. Check SMTP host, username, password, and from address.' });
  }
  const subject = `Chat transcript ${sessionId}`;
  const intro = config.transcriptIntro?.trim();
  const textBody = intro ? `${intro}\n\n${built.text}` : built.text;
  let htmlBody = built.html;
  if (intro) {
    const safeIntro = `<p>${escapeHtml(intro)}</p>`;
    if (htmlBody.includes('<hr/>')) {
      htmlBody = htmlBody.replace('<hr/>', `${safeIntro}<hr/>`);
    } else {
      htmlBody = htmlBody.replace('</body>', `${safeIntro}</body>`);
    }
  }
  try {
    await transporter.sendMail({
      from: config.fromAddress || EMAIL_FROM || config.user,
      to: emailTarget,
      subject,
      text: textBody,
      html: htmlBody,
    });
  } catch (e) {
    console.error('transcripts/email sendMail error', e);
    return res.status(502).json({ error: 'Failed to send email' });
  }
  res.json({ ok: true });
});

// POST /offline/message: store offline message for follow-up
app.post('/offline/message', async (req, res) => {
  const { firstName, lastName, name, email, issueType, message } = req.body as {
    firstName?: string;
    lastName?: string;
    name?: string;
    email?: string;
    issueType?: string;
    message: string;
  };
  if (!email || typeof email !== 'string' || !email.trim()) {
    return res.status(400).json({ error: 'Email is required for offline messages' });
  }
  const visitorName = buildVisitorName(firstName, lastName, name);
  const visitor = await prisma.visitor.create({ data: { name: visitorName, email } });
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

// Agent account creation (admin-only)
app.post('/register', authMiddleware, requireAdmin, async (req, res) => {
  const { email, password, name, displayName, phone, avatarUrl, role } = req.body as {
    email?: string;
    password?: string;
    name?: string;
    displayName?: string;
    phone?: string;
    avatarUrl?: string;
    role?: string;
  };
  const trimmedEmail = email?.trim();
  const trimmedName = name?.trim();
  if (!trimmedEmail || !password || !trimmedName) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPasswordValid(password)) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }
  const normalizedRole = typeof role === 'string' ? role.trim().toUpperCase() : null;
  const requestedRole =
    normalizedRole && (normalizedRole === AgentRole.ADMIN || normalizedRole === AgentRole.MANAGER)
      ? (normalizedRole as AgentRole)
      : AgentRole.AGENT;
  const existing = await prisma.agent.findUnique({ where: { email: trimmedEmail }, select: { id: true } });
  if (existing) return res.status(409).json({ error: 'Email already registered' });
  const hashed = await bcrypt.hash(password, 10);
  const agent = await prisma.agent.create({
    data: {
      email: trimmedEmail,
      name: trimmedName,
      password: hashed,
      displayName: displayName?.trim() || trimmedName,
      phone: phone?.trim() || undefined,
      role: requestedRole,
      avatarUrl: avatarUrl?.trim() || undefined,
    },
    select: { id: true, email: true, name: true, displayName: true, phone: true, avatarUrl: true, status: true, role: true },
  });
  res.json({ agent });
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
    role: agent.role,
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
      select: { id: true, email: true, name: true, displayName: true, status: true, role: true },
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

const sendAgentSystemMessage = async (sessionId: string, content: string) => {
  const message = await prisma.message.create({
    data: { chatSessionId: sessionId, role: 'AGENT', content },
  });
  io.to(sessionRoom(sessionId)).emit('new_message', {
    ...message,
    sessionId: message.chatSessionId,
  });
  return message;
};

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
      const agentIdForSocket = socket.data.agentId as string | undefined;
      if (agentIdForSocket && (payload.status === 'ONLINE' || payload.status === 'OFFLINE')) {
        prisma.agent
          .update({ where: { id: agentIdForSocket }, data: { status: payload.status } })
          .catch((err) => console.error('presence_update status update error', err));
      }
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
        const chatSessionBaseSelect = {
          id: true,
          botConversationId: true,
          botMode: true,
          visitorId: true,
          contactPhone: true,
          distributorId: true,
          handoffInfoRequestedAt: true,
          handoffInfoProvidedAt: true,
          initialEmailRequestedAt: true,
          initialPhoneRequestedAt: true,
          visitor: { select: { id: true, name: true, email: true, phone: true } },
        } as const satisfies Prisma.ChatSessionSelect;
        const chatSession = await prisma.chatSession.findUnique({
          where: { id: payload.sessionId },
          select: chatSessionBaseSelect,
        });
        if (!chatSession) {
          if (typeof callback === 'function') callback({ error: 'Session not found' });
          return;
        }
        type ChatSessionState = Prisma.ChatSessionGetPayload<{ select: typeof chatSessionBaseSelect }>;
        const sessionSnapshot: ChatSessionState = chatSession;
        type VisitorState = {
          id: string;
          name: string | null;
          email: string | null;
          phone: string | null;
        };
        const toVisitorState = (visitor: ChatSessionState['visitor']) =>
          visitor ? { id: visitor.id, name: visitor.name, email: visitor.email, phone: visitor.phone ?? null } : null;
        let visitorState: VisitorState | null =
          toVisitorState(sessionSnapshot.visitor) ??
          (sessionSnapshot.visitorId ? { id: sessionSnapshot.visitorId, name: null, email: null, phone: null } : null);
        let contactPhoneState: string | null = sessionSnapshot.contactPhone ?? null;
        let distributorIdState: string | null = sessionSnapshot.distributorId ?? null;
        let handoffInfoRequestedAt: Date | null = sessionSnapshot.handoffInfoRequestedAt ?? null;
        let handoffInfoProvidedAt: Date | null = sessionSnapshot.handoffInfoProvidedAt ?? null;
        let botModeState: string | null = sessionSnapshot.botMode ?? null;
        let initialEmailRequestedAt: Date | null = sessionSnapshot.initialEmailRequestedAt ?? null;
        let initialPhoneRequestedAt: Date | null = sessionSnapshot.initialPhoneRequestedAt ?? null;
        type ContactState = { contactPhone?: string | null; visitor?: { email?: string | null; phone?: string | null } | null };
        const contactState = (): ContactState => ({
          contactPhone: contactPhoneState,
          visitor: visitorState ? { email: visitorState.email, phone: visitorState.phone } : null,
        });

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
        let parsedName: { first: string; fullName: string } | null = null;
        const isQuickReply = payload.role === 'USER' ? isQuickReplyMessage(payload.content) : false;
        const missingName = payload.role === 'USER' && visitorState && !visitorState.name;
        if (missingName) {
          const visitorId = chatSession.visitorId;
          if (!visitorId) {
            if (typeof callback === 'function') callback({ error: 'Visitor missing' });
            return;
          }
          if (isQuickReply) {
            const reminderMsg = await prisma.message.create({
              data: {
                chatSessionId: payload.sessionId,
                role: 'AGENT',
                content: 'Before we continue, may I have your first and last name?',
              },
            });
            io.to(sessionRoom(payload.sessionId)).emit('new_message', {
              ...reminderMsg,
              sessionId: reminderMsg.chatSessionId,
            });
            if (typeof callback === 'function') callback({ ok: true });
            return;
          }
          parsedName = extractNameFromMessage(payload.content);
          if (parsedName) {
            await prisma.visitor.update({
              where: { id: visitorId },
              data: { name: parsedName.fullName },
            });
            const greeting = `Nice to meet you, ${parsedName.first}! How can I assist you today?`;
            const greetingMsg = await prisma.message.create({
              data: { chatSessionId: payload.sessionId, role: 'AGENT', content: greeting },
            });
            io.to(sessionRoom(payload.sessionId)).emit('new_message', {
              ...greetingMsg,
              sessionId: greetingMsg.chatSessionId,
            });
            if (visitorState) {
              visitorState = { ...visitorState, name: parsedName.fullName };
            } else if (visitorId) {
              visitorState = { id: visitorId, name: parsedName.fullName, email: null, phone: null };
            }
          } else {
            const reminderMsg = await prisma.message.create({
              data: {
                chatSessionId: payload.sessionId,
                role: 'AGENT',
                content: 'Before we continue, may I have your first and last name?',
              },
            });
            io.to(sessionRoom(payload.sessionId)).emit('new_message', {
              ...reminderMsg,
              sessionId: reminderMsg.chatSessionId,
            });
            if (typeof callback === 'function') callback({ ok: true });
            return;
          }
        }
        const shouldSkipBotForward = Boolean(parsedName);
        const sessionHasName = Boolean(visitorState?.name);
        const needsHandoffInfo = sessionHasName && shouldAutoRequestHandoff(payload.content);
        console.debug('[send_message] parsedName:', parsedName, 'sessionHasName:', sessionHasName, 'needsHandoffInfo:', needsHandoffInfo, 'content:', payload.content);
        if (needsHandoffInfo) {
          const alreadyRequestedInfo = Boolean(handoffInfoRequestedAt);
          if (!alreadyRequestedInfo) {
            await prisma.chatSession.update({
              where: { id: payload.sessionId },
              data: { handoffInfoRequestedAt: new Date(), botMode: 'HUMAN' },
            });
            handoffInfoRequestedAt = new Date();
            botModeState = 'HUMAN';
            const emailPromptAt = await promptForContactEmail(payload.sessionId);
            initialEmailRequestedAt = emailPromptAt;
            await sendAgentSystemMessage(
              payload.sessionId,
              'Once I have your email, I’ll grab the best phone number to reach you (and distributor ID if you have one).'
            );
            io.to(sessionRoom(payload.sessionId)).emit('handoff_status', {
              sessionId: payload.sessionId,
              awaitingContactInfo: true,
            });
            if (typeof callback === 'function') callback({ ok: true });
            return;
          }
        }

        // After name is captured, collect email (first) and then phone before allowing handoff
        if (sessionHasName && sessionSnapshot.visitorId) {
          const emailMatch = extractEmailFromMessage(payload.content);
          if (emailMatch && needsEmail({ visitor: visitorState })) {
            await prisma.visitor.update({
              where: { id: sessionSnapshot.visitorId },
              data: { email: emailMatch },
            });
            visitorState = visitorState
              ? { ...visitorState, email: emailMatch }
              : { id: sessionSnapshot.visitorId, name: null, email: emailMatch, phone: null };
            await sendAgentSystemMessage(payload.sessionId, 'Thanks! I’ve got your email.');
            if (needsPhone(contactState()) && !initialPhoneRequestedAt) {
              const phonePromptAt = await promptForContactPhone(payload.sessionId);
              initialPhoneRequestedAt = phonePromptAt;
            }
          } else if (!emailMatch && needsEmail({ visitor: visitorState }) && looksLikeEmailInput(payload.content)) {
            await sendAgentSystemMessage(
              payload.sessionId,
              'I couldn’t validate that email. Mind double-checking the spelling so I can pass it to the live agent?'
            );
          }
          const emailReady = !needsEmail({ visitor: visitorState });
          const phoneMatch = extractPhoneFromMessage(payload.content);
          if (emailReady && phoneMatch && needsPhone(contactState())) {
            await prisma.chatSession.update({
              where: { id: payload.sessionId },
              data: { contactPhone: phoneMatch },
            });
            contactPhoneState = phoneMatch;
            await sendAgentSystemMessage(payload.sessionId, 'Got it—thanks for the phone number.');
          } else if (!emailReady && phoneMatch && needsPhone(contactState())) {
            await sendAgentSystemMessage(
              payload.sessionId,
              'Appreciate that! I just need your email first, then I’ll grab the phone number.'
            );
          }
          // If user asked for handoff and we still need email/phone, prompt for them
          if (needsHandoffInfo) {
            if (needsEmail({ visitor: visitorState })) {
              const emailReminderAt = await remindEmailNeeded(
                payload.sessionId,
                Boolean(initialEmailRequestedAt)
              );
              if (emailReminderAt) initialEmailRequestedAt = emailReminderAt;
            } else if (needsPhone(contactState())) {
              const phoneReminderAt = await remindPhoneNeeded(
                payload.sessionId,
                Boolean(initialPhoneRequestedAt)
              );
              if (phoneReminderAt) initialPhoneRequestedAt = phoneReminderAt;
            }
            if (typeof callback === 'function') callback({ ok: true });
            return;
          }
        }

        if (handoffInfoRequestedAt && !handoffInfoProvidedAt && botModeState === 'HUMAN') {
          const extractedPhone = extractPhoneFromMessage(payload.content);
          const distributorMatch = payload.content.match(/\b\d{4,}\b/);
          const alreadyHasValidPhone = hasContactPhone(contactState());
          const phoneNowValid = alreadyHasValidPhone || Boolean(extractedPhone);

          if (needsEmail({ visitor: visitorState })) {
            const emailReminderAt = await remindEmailNeeded(
              payload.sessionId,
              Boolean(initialEmailRequestedAt)
            );
            if (emailReminderAt) initialEmailRequestedAt = emailReminderAt;
            if (typeof callback === 'function') callback({ ok: true });
            return;
          }

          if (!alreadyHasValidPhone && extractedPhone) {
            await prisma.chatSession.update({
              where: { id: payload.sessionId },
              data: { contactPhone: extractedPhone },
            });
            contactPhoneState = extractedPhone;
          }

          if (!phoneNowValid) {
            if (looksLikePhoneInput(payload.content) || hintedPhoneInput(payload.content)) {
              await sendAgentSystemMessage(
                payload.sessionId,
                'Hmm, that phone number doesn’t look valid. Could you send the full number with country code?'
              );
            } else {
              const phoneReminderAt = await remindPhoneNeeded(
                payload.sessionId,
                Boolean(initialPhoneRequestedAt)
              );
              if (phoneReminderAt) initialPhoneRequestedAt = phoneReminderAt;
            }
            if (typeof callback === 'function') callback({ ok: true });
            return;
          }

          if (distributorMatch) {
            await prisma.chatSession.update({
              where: { id: payload.sessionId },
              data: { distributorId: distributorMatch[0] },
            });
            distributorIdState = distributorMatch[0];
          }

          await prisma.chatSession.update({
            where: { id: payload.sessionId },
            data: { handoffInfoProvidedAt: new Date() },
          });
          handoffInfoProvidedAt = new Date();
          const confirmMsg = await prisma.message.create({
            data: {
              chatSessionId: payload.sessionId,
              role: 'AGENT',
              content: 'Thank you! I’m connecting you with a live agent now.',
            },
          });
          io.to(sessionRoom(payload.sessionId)).emit('new_message', { ...confirmMsg, sessionId: confirmMsg.chatSessionId });
          const { queuePosition } = await requestHandoffForSession(payload.sessionId);
          const queueMsg =
            typeof queuePosition === 'number'
              ? queuePosition <= 1
                ? 'You are next in the queue for a live agent.'
                : `You are #${queuePosition} in the queue for a live agent.`
              : 'A live agent will join shortly.';
          const queueNotice = await prisma.message.create({
            data: {
              chatSessionId: payload.sessionId,
              role: 'AGENT',
              content: queueMsg,
            },
          });
          io.to(sessionRoom(payload.sessionId)).emit('new_message', { ...queueNotice, sessionId: queueNotice.chatSessionId });
          console.log('[handoff] handoff_status emitted (info complete)', {
            sessionId: payload.sessionId,
            awaitingContactInfo: false,
            queuePosition,
          });
          io.to(sessionRoom(payload.sessionId)).emit('handoff_status', {
            sessionId: payload.sessionId,
            awaitingContactInfo: false,
            queuePosition,
          });
          if (typeof callback === 'function') callback({ ok: true });
          return;
        }

        if (payload.role === 'USER' && isM365AgentEnabled && !shouldSkipBotForward) {
          try {
            console.log('[M365] send_message: USER message received for session', payload.sessionId);
            if (!chatSession.botConversationId) {
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
    async (
      payload: { sessionId: string },
      callback?: (resp: { ok?: boolean; error?: string; queuePosition?: number }) => void
    ) => {
      try {
        const updated = await prisma.chatSession.update({
          where: { id: payload.sessionId },
          data: { botMode: 'HUMAN' },
          select: { id: true, createdAt: true, contactPhone: true, visitor: { select: { email: true, phone: true } } },
        });

        const awaitingContactInfo = !hasContactEmail({ visitor: updated.visitor }) || !hasContactPhone({ contactPhone: updated.contactPhone, visitor: updated.visitor });
        console.log('[handoff] request_handoff received', { sessionId: updated.id, awaitingContactInfo });

        // Determine this session's position in the live-agent queue.
        // Queue consists of OPEN sessions in HUMAN mode with no assigned agent, ordered by createdAt.
        const waitingSessions = await prisma.chatSession.findMany({
          where: { status: 'OPEN', botMode: 'HUMAN', agentId: null },
          orderBy: { createdAt: 'asc' },
          select: { id: true },
        });
        const index = waitingSessions.findIndex((s) => s.id === updated.id);
        const queuePosition = index >= 0 ? index + 1 : waitingSessions.length > 0 ? waitingSessions.length : 1;

        io.to(agentsRoom).emit('new_chat_available', { sessionId: updated.id });
        io.to(sessionRoom(updated.id)).emit('handoff_status', {
          sessionId: updated.id,
          awaitingContactInfo,
          queuePosition,
        });
        if (typeof callback === 'function') callback({ ok: true, queuePosition });
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
  const me = await prisma.agent.findUnique({
    where: { id: req.agentId },
    select: { id: true, email: true, name: true, displayName: true, phone: true, avatarUrl: true, status: true, role: true },
  });
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
  await emitAgentsDirectory();
  res.json({ ok: true, status: updated.status });
});

// ===== Routing & Directory Endpoints =====
// List agents (for transfer UI)
app.get('/agents', authMiddleware, async (_req, res) => {
  const agents = await prisma.agent.findMany({
    select: { id: true, email: true, name: true, displayName: true, status: true, phone: true, role: true },
  });
  res.json(agents);
});

app.put('/agents/:id/role', authMiddleware, requireAdmin, async (req, res) => {
  const { role } = req.body as { role?: string };
  const validRoles = ['ADMIN', 'MANAGER', 'AGENT'];
  if (!role || !validRoles.includes(role)) {
    return res.status(400).json({ error: 'Valid role required (ADMIN, MANAGER, AGENT)' });
  }
  try {
    const agentId = req.params.id;
    const updated = await prisma.agent.update({
      where: { id: agentId },
      data: { role: role as AgentRole },
      select: { id: true, email: true, name: true, displayName: true, status: true, role: true },
    });
    await emitAgentsDirectory();
    res.json(updated);
  } catch (err) {
    console.error('update agent role error', err);
    res.status(500).json({ error: 'Failed to update agent role' });
  }
});

// Departments minimal
app.post('/departments', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { name } = req.body as { name?: string };
    const normalized = name?.trim();
    if (!normalized) return res.status(400).json({ error: 'name required' });
    const existing = await prisma.department.findUnique({ where: { name: normalized } });
    if (existing) return res.status(409).json({ error: 'Department name already exists' });
    const dept = await prisma.department.create({ data: { name: normalized } });
    return res.json(dept);
  } catch (err) {
    console.error('create department error', err);
    return res.status(500).json({ error: 'Failed to create department' });
  }
});

app.get('/departments', authMiddleware, async (req: any, res) => {
  try {
    const agentId = req.agentId as string | undefined;
    let requesterRole: AgentRole | null = null;
    if (agentId) {
      const agent = await prisma.agent.findUnique({ where: { id: agentId }, select: { role: true } });
      requesterRole = agent?.role ?? null;
    }

    const query: any = {
      orderBy: { name: 'asc' },
    };
    if (requesterRole === AgentRole.ADMIN) {
      query.include = {
        agentDepartments: {
          include: {
            agent: { select: { id: true, email: true, name: true, displayName: true, status: true } },
          },
        },
      };
    }

    const depts = await prisma.department.findMany(query);
    return res.json(depts);
  } catch (err) {
    console.error('list departments error', err);
    return res.status(500).json({ error: 'Failed to load departments' });
  }
});

app.put('/departments/:id', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const departmentId = req.params.id;
    const { name } = req.body as { name?: string };
    const normalized = name?.trim();
    if (!normalized) return res.status(400).json({ error: 'name required' });
    const existing = await prisma.department.findUnique({ where: { name: normalized } });
    if (existing && existing.id !== departmentId) {
      return res.status(409).json({ error: 'Department name already exists' });
    }
    const updated = await prisma.department.update({ where: { id: departmentId }, data: { name: normalized } });
    return res.json(updated);
  } catch (err) {
    console.error('rename department error', err);
    return res.status(500).json({ error: 'Failed to rename department' });
  }
});

app.delete('/departments/:id', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const departmentId = req.params.id;
    await prisma.$transaction([
      prisma.agentDepartment.deleteMany({ where: { departmentId } }),
      prisma.department.delete({ where: { id: departmentId } }),
    ]);
    return res.json({ ok: true });
  } catch (err) {
    console.error('delete department error', err);
    return res.status(500).json({ error: 'Failed to delete department' });
  }
});

app.post('/departments/:id/agents', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { agentId, available } = req.body as { agentId?: string; available?: boolean };
    if (!agentId) return res.status(400).json({ error: 'agentId required' });
    const departmentId = req.params.id;
    const existing = await prisma.agentDepartment.findFirst({ where: { agentId, departmentId } });
    if (existing) return res.status(200).json(existing);
    const map = await prisma.agentDepartment.create({
      data: { agentId, departmentId, available: available ?? false },
    });
    return res.json(map);
  } catch (err) {
    console.error('assign agent department error', err);
    return res.status(500).json({ error: 'Failed to assign agent to department' });
  }
});

app.get('/me/departments', authMiddleware, async (req: any, res) => {
  const agentId = req.agentId as string | undefined;
  if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
  const assigned = await prisma.agentDepartment.findMany({
    where: { agentId },
    include: { department: true },
  });
  res.json(
    assigned.map((a) => ({
      id: a.department.id,
      name: a.department.name,
      available: a.available,
    }))
  );
});

app.post('/departments/:id/agents/me', authMiddleware, async (req: any, res) => {
  const agentId = req.agentId as string | undefined;
  if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const existing = await prisma.agentDepartment.findFirst({
      where: { agentId, departmentId: req.params.id },
    });
    if (!existing) {
      const dept = await prisma.department.findUnique({ where: { id: req.params.id } });
      if (!dept) return res.status(404).json({ error: 'Department not found' });
      const map = await prisma.agentDepartment.create({
        data: { agentId, departmentId: req.params.id, available: true },
      });
      res.json(map);
      return;
    }
    if (existing.available) return res.json(existing);
    const updated = await prisma.agentDepartment.update({
      where: { id: existing.id },
      data: { available: true },
    });
    res.json(updated);
  } catch (err) {
    console.error('assign self department error', err);
    res.status(500).json({ error: 'Failed to join department' });
  }
});

app.delete('/departments/:id/agents/me', authMiddleware, async (req: any, res) => {
  const agentId = req.agentId as string | undefined;
  if (!agentId) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const existing = await prisma.agentDepartment.findFirst({
      where: { agentId, departmentId: req.params.id },
    });
    if (!existing) return res.status(403).json({ error: 'You are not assigned to this department' });
    if (!existing.available) return res.json({ ok: true });
    await prisma.agentDepartment.update({
      where: { id: existing.id },
      data: { available: false },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('leave department error', err);
    res.status(500).json({ error: 'Failed to leave department' });
  }
});

app.delete('/departments/:id/agents/:agentId', authMiddleware, requireAdmin, async (req, res) => {
  try {
    await prisma.agentDepartment.deleteMany({
      where: { agentId: req.params.agentId, departmentId: req.params.id },
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error('unassign agent department error', err);
    return res.status(500).json({ error: 'Failed to unassign agent from department' });
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

app.get('/analytics/csat', authMiddleware, async (req, res) => {
  try {
    const trendWindowDays = (() => {
      const raw = Number.parseInt((req.query.days as string) ?? '14', 10);
      if (Number.isNaN(raw)) return 14;
      return Math.min(Math.max(raw, 3), 90);
    })();
    const agentWindowDays = (() => {
      const raw = Number.parseInt((req.query.agentDays as string) ?? '30', 10);
      if (Number.isNaN(raw)) return 30;
      return Math.min(Math.max(raw, 7), 120);
    })();
    const now = Date.now();
    const dayMs = 24 * 60 * 60 * 1000;
    const trendStart = new Date(now - (trendWindowDays - 1) * dayMs);
    const agentWindowStart = new Date(now - agentWindowDays * dayMs);

    const [aggregate, positive, recentFeedback, distributionGroup, agentGroup, firstAssignments] = await Promise.all([
      prisma.csatFeedback.aggregate({ _avg: { rating: true }, _count: { rating: true } }),
      prisma.csatFeedback.count({ where: { rating: { gte: 4 } } }),
      prisma.csatFeedback.findMany({
        where: { createdAt: { gte: trendStart } },
        select: { rating: true, createdAt: true },
      }),
      prisma.csatFeedback.groupBy({
        by: ['rating'],
        _count: { _all: true },
      }),
      prisma.chatSession.groupBy({
        by: ['agentId'],
        _count: { _all: true },
        where: {
          agentId: { not: null },
          closedAt: { gte: agentWindowStart },
          status: Status.CLOSED,
        },
      }),
      prisma.sessionAssignment.findMany({
        where: { assignedAt: { gte: agentWindowStart } },
        orderBy: { assignedAt: 'asc' },
        distinct: ['sessionId'],
        select: {
          sessionId: true,
          assignedAt: true,
          session: {
            select: { createdAt: true },
          },
        },
      }),
    ]);

    const distribution: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    distributionGroup.forEach((group) => {
      if (group.rating >= 1 && group.rating <= 5) {
        distribution[group.rating] = group._count._all;
      }
    });

    const trendBuckets = new Map<
      string,
      { totalRatings: number; sumRatings: number }
    >();
    recentFeedback.forEach((entry) => {
      const dateKey = entry.createdAt.toISOString().slice(0, 10);
      const bucket = trendBuckets.get(dateKey) ?? { totalRatings: 0, sumRatings: 0 };
      bucket.totalRatings += 1;
      bucket.sumRatings += entry.rating;
      trendBuckets.set(dateKey, bucket);
    });

    const trend: { date: string; average: number | null; responses: number }[] = [];
    for (let i = trendWindowDays - 1; i >= 0; i -= 1) {
      const dayDate = new Date(now - i * dayMs);
      const key = dayDate.toISOString().slice(0, 10);
      const bucket = trendBuckets.get(key);
      trend.push({
        date: key,
        average: bucket && bucket.totalRatings > 0 ? bucket.sumRatings / bucket.totalRatings : null,
        responses: bucket?.totalRatings ?? 0,
      });
    }

    const agentIds = agentGroup.map((group) => group.agentId).filter((id): id is string => Boolean(id));
    const agents =
      agentIds.length > 0
        ? await prisma.agent.findMany({
            where: { id: { in: agentIds } },
            select: { id: true, displayName: true, name: true, email: true },
          })
        : [];
    const agentChatCounts = agentGroup
      .filter((group) => group.agentId)
      .map((group) => {
        const agent = agents.find((a) => a.id === group.agentId);
        const label = agent?.displayName || agent?.name || agent?.email || 'Unknown agent';
        return {
          agentId: group.agentId as string,
          name: label,
          chatsHandled: group._count._all,
        };
      })
      .sort((a, b) => b.chatsHandled - a.chatsHandled);

    const waitDurationsMinutes = firstAssignments
      .map((assignment) => {
        const createdAt = assignment.session?.createdAt;
        if (!createdAt) return null;
        const durationMinutes = (assignment.assignedAt.getTime() - createdAt.getTime()) / (60 * 1000);
        return Number.isFinite(durationMinutes) && durationMinutes >= 0 ? durationMinutes : null;
      })
      .filter((value): value is number => value !== null);
    const averageWaitMinutes =
      waitDurationsMinutes.length > 0
        ? waitDurationsMinutes.reduce((sum, value) => sum + value, 0) / waitDurationsMinutes.length
        : null;
    const totalWindowMinutes = agentWindowDays * 24 * 60;
    const arrivalRatePerMinute =
      totalWindowMinutes > 0 ? firstAssignments.length / totalWindowMinutes : null;
    const averageQueueSizeEstimate =
      averageWaitMinutes !== null && arrivalRatePerMinute !== null ? arrivalRatePerMinute * averageWaitMinutes : null;

    return res.json({
      average: aggregate._avg.rating ?? null,
      total: aggregate._count.rating,
      positive,
      distribution,
      trend,
      period: {
        days: trendWindowDays,
        responses: recentFeedback.length,
      },
      agentChatCounts,
      agentWindowDays,
      averageWaitMinutes,
      averageQueueSize: averageQueueSizeEstimate,
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
