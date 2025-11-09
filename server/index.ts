import 'dotenv/config';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { prisma } from './prisma';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';

const JWT_SECRET: string = process.env.JWT_SECRET || 'dev-secret';

const app = express();
app.use(express.json());
// Allow CORS for REST endpoints (e.g., /login) from the frontend origin
app.use(
  cors({
    origin: process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : ['http://localhost:3000', 'http://localhost:3001'],
    methods: ['GET', 'POST', 'OPTIONS'],
    credentials: true,
  })
);

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

// Simple health endpoint
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

// GET /agents/online: check if any agent is ONLINE
app.get('/agents/online', async (_req, res) => {
  const count = await prisma.agent.count({ where: { status: 'ONLINE' } });
  res.json({ online: count > 0, count });
});

// POST /sessions/start: create visitor and session from pre-chat
app.post('/sessions/start', async (req, res) => {
  const { name, email, issueType } = req.body as { name?: string; email?: string; issueType?: string };
  const visitor = await prisma.visitor.create({ data: { name, email } });
  const session = await prisma.chatSession.create({
    data: { visitorId: visitor.id, issueType, status: 'OPEN' },
    select: { id: true, visitorId: true, issueType: true, status: true, createdAt: true },
  });
  // Notify all agents that a new chat is available
  io.to(agentsRoom).emit('new_chat_available', { sessionId: session.id });
  res.json({ sessionId: session.id, visitorId: visitor.id, session });
});

// GET /sessions/:id: fetch session with visitor (for agents)
app.get('/sessions/:id', authMiddleware, async (req, res) => {
  const session = await prisma.chatSession.findUnique({
    where: { id: req.params.id },
    select: { id: true, issueType: true, status: true, createdAt: true, closedAt: true, visitor: { select: { id: true, name: true, email: true } } },
  });
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session);
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
  res.json({ ok: true, sessionId: session.id, visitorId: visitor.id });
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { email, password, name, displayName, phone, avatarUrl } = req.body as {
    email: string; password: string; name: string; displayName?: string; phone?: string; avatarUrl?: string;
  };
  if (!email || !password || !name) return res.status(400).json({ error: 'Missing required fields' });
  const existing = await prisma.agent.findUnique({ where: { email }, select: { id: true } });
  if (existing) return res.status(409).json({ error: 'Email already registered' });
  const hashed = await bcrypt.hash(password, 10);
  const agent = await prisma.agent.create({
    data: { email, name, password: hashed, displayName: displayName ?? name, phone, avatarUrl },
    select: { id: true, email: true, name: true, displayName: true, phone: true, avatarUrl: true, status: true }
  });
  const token = jwt.sign({ agentId: agent.id }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, agent });
});

// Login endpoint for agents
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
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
  };
  res.json({ token, agent: agentPublic });
});

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.FRONTEND_URL
      ? [process.env.FRONTEND_URL]
      : ['http://localhost:3000', 'http://localhost:3001'],
    methods: ['GET', 'POST'],
  },
});

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

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

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
  socket.on('agent_ready', () => {
    socket.join(agentsRoom);
  });

  // Agent updates presence: join/leave agents room accordingly
  socket.on('presence_update', (payload: { status: 'ONLINE' | 'OFFLINE' }) => {
    try {
      if (payload.status === 'ONLINE') {
        socket.join(agentsRoom);
      } else {
        socket.leave(agentsRoom);
      }
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
  socket.on('join_session', async (payload: { sessionId: string }) => {
    try {
      const room = sessionRoom(payload.sessionId);
      socket.join(room);
      socket.emit('session_joined', { sessionId: payload.sessionId });
    } catch (err) {
      console.error('join_session error', err);
      socket.emit('session_joined', { error: 'failed' });
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
      io.to(room).emit('agent_joined', { sessionId: payload.sessionId });
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
        const agentId = socket.data.agentId; // Ensure agent is authenticated if role is AGENT
        if (payload.role === 'AGENT' && !agentId) {
          if (typeof callback === 'function') callback({ error: 'Unauthenticated' });
          return;
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
        if (typeof callback === 'function') callback({ ok: true });
      } catch (err) {
        console.error('send_message error', err);
        if (typeof callback === 'function') callback({ error: 'failed' });
      }
    }
  );

  // End a chat session
  socket.on('end_chat', async (payload: { sessionId: string }) => {
    try {
      await prisma.chatSession.update({ where: { id: payload.sessionId }, data: { status: 'CLOSED', closedAt: new Date() } });
      io.to(sessionRoom(payload.sessionId)).emit('chat_closed', { sessionId: payload.sessionId });
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

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
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

const PORT = process.env.PORT || 3010;

httpServer.listen(PORT, () => {
  console.log(`Server listening on *:${PORT}`);
});
