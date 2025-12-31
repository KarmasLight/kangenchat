const { io } = require('socket.io-client');

const getArg = (name) => {
  const prefix = `--${name}=`;
  const match = process.argv.slice(2).find((arg) => arg.startsWith(prefix));
  return match ? match.slice(prefix.length) : undefined;
};

const BACKEND_URL = getArg('backend') || process.env.TEST_BACKEND_URL || 'http://localhost:5010';
const CONNECT_TIMEOUT_MS = parseInt(getArg('connectTimeout') || process.env.TEST_CONNECT_TIMEOUT || '5000', 10);
const MESSAGE_TIMEOUT_MS = parseInt(getArg('messageTimeout') || process.env.TEST_MESSAGE_TIMEOUT || '5000', 10);

if (!Number.isFinite(CONNECT_TIMEOUT_MS) || CONNECT_TIMEOUT_MS <= 0) {
  throw new Error('CONNECT_TIMEOUT_MS must be a positive integer');
}

if (!Number.isFinite(MESSAGE_TIMEOUT_MS) || MESSAGE_TIMEOUT_MS <= 0) {
  throw new Error('MESSAGE_TIMEOUT_MS must be a positive integer');
}

class MessageTracker {
  constructor() {
    this.entries = [];
    this.waiters = [];
    this.seq = 0;
  }

  push(message) {
    const entry = { seq: ++this.seq, message };
    this.entries.push(entry);
    this.waiters = this.waiters.filter((waiter) => {
      if (entry.seq <= waiter.afterSeq) {
        return true;
      }
      if (waiter.predicate(message)) {
        clearTimeout(waiter.timer);
        waiter.resolve(message);
        return false;
      }
      return true;
    });
  }

  getCursor() {
    return this.seq;
  }

  wait(predicate, timeoutMs, afterSeq) {
    const existing = this.entries.find((entry) => entry.seq > afterSeq && predicate(entry.message));
    if (existing) {
      return Promise.resolve(existing.message);
    }

    return new Promise((resolve, reject) => {
      const waiter = {
        predicate,
        afterSeq,
        resolve: (msg) => {
          this.waiters = this.waiters.filter((w) => w !== waiter);
          resolve(msg);
        },
        reject: (err) => {
          this.waiters = this.waiters.filter((w) => w !== waiter);
          reject(err);
        },
        timer: setTimeout(() => {
          waiter.reject(new Error('Timed out waiting for message'));
        }, timeoutMs),
      };
      this.waiters.push(waiter);
    });
  }

  clearWaiters() {
    this.waiters.forEach((waiter) => clearTimeout(waiter.timer));
    this.waiters = [];
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function createSession(visitorLabel) {
  const response = await fetch(`${BACKEND_URL}/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      issueType: 'EssentialTests',
      message: `Initial message from ${visitorLabel}`,
    }),
  });
  if (!response.ok) {
    throw new Error(`Failed to create session: ${response.status}`);
  }
  return response.json();
}

const onceConnected = (socket) =>
  new Promise((resolve, reject) => {
    const onConnect = () => {
      socket.off('connect_error', onError);
      resolve();
    };
    const onError = (err) => {
      socket.off('connect', onConnect);
      reject(err);
    };
    socket.once('connect', onConnect);
    socket.once('connect_error', onError);
  });

const emitWithAck = (socket, event, payload, timeoutMs = 4000) =>
  new Promise((resolve, reject) => {
    let finished = false;
    const timer = setTimeout(() => {
      if (finished) return;
      finished = true;
      reject(new Error(`Ack timeout for event ${event}`));
    }, timeoutMs);

    socket.emit(event, payload, (resp) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (resp && resp.error) {
        reject(new Error(resp.error));
      } else {
        resolve();
      }
    });
  });

const normalizeContent = (text = '') =>
  text
    .toLowerCase()
    .replace(/[’‘]/g, "'")
    .replace(/[“”]/g, '"');

const contentIncludes = (msg, substring) =>
  normalizeContent(msg.content).includes(substring.toLowerCase());

const essentialTests = [
  {
    name: 'quick-reply-requires-name',
    description: 'Quick replies should not satisfy the name prompt and must trigger a reminder.',
    run: async (ctx) => {
      const cursor = ctx.tracker.getCursor();
      await ctx.sendMessage('Warranty & repairs');
      await ctx.waitForBotMessage(
        (msg) => contentIncludes(msg, 'first and last name'),
        MESSAGE_TIMEOUT_MS,
        cursor
      );
    },
  },
  {
    name: 'manual-name-accepted',
    description: 'Providing a proper name should be acknowledged by the bot greeting.',
    run: async (ctx) => {
      const cursor = ctx.tracker.getCursor();
      await ctx.sendMessage('My name is Essential Tester');
      await ctx.waitForBotMessage(
        (msg) => normalizeContent(msg.content).startsWith('nice to meet you'),
        MESSAGE_TIMEOUT_MS,
        cursor
      );
    },
  },
  {
    name: 'handoff-contact-info-flow',
    description: 'Requesting a live agent should enforce email/phone order, validate inputs, and queue properly.',
    run: async (ctx) => {
      const waitForContent = (substring, afterSeq) =>
        ctx.waitForBotMessage(
          (msg) => contentIncludes(msg, substring),
          MESSAGE_TIMEOUT_MS,
          afterSeq
        );

      const handoffCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('I need a live agent');
      await waitForContent('once i have your email', handoffCursor);

      const phoneBeforeEmailCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('+1 222 333 4444');
      await waitForContent('need your email first', phoneBeforeEmailCursor);

      const invalidEmailCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('not-a-valid-email@foo');
      await waitForContent('validate that email', invalidEmailCursor);

      const emailCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('essential.test@example.com');
      await waitForContent('got your email', emailCursor);

      const invalidPhoneCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('12345');
      await ctx.waitForBotMessage(
        (msg) =>
          contentIncludes(msg, "phone number doesn't look valid") || contentIncludes(msg, 'please drop a phone number'),
        MESSAGE_TIMEOUT_MS,
        invalidPhoneCursor
      );

      const phoneCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('+1 555 867 5309');
      await waitForContent('thanks for the phone number', phoneCursor);

      const connectCursor = ctx.tracker.getCursor();
      await waitForContent('connecting you with a live agent', connectCursor);

      const queueCursor = ctx.tracker.getCursor();
      await ctx.waitForBotMessage(
        (msg) => contentIncludes(msg, 'queue for a live agent') || contentIncludes(msg, 'live agent will join shortly'),
        MESSAGE_TIMEOUT_MS,
        queueCursor
      );
    },
  },
];

async function runEssentialSuite() {
  console.log(`Running essential tests against ${BACKEND_URL}`);
  const { sessionId, visitorId } = await createSession('essential-test');

  const socket = io(BACKEND_URL, {
    transports: ['websocket'],
    timeout: CONNECT_TIMEOUT_MS,
    forceNew: true,
  });

  const tracker = new MessageTracker();
  socket.on('new_message', (message) => {
    tracker.push(message);
    if (process.env.ESSENTIAL_VERBOSE === '1' && message.role === 'AGENT') {
      console.log(`[AGENT] ${message.content}`);
    }
  });

  try {
    await onceConnected(socket);
    await emitWithAck(socket, 'visitor_join', { sessionId, visitorId });

    const ctx = {
      sessionId,
      visitorId,
      tracker,
      sendMessage: async (content) => {
        await emitWithAck(socket, 'send_message', { sessionId, role: 'USER', content });
        await delay(150);
      },
      waitForBotMessage: (predicate, timeoutMs = MESSAGE_TIMEOUT_MS, afterSeq = 0) =>
        tracker.wait((msg) => msg.role === 'AGENT' && predicate(msg), timeoutMs, afterSeq),
    };

    const results = [];

    for (const test of essentialTests) {
      try {
        await test.run(ctx);
        results.push({ name: test.name, description: test.description, status: 'PASS' });
        console.log(`✅ ${test.name}`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        results.push({ name: test.name, description: test.description, status: 'FAIL', details: message });
        console.error(`❌ ${test.name}: ${message}`);
        break;
      }
    }

    console.table(results);
    if (results.some((r) => r.status === 'FAIL')) {
      process.exitCode = 1;
    }
  } finally {
    tracker.clearWaiters();
    if (socket.connected) {
      socket.disconnect();
    }
  }
}

runEssentialSuite().catch((err) => {
  console.error('Essential test suite crashed', err);
  process.exit(1);
});
