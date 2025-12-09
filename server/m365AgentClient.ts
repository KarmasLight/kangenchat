import 'dotenv/config';

export type M365BotReply = {
  text: string;
};

const DIRECTLINE_SECRET = process.env.DIRECTLINE_SECRET || '';
const DIRECTLINE_API = 'https://directline.botframework.com/v3/directline';

/**
 * Returns true if DirectLine is configured
 */
export const isM365AgentEnabled = Boolean(DIRECTLINE_SECRET);

console.log('[DirectLine] isM365AgentEnabled at startup =', isM365AgentEnabled,
  'secret =', DIRECTLINE_SECRET ? '(set)' : '(not set)'
);

// Cache conversation IDs per session
const conversationCache = new Map<string, string>();

/**
 * Start a new conversation with Copilot Studio via DirectLine.
 */
export async function startM365Conversation(): Promise<string | null> {
  if (!isM365AgentEnabled) {
    console.warn('[DirectLine] startM365Conversation called but integration is not enabled');
    return null;
  }

  try {
    console.log('[DirectLine] Starting new conversation...');
    
    const response = await fetch(`${DIRECTLINE_API}/conversations`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${DIRECTLINE_SECRET}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[DirectLine] Failed to start conversation:', response.status, errorText);
      return null;
    }

    const data = await response.json();
    const conversationId = data.conversationId;
    
    if (!conversationId) {
      console.error('[DirectLine] No conversationId in response:', data);
      return null;
    }

    console.log('[DirectLine] Started conversation:', conversationId);
    return conversationId;
  } catch (err) {
    console.error('[DirectLine] startM365Conversation error:', err);
    return null;
  }
}

/**
 * Send a user message to Copilot Studio via DirectLine and return bot replies.
 */
export async function sendMessageToM365(
  conversationId: string,
  text: string
): Promise<M365BotReply[]> {
  if (!isM365AgentEnabled) {
    console.warn('[DirectLine] sendMessageToM365 skipped: integration is not enabled');
    return [];
  }
  if (!conversationId) {
    console.warn('[DirectLine] sendMessageToM365 skipped: missing conversationId');
    return [];
  }
  if (!text.trim()) {
    return [];
  }

  try {
    console.log('[DirectLine] Sending message to conversation:', conversationId);

    // Send the message
    const sendResponse = await fetch(
      `${DIRECTLINE_API}/conversations/${conversationId}/activities`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${DIRECTLINE_SECRET}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'message',
          from: { id: 'user' },
          text: text,
        }),
      }
    );

    if (!sendResponse.ok) {
      const errorText = await sendResponse.text();
      console.error('[DirectLine] Failed to send message:', sendResponse.status, errorText);
      return [];
    }

    const sendData = await sendResponse.json();
    console.log('[DirectLine] Message sent, id:', sendData.id);

    // Poll for bot responses (with watermark tracking)
    const replies: M365BotReply[] = [];
    let watermark = conversationCache.get(conversationId) || '';
    const maxAttempts = 10;
    const pollInterval = 1000; // 1 second

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, pollInterval));

      const pollUrl = `${DIRECTLINE_API}/conversations/${conversationId}/activities${watermark ? `?watermark=${watermark}` : ''}`;
      const pollResponse = await fetch(pollUrl, {
        headers: {
          'Authorization': `Bearer ${DIRECTLINE_SECRET}`,
        },
      });

      if (!pollResponse.ok) {
        console.error('[DirectLine] Poll failed:', pollResponse.status);
        continue;
      }

      const pollData = await pollResponse.json();
      
      if (pollData.watermark) {
        watermark = pollData.watermark;
        conversationCache.set(conversationId, watermark);
      }

      const activities = pollData.activities || [];
      for (const activity of activities) {
        // Only process bot messages (not echoed user messages)
        if (
          activity.type === 'message' &&
          activity.from?.role === 'bot' &&
          activity.text &&
          activity.text.trim().length > 0
        ) {
          console.log('[DirectLine] Bot reply:', activity.text.substring(0, 100));
          replies.push({ text: activity.text.trim() });
        }
      }

      // If we got bot replies, we're done
      if (replies.length > 0) {
        break;
      }
    }

    console.log('[DirectLine] Total replies:', replies.length);
    return replies;
  } catch (err) {
    console.error('[DirectLine] sendMessageToM365 error:', err);
    return [];
  }
}
