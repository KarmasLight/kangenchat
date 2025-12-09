# Copilot Studio ⇄ KangenChat Integration Guide

This document explains how to connect a Microsoft Copilot Studio bot to the KangenChat live-agent backend so that Copilot handles chatbot/RAG and escalates to human agents in KangenChat when needed.

---

## 1. Backend requirements (KangenChat)

### 1.1. Endpoint `/copilot/escalate`

The KangenChat backend exposes this REST endpoint (already implemented in `server/index.ts`):

- **Method:** `POST`
- **Path:** `/copilot/escalate`
- **Headers:**
  - `Content-Type: application/json`
  - `x-api-key: <COPILOT_API_KEY>` (shared secret)

**Example request body:**

```json
{
  "conversationId": "copilot-conv-123",
  "user": {
    "name": "Jane Doe",
    "email": "jane@example.com"
  },
  "issueType": "billing",
  "latestUserMessage": "I was double charged last month.",
  "transcript": [
    { "from": "user", "text": "Hi, I need help with my bill." },
    { "from": "bot", "text": "Sure, what seems to be the issue?" },
    { "from": "user", "text": "I was double charged last month." }
  ],
  "channel": "CopilotStudio",
  "locale": "en-US"
}
```

**Behavior (server):**

1. Validates `x-api-key` against `process.env.COPILOT_API_KEY`.
2. Finds or creates a `Visitor` by email.
3. Creates a new `ChatSession` with `status = OPEN` and `issueType` or fallback `"Copilot escalation"`.
4. Seeds initial `Message` rows from `transcript` (mapping `from: "user"` → `role: "USER"`, `from: "bot"` → `role: "AGENT"`). If there is no transcript, seeds a single `USER` message from `latestUserMessage`.
5. Emits `new_chat_available` to `agentsRoom` so agents see the new chat in the dashboard.
6. Returns session details.

**Example success response:**

```json
{
  "status": "created",
  "sessionId": "sess_abc123",
  "visitorId": "vis_789",
  "queueMessage": "I have created a live chat session. An agent will join shortly.",
  "webChatUrl": "https://<FRONTEND_URL_BASE>/widget?sessionId=sess_abc123",
  "agentDashboardUrl": "https://<FRONTEND_URL_BASE>/agent?sessionId=sess_abc123"
}
```

### 1.2. Environment variables

On the backend host (e.g. Lightsail), set:

```env
# Internal backend port (Node/Express)
PORT=5010

# Public URLs
FRONTEND_URL=https://kangenchat.yourdomain.com
NEXT_PUBLIC_BACKEND_URL=https://api.kangenchat.yourdomain.com

# Copilot shared secret (used in x-api-key)
COPILOT_API_KEY=some-long-random-secret

# JWT / session security
JWT_SECRET=change_this_in_prod
FORCE_LOGOUT_SECRET=change_this_force_logout

# Database (adjust host/port/credentials for your Postgres instance)
DATABASE_NAME="kangenchatdb"
DATABASE_HOST="your-db-host.rds.amazonaws.com"
DATABASE_PORT="5432"
DATABASE_USER="postgres"
DATABASE_PASSWORD="yourStrongPassword"
DATABASE_URL="postgresql://postgres:yourStrongPassword@your-db-host.rds.amazonaws.com:5432/kangenchatdb?schema=public"

# Session cleanup
STALE_SESSION_MINUTES=10

# Default admin
DEFAULT_ADMIN_EMAIL=admin@example.com
DEFAULT_ADMIN_PASSWORD=admin123
DEFAULT_ADMIN_NAME=Admin User
```


## 2. Nginx / HTTPS setup (example)

Assuming KangenChat backend runs on `localhost:5010` and should be exposed as `https://api.kangenchat.yourdomain.com`.

Example Nginx config:

```nginx
server {
    listen 80;
    server_name api.kangenchat.yourdomain.com;
    # After issuing a cert with certbot, you can redirect HTTP to HTTPS:
    # return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.kangenchat.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/api.kangenchat.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.kangenchat.yourdomain.com/privkey.pem;

    client_max_body_size 10M;

    location / {
        proxy_pass         http://127.0.0.1:5010;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket / Socket.IO support
        proxy_set_header Upgrade           $http_upgrade;
        proxy_set_header Connection        "upgrade";

        proxy_read_timeout  600s;
        proxy_send_timeout  600s;
    }
}
```

Use Certbot to obtain SSL certificates:

```bash
sudo certbot --nginx -d api.kangenchat.yourdomain.com
```


## 3. Copilot Studio: custom connector

1. **Create a custom connector** (in Power Platform / Copilot Studio):
   - Name: `KangenChatEscalationConnector` (or similar).
   - Base URL: `https://api.kangenchat.yourdomain.com`.

2. **Security**:
   - Authentication type: **API key**.
   - Parameter name: `x-api-key`.
   - Location: `Header`.

3. **Operation definition**:
   - Operation name: `EscalateToLiveAgent`.
   - Method: `POST`.
   - Path: `/copilot/escalate`.
   - Request body schema (simplified):

     ```json
     {
       "conversationId": "string",
       "user": {
         "name": "string",
         "email": "string"
       },
       "issueType": "string",
       "latestUserMessage": "string"
     }
     ```

   - Response body schema:

     ```json
     {
       "status": "string",
       "sessionId": "string",
       "visitorId": "string",
       "queueMessage": "string",
       "webChatUrl": "string",
       "agentDashboardUrl": "string"
     }
     ```

4. **Test the connector**:
   - Provide the same `COPILOT_API_KEY` value as the API key.
   - Call `EscalateToLiveAgent` with a sample body.
   - Verify a `200` response and that a new session appears in the KangenChat agent dashboard.


## 4. Copilot Studio bot configuration

1. **Attach the connector to your bot**:
   - In your Copilot Studio bot, go to **Plugins / Actions**.
   - Add the `KangenChatEscalationConnector` and enable the `EscalateToLiveAgent` action.

2. **Add an action step in a topic**:
   - In the topic where escalation is needed, insert an **Action**.
   - Choose `EscalateToLiveAgent`.

3. **Map input parameters**:
   - `conversationId` → Copilot conversation ID (e.g. `Conversation.Id`).
   - `user.name` → user display name (e.g. `User.DisplayName`).
   - `user.email` → user email (e.g. `User.Email`), if available.
   - `issueType` → a variable from your dialog (e.g. `"billing"`, `"technical"`).
   - `latestUserMessage` → last user utterance (e.g. `Turn.Input`).

4. **Use the action result in dialog**:
   - After the action, the result object contains `sessionId`, `queueMessage`, and `webChatUrl`.
   - Add a bot message like:

     > `{{EscalateToLiveAgent_Result.queueMessage}} Your case ID is {{EscalateToLiveAgent_Result.sessionId}}.`

   - Optionally include:

     > `You can also open live chat here: {{EscalateToLiveAgent_Result.webChatUrl}}`

5. **Test end-to-end**:
   - Run the Copilot in test mode.
   - Trigger the escalation path.
   - Confirm:
     - Copilot shows the queue message and case ID.
     - A new open chat session appears in the KangenChat agent dashboard.


## 5. High-level checklist

- [ ] Backend deployed and reachable at `https://api.kangenchat.yourdomain.com`.
- [ ] `.env` configured with `COPILOT_API_KEY`, `FRONTEND_URL`, `NEXT_PUBLIC_BACKEND_URL`, DB settings.
- [ ] `/copilot/escalate` returns `200` and creates a session when called with the correct API key.
- [ ] Custom connector created in Copilot Studio with API key auth and `/copilot/escalate` operation.
- [ ] Copilot bot topic wired to call `EscalateToLiveAgent` and show response to the user.
- [ ] End-to-end test confirms: Copilot escalates and agents see the chat in KangenChat.


## 6. AWS Lightsail instance setup (example)

This section gives a concrete example of deploying the KangenChat backend on an AWS Lightsail instance so Copilot Studio can reach it over HTTPS.

### 6.1. Create the Lightsail instance

1. In the AWS console, go to **Lightsail → Instances → Create instance**.
2. Choose a **Linux/Unix** platform (e.g. Ubuntu LTS blueprint).
3. Pick an instance plan (start with the smallest for testing).
4. Give it a name (for example `kangenchat-backend`).
5. Create the instance and wait for it to start.

### 6.2. Connect and install dependencies

1. From Lightsail, click the instance and use the **SSH** button (browser-based) or connect via your own SSH client.
2. Update packages:

   ```bash
   sudo apt-get update && sudo apt-get upgrade -y
   ```

3. Install Node.js (pick a supported LTS version for your app):

   ```bash
   # Example for Node 20.x via Nodesource or nvm
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

4. Install Git and Nginx:

   ```bash
   sudo apt-get install -y git nginx
   ```

### 6.2.1. Configure GitHub SSH key on Lightsail (recommended)

To avoid HTTPS password/PAT prompts and make `git clone` easier from the Lightsail instance, create an SSH key and add it to your GitHub account:

1. Generate an SSH key on the Lightsail instance (replace the email with your GitHub email):

   ```bash
   ssh-keygen -t ed25519 -C "your-github-email@example.com"
   ```

   Press **Enter** to accept the default file path, and optionally press **Enter** again for an empty passphrase.

2. Show the public key and copy it:

   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

3. In GitHub (in your browser), go to **Settings → SSH and GPG keys → New SSH key**, give it a name (for example `lightsail-kangenchat`), and paste the copied public key.

4. Back on Lightsail, test the connection:

   ```bash
   ssh -T git@github.com
   ```

   You should see a message like `Hi KarmasLight! You've successfully authenticated...`.

5. Now you can clone the repo via SSH without entering credentials:

   ```bash
   cd ~
   git clone git@github.com:KarmasLight/kangenchat.git
   ```

### 6.3. Deploy the KangenChat backend

1. Clone your repository (or otherwise copy the code). If you followed the SSH key setup above, use:

   ```bash
   cd ~
   git clone git@github.com:KarmasLight/kangenchat.git
   cd kangenchat
   ```

2. Install Node dependencies:

   ```bash
   npm install
   ```

3. Create a production `.env` file based on the example in this guide:

   ```bash
   nano .env
   ```

   Set at least:

   - `PORT=5010`
   - `FRONTEND_URL=https://kangenchat.yourdomain.com`
   - `NEXT_PUBLIC_BACKEND_URL=https://api.kangenchat.yourdomain.com`
   - `COPILOT_API_KEY=some-long-random-secret`
   - `JWT_SECRET`, `FORCE_LOGOUT_SECRET`
   - `DATABASE_URL` pointing to your production Postgres.

4. Build (if needed) and start the backend:

   ```bash
   # If you have a build step for TypeScript or Next.js server code
   npm run build || true

   # Start the backend (for production use a process manager like pm2)
   npm run dev:server
   ```

   For production, install and use `pm2` or a systemd service so the server restarts automatically:

   ```bash
   sudo npm install -g pm2
   pm2 start "npm run dev:server" --name kangenchat-backend
   pm2 save
   ```

### 6.4. Configure Nginx and HTTPS

1. Point a DNS record (e.g. `api.kangenchat.yourdomain.com`) to the Lightsail instance’s public IP.
2. Create an Nginx site configuration like the example in section **2. Nginx / HTTPS setup (example)** of this document, proxying to `http://127.0.0.1:5010`.
3. Enable the config and reload Nginx:

   ```bash
   sudo ln -s /etc/nginx/sites-available/kangenchat-api.conf /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

4. Install Certbot and obtain an SSL certificate:

   ```bash
   sudo apt-get install -y certbot python3-certbot-nginx
   sudo certbot --nginx -d api.kangenchat.yourdomain.com
   ```

5. Verify that `https://api.kangenchat.yourdomain.com/health` returns `{ "status": "ok" }`.

### 6.5. Final checks for Copilot integration

1. Confirm the backend is reachable over HTTPS from outside your network.
2. Test `POST https://api.kangenchat.yourdomain.com/copilot/escalate` with the correct `x-api-key` and sample JSON.
3. Once it works, use this same base URL and API key in your Copilot Studio custom connector.

