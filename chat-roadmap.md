# Live Chat System Roadmap

## Milestone 0: Stabilize current build (today)
- Fix Chats tab JSX structure and parsing error.
- Use REST Register/Login (JWT), hydrate agent profile.
- Confirm presence toggle and profile save endpoints work.

## Milestone 1: Customer-facing (Chat Widget)
- Branding and Embed (MVP)
  - Floating/inline widget.
  - Theme props: colors, logo, welcome message.
  - Embeddable script with init options.
- Pre-Chat Form (MVP)
  - Name, email, issue type (+ extensible custom fields).
  - Persist on session; expose to routing.
- Live Chat (MVP)
  - Real-time messaging, typing indicators (done).
  - Rich text (markdown + emoji picker).
  - File/image upload (S3-compatible; validate size/type).
- Offline Mode (MVP)
  - If no agents online, show "Leave a message".
  - Create ticket/email, confirmation to user.
- Transcript (MVP)
  - Email transcript to user; downloadable HTML/text.

### Data model (Widget)
- visitors: id, name, email, created_at.
- sessions: add visitor_id, issue_type, closed_reason.
- uploads: id, session_id, file_url, mime, size.
- transcripts: session_id, content, emailed_to, emailed_at.

### APIs (Widget)
- POST /widget/init (branding/status)
- POST /sessions/start (pre-chat payload)
- POST /uploads, GET /uploads/:id
- POST /transcripts/email, GET /sessions/:id/transcript

## Milestone 2: Agent Tools
- Agent Dashboard (MVP)
  - Queues: waiting, active, closed.
  - Accept/assign/reassign.
  - Active chat view w/ history and typing indicator.
- Internal Notes (Phase 2)
  - Private notes per session (not shown to customer).
- Macros / Canned Responses (Phase 2)
  - Personal and global responses.
- Typing Preview (Phase 2)
  - Consent-gated; redact sensitive patterns.
- Visitor Info Panel (Phase 2)
  - Location, device, browser, prior sessions, tags.
- Transfer Chat (Phase 2)
  - Transfer to another agent or department.
- Tags & Categorization (Phase 2)
  - Label chats for search/reporting.

### Data model (Agent)
- internal_notes: id, session_id, agent_id, content.
- macros: id, owner_id/null (global), title, content.
- departments: id, name; agent_departments.
- session_tags: mapping table.
- session_assignment: session_id, agent_id, assigned_at.

### APIs (Agent)
- POST /sessions/:id/assign, POST /sessions/:id/transfer
- POST /sessions/:id/notes, GET /sessions/:id/notes
- GET/POST /macros
- GET /visitors/:id (profile + history)

## Milestone 3: Admin & Backend
- Routing Rules (MVP)
  - Department, availability, issue type, language.
- Agent Availability (MVP)
  - Online/Offline (done). Phase 2: shift scheduling.
- Analytics & Reporting (Phase 2)
  - Volume by time/department/agent.
  - Performance (first response, handle time).
  - CSAT capture and reporting.
- Chat History & Search (MVP→Phase 2)
  - Basic filters (date/agent) → full-text search.
- Integrations (Phase 2)
  - CRM (Salesforce/HubSpot), Helpdesk (Zendesk), Copilot Studio handoff, REST webhooks.
  - API keys management.
- Security & Compliance (MVP→Phase 2)
  - RBAC (admin/agent/viewer), audit logs, PII minimization.
  - Data retention policies; GDPR/CCPA export/delete.

## Milestone 4: Polish & Scale
- Offline notifications (email/Slack) for missed chats.
- Multi-language UI and routing.
- Multi-tenant support (optional).
- Observability: logs/traces/metrics, cost telemetry.

## Current status snapshot
- Backend
  - JWT auth (login/register), /me (GET/PUT), /me/password, /presence.
  - Socket: start_chat, agent_accept, send_message, get_chat_history, typing events, notifications.
- Frontend
  - Agent Dashboard: Chats | Profile tabs, presence toggle, profile form, password change, header avatar/display name.
  - Widget: basic chat + typing; to add pre-chat, offline mode, uploads, transcript.

## Acceptance criteria (MVP)
- End-to-end chat from widget: pre-chat → routed to online agent → transcript deliverable.
- Offline flow creates ticket/email when no agents online.
- Agents can accept/reassign; presence managed; profile editable.
- Basic history filterable; uploads safe and retrievable.

## Next implementation slice (proposal)
1) Widget Pre-Chat Form + Offline Mode.
2) Transcript email/download.
3) File uploads (widget + dashboard) with S3 storage abstraction.
4) Basic routing UI (departments + availability).
