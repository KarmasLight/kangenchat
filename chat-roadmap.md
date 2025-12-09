# Live Chat System Roadmap

## Milestone 0: Stabilize current build (today)

- [X] Fix Chats tab JSX structure and parsing error.
- [X] Use REST Register/Login (JWT), hydrate agent profile.
- [X] Confirm presence toggle and profile save endpoints work.

## Milestone 1: Customer-facing (Chat Widget)

- Branding and Embed (MVP)
  - [X] Floating/inline widget.
  - [X] Theme props: colors, logo, welcome message.
  - [X] Embeddable script with init options.
- Pre-Chat Form (MVP)
  - [X] Name, email, issue type (+ extensible custom fields).
  - [X] Persist on session; expose to routing.
- Live Chat (MVP)
  - [X] Real-time messaging, typing indicators (done).
  - [X] Rich text (markdown + emoji picker).
  - [X] File/image upload (S3-compatible; validate size/type). (ignore for now)
- Offline Mode (MVP)
  - [X] If no agents online, show "Leave a message".
  - [X] Create ticket/email, confirmation to user.
- Transcript (MVP)
  - [X] Email transcript to user; downloadable HTML/text.

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
- Agent Dashboard (MVP)

  - [X] Queues: waiting, active, closed.
  - [X] Accept/assign/reassign.
  - [X] Active chat view w/ history and typing indicator.
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
  - [ ] Department, availability, issue type, language.
- Agent Availability (MVP)
  - [X] Online/Offline (done). Phase 2: shift scheduling.
  - [X] Admin force-logout of all agents.
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
  - JWT auth (login/register), /me (GET/PUT), /me/password, /presence, admin force-logout.
  - Offline message endpoints and stale session cleanup.
  - Socket: start_chat, agent_accept, send_message, get_chat_history, typing events, notifications, force_logout broadcast.
- Frontend
  - Agent Dashboard: Chats | Profile tabs, presence toggle, profile form, password change, header avatar/display name, forced logout handling.
  - Widget: basic chat + typing, pre-chat form with availability polling, offline message form; uploads & transcript pending.

## Acceptance criteria (MVP)

- End-to-end chat from widget: pre-chat → routed to online agent → transcript deliverable.
- Offline flow creates ticket/email when no agents online.
- Agents can accept/reassign; presence managed; profile editable.
- Basic history filterable; uploads safe and retrievable.

## Next implementation slice (proposal)

1) File uploads (widget + dashboard) with S3 storage abstraction and validation.
2) Transcript email/download and transcript history management.
3) Basic routing UI (departments + availability) plus agent queue analytics.
4) Chat widget UX polish (header layout, minimize/end-chat flow, better availability state handling).

## Next steps

- Complete file/image upload support (frontend widgets + backend APIs, S3 integration, size/type validation).
- Build the routing/department UI so agents can flag availability and route chats before assignment.
- Surface analytics/queue metrics (waiting/active/closed filters, CSAT placeholder) and extend search/history filters.
- Harden chat widget UX (ensure Start Chat visibility, refresh agent status syncing, responsive layout) before tackling visitor info panel.
