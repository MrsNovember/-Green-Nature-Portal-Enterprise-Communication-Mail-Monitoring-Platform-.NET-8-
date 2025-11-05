🏨 Green Nature Portal

Enterprise Communication & Mail Monitoring Platform (ASP.NET Core 8 + React 18)

Production-ready, hotel-aware portal for email monitoring with SLA, AD/LDAP sync, real-time dashboards, chat & file sharing, auditing, and KVKK/GDPR compliance—built as a modular, scalable monorepo.

✨ Highlights

End-to-end mail lifecycle (Exchange Online/On-Prem): ingest → normalize → SLA/routing → reply tracking → exports

Hotel isolation by design: tenant filters, policy-based authorization, and query filters enforced across the stack

Realtime experience with SignalR: live dashboards, inbox updates, chat presence/typing/read receipts

Compliance first: immutable audit hash-chain, SIEM NDJSON export, retention per hotel, KVKK/GDPR tooling

Modern frontend: React 18 + Vite + Tailwind, full TR/EN i18n, PWA (offline read-only) and Web Push

Ops ready: Health endpoints, Hangfire Dashboard, OpenTelemetry hooks, systemd + Nginx reference, Docker option

Quality gates: xUnit (+FluentAssertions), Integration Tests, Playwright E2E, CI coverage gate ≥ 70%

🧭 Table of Contents

Architecture

Bounded Contexts

Data Model (ER Overview)

Role Model & Scoping

Features

Frontend (UI/UX)

Security & Compliance

Health & Observability

Project Structure

Quick Start

Configuration

Deployment (Linux + Nginx + systemd)

Docker (optional)

Seeds & Demo Data

Testing & Quality

API Surface (selected)

Roadmap

Troubleshooting

License

🏗 Architecture

Stack

Backend: ASP.NET Core 8 (Minimal API + Clean Architecture), EF Core 8, PostgreSQL 16 (recommended)

Realtime: SignalR (WebSockets) + Redis backplane

Jobs: Hangfire (Redis or PostgreSQL storage)

Search: PostgreSQL Full-Text (default) or Meilisearch (optional)

Frontend: React 18 + Vite + TypeScript + TailwindCSS, i18n (TR/EN), Workbox PWA + Web Push (VAPID)

Security: ASP.NET Identity, 2FA (TOTP/U2F), policy-based auth

Files/AV: ClamAV socket scan for all uploads

PDF/XLSX: QuestPDF + ClosedXML

Observability: Serilog + (optional) OpenTelemetry + HealthChecks UI

Why PostgreSQL?
First-class JSONB, powerful indexing, partitions, robust FT search, mature EF Core provider.

🧱 Bounded Contexts

Directory & Identity – AD bind, OU mapping, initial user onboarding, leave & replacement logic

Mail Ingest & Normalize – Graph subscriptions/webhooks (+ EWS/IMAP fallback), HTML sanitize, thread/message creation

SLA & Routing Engine – business hours/holiday aware; T-15 at-risk, breach, multi-tier escalation

Inbox & Workflow – statuses, tags, internal notes, secure HTML viewer, attachments

Announcements & Recognition – hotel/global scoping, audiences, schedule windows, read receipts, “Employee of the Month”

Chat & File Share – dept rooms, DMs (hotel-internal), cross-department one-time approval, durable history

Search & Discovery – fuzzy search on subject/body/sender/tags; operators and time filters

Exports & Templates – drag-and-drop export builder to PDF/XLSX; saved templates per role/hotel

Theme & Branding – per-hotel color/logo tokens, dark mode; theme editor

Audit & Compliance – immutable hash-chain, SIEM NDJSON export, retention tools

Health & Ops – health endpoints, Hangfire Dashboard, SignalR/Exchange latency metrics

🗃 Data Model (ER Overview)

Common fields across entities: CreatedBy, UpdatedBy, HotelId, DeptId, TenantBoundary, RowVersion (concurrency), SoftDelete (optional)

Identity & Organization

Hotels, Departments, Users (+ UserHotels pivot for multi-hotel support), Leaves (with ReplacementUserId)

Mail

Mailboxes, Threads, Messages (+ Attachments), Tags (+ ThreadTags, MessageTags), SLAPolicies, RoutingRules

Announcements

Announcements, AnnouncementReads

Chat & Files

ChatRooms (dept/dm/cross), ChatMemberships, ChatMessages

FileBlobs (SHA-256 dedupe), FileShares

CrossDeptApprovals (status: pending/approved/rejected, token + expiry)

Search

SearchIndex (subject/body/sender/tags, ts vector)

Audit

Audits (immutable: Hash, PrevHash)

Exports

ExportTemplates

AI Drafts

AIDraftLogs (provider usage & latency logs)

Indexes on all hot paths (threads/messages/chat/audit/search); designed for multi-hotel filtering and SLA reporting.

🔐 Role Model & Scoping
Role	Scope	Capabilities
SuperAdmin	Global	All system settings, branding, retention, audit, integration keys
Admin	Global	Hotels, users, announcements, SLA/routing (sans root secrets)
Manager	Hotel-Scoped	Their hotel(s), departments, reports, announcements, chat moderation
Staff	Individual	Personal inbox, hotel/department chat, file share

Hotel isolation is enforced via global policy + tenant filter (HotelId) + EF Core query filters. Negative tests ensure no cross-hotel leakage.

✅ Features
Mail Lifecycle & SLA

Statuses: new → assigned → pending → responded → closed

Auto-tags: waiting-action, resolved, unanswered, sla-at-risk, sla-breached

FRT: First Response Time captured on initial reply

Timers: pause on pending, T-15 warnings, breach → escalation (email/push/chat mention)

Routing DSL: sender domain, subject regex, department, shift, leave, VIP lists, load balancing, historical signals

Chat & File Share

Department rooms auto-provisioned; DMs permitted within hotel; everything logged

Cross-department requires one-time approval (token with expiry via Hangfire)

File uploads scanned via ClamAV; metadata in DB, blobs on disk/NAS; SHA-256 dedupe; access fully audited

Announcements

Hotel/global scope, audience targeting (hotel/department/users), schedule windows, priorities (info/important/critical)

Delivery: dashboard/push/email; read receipts; recognition cards

Search & Exports

Operators: hotel:, dept:, user:, tag: + date filters; fuzzy highlight

Export Builder → PDF/XLSX with saved templates per role/hotel

Theming

Per-hotel primary/accent/logo tokens; dark mode; theme editor feeds web build

🖥 Frontend (UI/UX)

Pages: Login, Global/Hotel Dashboards, Inbox, Chat, Announcements, Search, Export Builder, Settings (General/Hotels/Mail Connectors/Routing & SLA/Directory/Security/Notifications/Data Retention/Theme/Templates), Health

Components: SLA chips, Tag selector, Thread list, Sanitized message viewer, Announcement banners/cards, Chat composer, File uploader (ClamAV status), Export builder, Theme editor, Charts

PWA: installable; offline read-only for Inbox/Announcements/Chat history; Web Push for mentions/SLA risks/announcements

i18n: full English and Turkish coverage (including PDFs)

🛡 Security & Compliance

ASP.NET Identity + 2FA (TOTP/U2F), device/session limits

Policy-based authorization + hotel-level query filters

HTML sanitize with Ganss.XSS (CID images allowed via allowlist)

ClamAV is mandatory for uploads; quarantining on failure

Audit chain: every critical action hashed; daily anchor digest + SIEM NDJSON export

KVKK/GDPR: per-hotel retention policies; export/delete tools

📈 Health & Observability

Health endpoints:
GET /health/app, /health/queue, /health/websockets, /health/integrations

Hangfire Dashboard (Admin/SuperAdmin); Manager gets read-only hotel-scoped view

SignalR uptime + Graph/Exchange ingest latency metrics

Daily PDF to admins: “Hotel IT Health Report”

Optional OpenTelemetry tracing; Serilog sinks (console/file/Seq)

🗂 Project Structure
green-nature-portal/
├─ src/
│  ├─ Api/                # ASP.NET Core 8 Minimal API
│  ├─ Application/        # CQRS, validators, policies
│  ├─ Domain/             # Entities, value objects, domain events
│  ├─ Infrastructure/     # EF Core, Repos, Graph/EWS/LDAP, Hangfire, Redis, Serilog, ClamAV
│  └─ Realtime/           # SignalR hubs: dashboards, inbox, chat, announcements
├─ web/                   # React 18 + Vite + TS + Tailwind + i18n + Workbox
├─ deploy/
│  ├─ nginx.conf
│  ├─ portal.service      # systemd unit
│  └─ docker-compose.yml  # optional
├─ scripts/
│  ├─ setup.sh
│  ├─ migrate-seed.sh
│  └─ health-check.sh
└─ tests/
   ├─ Unit (xUnit)
   ├─ Integration
   └─ E2E (Playwright)

🚀 Quick Start
Prerequisites

Ubuntu 22.04+, .NET 8 SDK, Node 18+, PNPM/Yarn or npm, PostgreSQL 16, Redis, ClamAV

(Optional) Meilisearch, OpenTelemetry Collector, Seq

Build & Run (Dev)
# Backend
cd src/Api
dotnet build
dotnet run

# Frontend
cd ../../web
npm install
npm run dev

Run Tests
# Unit + Integration with coverage
dotnet test --collect:"XPlat Code Coverage"

# E2E (headless)
cd tests/E2E
npx playwright install --with-deps
npx playwright test

⚙ Configuration

appsettings.json (excerpt):

{
  "App": {
    "Name": "Green Nature Portal",
    "BaseUrl": "https://portal.greennaturehotels.com",
    "DefaultLocale": "tr",
    "Timezone": "Europe/Istanbul"
  },
  "ConnectionStrings": {
    "Default": "Host=127.0.0.1;Port=5432;Database=gn_portal;Username=portal;Password=***",
    "Redis": "127.0.0.1:6379"
  },
  "Identity": { "Require2FAForAdmins": true },
  "LDAP": {
    "Host": "ad.greennature.local",
    "BaseDn": "OU=Users,DC=greennature,DC=local",
    "BindUser": "svc_ldap",
    "BindPassword": "***"
  },
  "Graph": {
    "TenantId": "",
    "ClientId": "",
    "ClientSecret": "",
    "SubscriptionUrl": "/api/webhooks/graph"
  },
  "EWS": { "Host": "ews.greennature.local", "Username": "svc_ews", "Password": "***" },
  "WebPush": { "VapidPublicKey": "", "VapidPrivateKey": "", "Subject": "mailto:it@greennaturehotels.com" },
  "ClamAV": { "SocketPath": "/var/run/clamav/clamd.ctl" },
  "Brand": {
    "Diamond":   { "Primary": "#009879", "Accent": "#E4C44A", "Logo": "diamond-logo.png" },
    "Resort":    { "Primary": "#006B3F", "Accent": "#D6B36A", "Logo": "resort-logo.png" },
    "Sarigerme": { "Primary": "#00A79D", "Accent": "#F7786B", "Logo": "sarigerme-logo.png" }
  }
}


Secrets to fill: Graph (TenantId/ClientId/ClientSecret), EWS creds, LDAP bind user/password, Web Push VAPID keys.

📦 Deployment (Linux + Nginx + systemd)

Nginx (TLS + HTTP/2 + WebSockets proxy)

server {
  listen 443 ssl http2;
  server_name portal.greennaturehotels.com;

  ssl_certificate     /etc/ssl/fullchain.pem;
  ssl_certificate_key /etc/ssl/privkey.pem;

  location / {
    proxy_pass         http://127.0.0.1:5051; # Kestrel
    proxy_http_version 1.1;
    proxy_set_header   Upgrade $http_upgrade;
    proxy_set_header   Connection "upgrade";
    proxy_set_header   Host $host;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}


systemd

[Unit]
Description=Green Nature Portal
After=network.target

[Service]
WorkingDirectory=/www/wwwroot/green-nature-portal
ExecStart=/usr/bin/dotnet /www/wwwroot/green-nature-portal/src/Api/GreenNature.Portal.Api.dll
Restart=always
Environment=ASPNETCORE_ENVIRONMENT=Production
User=www-data

[Install]
WantedBy=multi-user.target


If you encounter 404/SSL/aaPanel reverse-proxy quirks, use the included deployment fix script and re-load Nginx.

🐳 Docker (optional)

An optional deploy/docker-compose.yml can spin up: API, Web, PostgreSQL, Redis, ClamAV, Meilisearch.
Adjust volumes and environment variables, then:

docker compose up -d --build

🌱 Seeds & Demo Data

Run:

scripts/setup.sh
scripts/migrate-seed.sh


What you get:

3 hotels (Diamond, Resort, Sarigerme) with branding tokens

15 departments, 30 users, 9 mailboxes

Sample threads/messages, announcements, department chats, cross-dept approval scenario

Saved export templates

🧪 Testing & Quality

Unit Tests: hotel scoping, routing/SLA math, leave/replacement, auto-tags, audit hashing, cross-dept approvals, file scan flows

Integration: health endpoints, Redis/Hangfire/DB connectivity, controller workflows

E2E (Playwright): inbox flow, chat/file share, announcements, PWA install/push

Static Analysis: StyleCop; optional SonarQube

Coverage Gate: CI enforces combined coverage ≥ 70%

Typical commands:

dotnet test --collect:"XPlat Code Coverage"
npx playwright test

🔌 API Surface (selected)

Health
GET /health/app – app & dependencies basic health
GET /health/queue – jobs/queues (Hangfire)
GET /health/websockets – SignalR presence & transport
GET /health/integrations – Graph/EWS/LDAP checks

Mail / Inbox
GET /api/v1/inbox/threads (filters: status/tags/date/hotel/dept)
POST /api/v1/inbox/threads/{id}/assign
POST /api/v1/inbox/threads/{id}/reply (sanitized HTML, attachments → ClamAV)
POST /api/v1/inbox/threads/{id}/status (pending/responded/closed)

SLA & Routing
POST /api/v1/sla/policies | GET /api/v1/sla/policies
POST /api/v1/routing/rules | GET /api/v1/routing/rules

Chat & Files
Hubs: hotel:{id}:dashboard, hotel:{id}:sla, user:{id}:inbox, dept:{id}:chat, dm:{id}, announcements:{scope}
REST for file upload/download uses AV checks + audit

Announcements
POST /api/v1/announcements (scoped schedule/audience)
POST /api/v1/announcements/{id}/read

Search
GET /api/v1/search?q=...&hotel=...&tag=...&from=...&to=...

🗺 Roadmap

✅ Scaffold & Identity/AD sync

✅ Graph/EWS ingest

✅ Inbox & SLA Engine

✅ Announcements

✅ Chat & File Share (+ cross-dept approval)

✅ Dashboards & Search

✅ Exports & Templates

✅ PWA & Push

✅ Ops & Health

✅ Tests + Seeds + Docs + CI (≥ 70% coverage)

Expansion ideas: advanced manager KPI board, AI-assisted polite replies (EN/TR) with provider adapter, server health widget.

🧩 Troubleshooting

Health endpoints fail → verify DB/Redis/ClamAV sockets and Graph/EWS/LDAP credentials

Uploads blocked → check ClamAV socket path and permissions

SignalR disconnects → confirm Nginx Upgrade/Connection headers and Redis backplane

Coverage < 70% → run unit/integration locally, inspect coverage.cobertura.xml, add tests for SLA/routing/hotel filters

PWA push not received → re-create VAPID keys, check Service Worker registration and permission state

📜 License

© Green Nature Hotels. All rights reserved.
This repository is intended for internal enterprise use within the Green Nature Hotels group and approved partners. Redistribution or public use requires written permission.
