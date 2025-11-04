# 🏨 Green Nature Portal — Enterprise Communication & Mail Monitoring Platform (.NET 8)

**Production Specification & Emergend AI Generation Prompt**
**Version:** 1.0 (2025‑11‑04)
**Owner:** Green Nature Hotels (IT & Digital Transformation)

---

## A. Executive Overview

**Goal:** Tek bir kurumsal portal altında aşağıdaki ihtiyaçların tamamını, **ASP.NET Core 8** tabanlı, modüler ve ölçeklenebilir bir mimariyle sunmak:

* **E‑posta izleme ve SLA yönetimi** (Exchange Online/On‑Prem)
* **AD/LDAP senkronizasyonu** ve rol‑tabanlı yetkilendirme
* **Gerçek zamanlı portal**: dashboard’lar, duyurular, iç sohbet ve dosya paylaşımı (otel/birim bazlı), çapraz birim mesajlaşmada **tek seferlik onay**
* **Arama, raporlama, PDF/XLSX export**
* **KVKK/GDPR uyumlu denetim ve veri yaşam döngüsü**

Tüm bileşenler **on‑prem** veya GN altyapısında; **harici veri kalıcı depolama yok.**

---

## B. Technology Stack (Final)

* **Backend:** **ASP.NET Core 8** (Minimal API + Clean Architecture)
* **Realtime:** **SignalR** (WebSockets)
* **Background Jobs:** **Hangfire** (Redis veya PostgreSQL storage)
* **Database:** **PostgreSQL 16** (önerilen) veya SQL Server 2019+
* **Cache/Bus:** **Redis**
* **Directory:** **LDAP (on‑prem AD)** + **Microsoft Graph (Azure AD/Exchange Online)**
* **On‑Prem Exchange:** **EWS** (fallback)
* **Frontend:** **React 18 + Vite + TypeScript + TailwindCSS** (PWA + i18n)
* **Arama:** Meilisearch (opsiyonel) / PostgreSQL FT
* **PDF/XLSX:** **QuestPDF** + **ClosedXML**
* **Security:** ASP.NET Identity + Policy‑based Authorization; 2FA (TOTP/U2F)
* **Observability:** Serilog + OpenTelemetry (opsiyonel) + HealthChecks UI
* **AV:** ClamAV socket taraması (dosya yüklemeleri)

> **Neden PostgreSQL?** JSONB, FT arama, parti̇syon, güçlü indeks türleri; EF Core ekosistemi olgun.

---

## C. Bounded Contexts & Services

1. **Directory & Identity** – AD bind, OU eşleştirme, kullanıcı ilk kaydı/sync, leave & replacement.
2. **Mail Ingest & Normalize** – Graph/Webhook + EWS/IMAP fallback, inline sanitization, thread/message oluşturma.
3. **SLA & Routing Engine** – iş saatleri/holiday, T‑15 risk, breach, çok kademeli eskalasyon.
4. **Inbox & Workflow** – durumlar, etiketler, notlar, ekler, güvenli HTML.
5. **Announcements & Recognition** – otel/global, kitle hedefleme, okundu, “Ayın Personeli”.
6. **Chat & File Share** – otel/birim içi sohbet, dosya gönderimi, **çapraz birim tek seferlik onay**, kalıcı kayıt.
7. **Search & Discovery** – konu/gövde/gönderen/etiket fuzzy; operatörler.
8. **Exports & Templates** – PDF/XLSX rapor ve özelleştirilebilir export builder.
9. **Theme & Branding** – otel başına renk/logo; karanlık mod.
10. **Audit & Compliance** – immutable hash‑zincir, SIEM export (NDJSON), KVKK/GDPR araçları.
11. **Health & Ops** – health endpoints, Hangfire Dashboard, SignalR ve entegrasyon gecikmeleri.

---

## D. Role Model & Access

| Rol                | Kapsam       | Yetkiler                                                                   |
| ------------------ | ------------ | -------------------------------------------------------------------------- |
| **SuperAdmin**     | Global       | Tüm sistem, markalama, retention, audit, entegrasyon anahtarları           |
| **Admin**          | Global       | Oteller, kullanıcılar, duyurular, SLA/routing (güvenlik anahtarları hariç) |
| **Manager/Müdür**  | Hotel‑Scoped | Kendi oteli/otelleri, birimler, raporlar, duyurular, chat moderasyonu      |
| **Staff/Personel** | Individual   | Kendi gelen kutusu, otel/birim içi sohbet, dosya paylaşımı                 |

**Otel izolasyonu**: global policy + tenant filter (HotelId) + EF Core Query Filters; **negatif test** senaryoları zorunlu.

---

## E. Data Model (ER Özeti)

**Ortak alanlar**: `CreatedBy, UpdatedBy, HotelId, DeptId, TenantBoundary`, `RowVersion` (concurrency), `SoftDelete` (opsiyonel)

**Kimlik & Organizasyon**

* `Hotels(Id, Code, Name, Timezone, BrandJson, BusinessHoursJson, HolidayRulesJson)`
* `Departments(Id, HotelId, Name, Code)`
* `Users(Id, Email, SamAccountName, DisplayName, Locale, Timezone, Role, HotelIds jsonb, DeptId, TwoFAEnabled)` (çok‑otelli destek `UserHotels` pivot)
* `Leaves(Id, UserId, StartAt, EndAt, ReplacementUserId, Reason)`

**Posta**

* `Mailboxes(Id, HotelId, Address, Provider, MetaJson, Active)`
* `Threads(Id, HotelId, MailboxId, Subject, CustomerAddress, Status, FirstReceivedAt, LastActivityAt, FrtSeconds, LastReplyUserId)`
* `Messages(Id, ThreadId, Direction, Sender, RecipientsJson, CcJson, BccJson, HtmlSanitized, Text, ReceivedAt, SentAt, MessageId, InReplyTo)`
* `Tags(Id, HotelId, Name, Color, SystemTag)` + `ThreadTags(ThreadId, TagId)` + `MessageTags(MessageId, TagId)`
* `SLAPolicies(Id, HotelId, Name, BusinessHoursJson, ThresholdMinutes, EscalationJson, PauseOnPending)`
* `RoutingRules(Id, HotelId, RuleJson, Priority)`

**Duyuru**

* `Announcements(Id, HotelId NULL, CreatedByUserId, Title, MessageHtml, Priority, Scope, StartAt, EndAt, AudienceJson, Delivery, LocaleJson)`
* `AnnouncementReads(Id, AnnouncementId, UserId, ReadAt)`

**Chat & Dosya**

* `ChatRooms(Id, HotelId, DeptId NULL, Type ENUM('dept','dm','cross'))`
* `ChatMemberships(Id, RoomId, UserId, Role ENUM('owner','member'), Muted)`
* `ChatMessages(Id, RoomId, UserId, BodyText, HtmlSanitized, AttachJson, CreatedAt, EditedAt)`
* `FileBlobs(Id, Sha256, Size, Mime, StoragePath, CreatedBy)`
* `FileShares(Id, BlobId, RoomId NULL, SenderId, ReceiverId NULL, HotelId, DeptId NULL, CreatedAt)`
* `CrossDeptApprovals(Id, RequestorId, TargetDeptId, TargetUserId NULL, Purpose, Status ENUM('pending','approved','rejected'), Token, ExpiresAt, CreatedAt)`

**Arama**

* `SearchIndex(Id, HotelId, ThreadId NULL, MessageId NULL, Subject, BodyText, Sender, TagsText, Ts)`

**Denetim**

* `Audits(Id, ActorUserId, HotelId NULL, Action, TargetType, TargetId, PayloadJson, CreatedAt, Hash, PrevHash)`

**Export**

* `ExportTemplates(Id, HotelId, Name, DefinitionJson, VisibilityJson, CreatedByUserId)`

**AI Taslak**

* `AIDraftLogs(Id, UserId, ThreadId, PromptHash, Provider, Tokens, LatencyMs, CreatedAt)`

**İndeksler**: Threads(HotelId, Status, FirstReceivedAt, LastActivityAt), Messages(ThreadId, ReceivedAt), ChatMessages(RoomId, CreatedAt DESC), FileBlobs(Sha256 unique), Audits(CreatedAt), Search fulltext.

---

## F. İş Kuralları (Kanoni̇k Akışlar)

**Posta yaşam döngüsü**: `new → assigned → pending → responded → closed`

* Okundu ama yanıt yok → `unanswered`
* `pending` → SLA zamanlayıcıları **pause**
* İlk yanıt → `responded` + FRT hesapla
* T‑15 dk → `sla-at-risk` uyarısı
* Süre aşımı → `sla-breached` + eskalasyon (e‑posta/push/chat mention)

**Yönlendirme DSL**: gönderen domain, konu regex, departman, vardiya, leave, VIP listesi, yük dağılımı, geçmiş

**Chat/Dosya**

* **Birim içi** odalar otomatik; herkes üye.
* **DM** izinli (otel içi sınır); audit log zorunlu.
* **Çapraz birim**: ilk mesaj/transferde **tek seferlik onay**:

  * `CrossDeptApprovals` kaydı → hedef departman onaylar veya hedef kullanıcı tekil onay verir.
  * Süresi dolan tokenlar otomatik iptal (Hangfire job).
* **Dosya**: veritabanında yalnızca meta; **blob** disk/NAS üzerinde, **ClamAV taraması** sonrası erişime açılır. Sha256 ile deduplikasyon; erişim log’ları audit’e yazılır.

---

## G. Frontend (React + Vite + TS)

* **Layout:** otel teması (primary/accent/logo), karanlık mod
* **Sayfalar:** Login, Dashboard(otel/global), Inbox, Chat, Duyurular, Arama, Export Builder, Ayarlar (Genel/Oteller/Mail Bağlantıları/Routing&SLA/Directory/Security/Notifications/Data Retention/Theme/Şablonlar), Health
* **Chat UI:** WhatsApp benzeri, mention’lar, dosya sürük‑bırak, okundu/teslim durumları, arşiv, sabitleme, sessize alma
* **Arama:** `hotel:`, `dept:`, `user:`, `tag:` operatörleri + tarih filtresi
* **PWA:** offline okuma (Inbox, Duyuru, Chat read‑only), push bildirim

---

## H. Security & Compliance

* **ASP.NET Identity** + 2FA (TOTP/U2F), cihaz/oturum sınırları
* **Policy‑based Authorization** + otel sınırı query filters
* **HTML sanitize:** Ganss.XSS safelist; CID görseller kontrollü
* **ClamAV**: yüklemelerde zorunlu tarama; karantinaya alma
* **Audit chain:** her kritik aksiyon hash’li; günlük “anchor digest” e‑posta + SIEM NDJSON export
* **KVKK/GDPR:** veri saklama politikaları (otel bazlı), export/delete araçları

---

## I. Health & Telemetry

* **Health endpoints:** `/health/app`, `/health/queue`, `/health/websockets`, `/health/integrations`
* **Hangfire Dashboard:** sadece Admin/SuperAdmin (otel sınırı read‑only görünüm Manager’a)
* **SignalR** uptime ve Exchange/Graph gecikme metrikleri
* **Günlük PDF:** “Hotel IT Health Report” (Admin’e)
* **Sabah Bildirimi:** Daily Brief push (hacim, cevap süreleri, riskli kuyruklar)

---

## J. Project Structure

```
/green-nature-portal
├─ src/
│  ├─ Api/                  # ASP.NET Core 8 Minimal API
│  ├─ Application/          # CQRS, Validators, Policies
│  ├─ Domain/               # Entities, ValueObjects, DomainEvents
│  ├─ Infrastructure/       # EF Core, Repositories, Graph/EWS/LDAP, Hangfire, Redis, Serilog, ClamAV
│  └─ Realtime/             # SignalR hubs, presence, chat
├─ web/                     # React 18 + Vite + TS + Tailwind + i18n + Workbox
├─ deploy/
│  ├─ nginx.conf
│  ├─ portal.service        # systemd
│  └─ docker-compose.yml    # opsiyonel
├─ scripts/
│  ├─ setup.sh
│  ├─ migrate-seed.sh
│  └─ health-check.sh
└─ tests/
   ├─ Unit (xUnit)
   ├─ Integration
   └─ E2E (Playwright)
```

---

## K. appsettings.json (örnek)

```json
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
    "Diamond": { "Primary": "#009879", "Accent": "#E4C44A", "Logo": "diamond-logo.png" },
    "Resort":  { "Primary": "#006B3F", "Accent": "#D6B36A", "Logo": "resort-logo.png" },
    "Sarigerme": { "Primary": "#00A79D", "Accent": "#F7786B", "Logo": "sarigerme-logo.png" }
  }
}
```

---

## L. Nginx Reverse Proxy (örnek)

```nginx
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
```

**systemd** (`deploy/portal.service`):

```ini
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
```

---

## M. Hangfire Jobs & SignalR Kanalları

**Queues:** `critical` (escalations), `high` (webhooks), `default` (routing), `low` (exports/ai)
**Jobs:** `IngestGraphWebhook`, `ParseEml`, `ApplyRoutingRules`, `ComputeSLA`, `Escalate`, `SendPush`, `GenerateAIDraft`, `BuildExport`, `DailyHealthReport`, `ExpireCrossDeptTokens`
**Hubs:** `hotel:{id}:dashboard`, `hotel:{id}:sla`, `user:{id}:inbox`, `dept:{id}:chat`, `dm:{id}`, `announcements:{scope}`

---

## N. Testing & Quality Gates

* **xUnit + FluentAssertions**, **EFCore.InMemory** / Testcontainers
* **Playwright E2E**: inbox akışları, chat/dosya, çapraz birim onay, PWA push
* **Analyzers:** StyleCop/IDisposable analizleri; **SonarQube** opsiyonel
* **Security tests:** XSS sanitization, dosya tarama negatif vakaları, policy bypass testleri

---

## O. Seeds & Demo Data

* 3 otel, 15 birim, 30 kullanıcı, 9 posta kutusu
* Temsili threads/messages, duyurular, chat odaları, çapraz birim onay senaryosu

---

## P. UX & Estetik

* **Login:** döngüsel otel logolu video arka plan
* **Dashboard:** “Think Green – Save Paper” widget
* **Chat:** sabitleme, yıldızlı mesaj, reply‑thread, mention, hızlı tepki emojileri (kurumsal set)
* **Dosya:** preview (PDF/Image), sürümleme (opsiyonel), 2GB tek dosya sınırı (konfigürasyon)

---

## Q. Implementation Roadmap

1. **Scaffold & Identity/AD sync**
2. **Graph/EWS ingest**
3. **Inbox & SLA Engine**
4. **Announcements**
5. **Chat & File Share (+ cross‑dept approval)**
6. **Dashboards & Search**
7. **Exports & Templates**
8. **PWA & Push**
9. **Ops & Health**

Her aşama: testler + dokümantasyon + seed güncellemesi.

---

## R. Emergend AI — **Generation Prompt** (paste as‑is)

```
You are Emergend AI. Generate a **production‑ready** monorepo named `green-nature-portal` implementing the following .NET 8 system.

1) Stack & Structure:
- Backend: ASP.NET Core 8 (Minimal API + Clean Architecture). EF Core 8 with PostgreSQL. Redis for cache and SignalR backplane. Background jobs with Hangfire.
- Realtime: SignalR hubs (hotel/manager dashboards, inbox updates, chat rooms, announcements).
- Frontend: React 18 + Vite + TypeScript + Tailwind, i18n (TR/EN), PWA with Workbox and Web Push (VAPID).
- Security: ASP.NET Identity + 2FA (TOTP/U2F), policy-based authorization, hotel-level tenant filters.
- AV: ClamAV socket scan for all uploads. HTML sanitization with Ganss.XSS.
- PDF/XLSX: QuestPDF + ClosedXML. Logging: Serilog. HealthChecks endpoints.
- Observability: optional OpenTelemetry wiring. Meilisearch optional via adapter.

2) Bounded Contexts (folders under src/): Directory, Mail, SLA, Inbox, Announcements, Chat, Search, Exports, Theme, Audit, Health. Include Domain/Application/Infrastructure layers and Api + Realtime.

3) Data model & migrations (PostgreSQL):
- Hotels, Departments, UserHotels (pivot), Users (extend Identity) with Locale/Timezone/Role/DeptId and HotelIds jsonb.
- Mailboxes, Threads, Messages, MessageAttachments.
- Tags + ThreadTags + MessageTags.
- SLAPolicies, RoutingRules.
- Leaves, Replacements.
- Announcements, AnnouncementReads.
- ChatRooms (dept/dm/cross), ChatMemberships, ChatMessages, FileBlobs (Sha256 dedupe), FileShares, CrossDeptApprovals.
- SearchIndex table (or Meilisearch config).
- Audits with immutable hash chain (Hash, PrevHash). ExportTemplates. AIDraftLogs.

4) Features:
- AD sync (LDAP bind + OU mapping) & identity match (email → name → sAMAccountName). Manual review queue.
- Exchange Online via Graph (subscriptions/webhooks + delta) and on‑prem EWS fallback; IMAP fallback optional.
- Normalize HTML, sanitize, store threads/messages; attachment scan with ClamAV; CID inline policy.
- SLA engine with pause on `pending`, T‑15 risk event, breach + escalation tiers; per‑hotel business hours/holidays.
- Inbox UI: statuses (new/assigned/pending/responded/closed), system tags (waiting‑action/resolved/unanswered/sla‑at‑risk/sla‑breached), internal notes, attachment preview.
- Dashboards: SuperAdmin global KPIs and Manager hotel KPIs; 60s cached; SignalR pushed updates.
- Announcements: hotel/global scope, audience targeting (hotel/department/users), schedule windows, priority (info/important/critical), delivery (dashboard/push/email/all), read receipts; Employee of the Month cards.
- Chat & File Share: dept rooms auto-provisioned; DMs within hotel; cross‑dept requires one‑time approval token; all messages and file shares permanently stored; presence, typing, read receipts.
- Search: operators hotel:/dept:/user:/tag:, fuzzy highlight; default PostgreSQL FT; optional Meilisearch adapter.
- Exports: drag‑and‑drop export builder to PDF/XLSX; saved templates per role.
- Theme: per‑hotel color/logo tokens, dark mode. Theme editor updates config used by web build.
- AI Drafts: polite EN/TR reply suggestions for email context; pluggable provider adapter; usage logs.
- Health: /health/app, /health/queue, /health/websockets, /health/integrations. Hangfire Dashboard secure.
- PWA: installable, offline read‑only inbox/announcements/chat history; push notifications for mentions, SLA risk, announcements.

5) Frontend deliverables:
- React routes/pages: login, dashboards, inbox, chat, announcements, search, exports, settings (General/Hotels/Mail Connectors/Routing & SLA/Directory/Security/Notifications/Data Retention/Theme/Templates), health.
- Shared components: SLA chips, tag selector, thread list, message viewer (sanitized), announcement banners/cards, chat composer, file uploader with ClamAV status, export builder, theme editor, charts.
- i18n: full `tr` and `en` locales including PDFs.

6) Seeds:
- 3 hotels (Diamond, Resort, Sarigerme) with brand tokens; 15 departments; 30 users; 9 mailboxes; sample threads/messages; announcements; chat rooms; a cross‑dept approval scenario; export templates.

7) Ops & Scripts:
- README with Ubuntu 22.04 setup: Nginx reverse proxy for Kestrel, PostgreSQL 16, Redis, ClamAV, Hangfire setup, SignalR scaling, HealthChecks UI, Playwright.
- deploy/nginx.conf, deploy/portal.service, docker-compose.yml (optional). scripts/setup.sh, migrate-seed.sh, health-check.sh.

8) Quality gates:
- xUnit tests for hotel scoping, routing/SLA math, leave/replacement logic, auto‑tags, audit hashing, cross‑dept approval, file scan flows.
- Playwright E2E for inbox, chat/file send, announcements, PWA install/push.
- Static analysis and CI workflow (build/test/lint). Serilog sinks sample (console/file/seq).

Deliver a complete monorepo with passing tests and runnable preview.
```

---

## S. Next Steps

1. Emergend’e **Generation Prompt**’u yapıştır → repo üret.
2. Sunucuda PostgreSQL, Redis, ClamAV, Nginx reverse proxy hazırla.
3. `appsettings` sırlarını doldur (Graph/EWS/LDAP/VAPID).
4. `scripts/setup.sh` + `migrate-seed.sh` çalıştır; Hangfire ve SignalR’ı başlat.
5. Sarıgerme üzerinde pilot: AD sync + Graph webhook; ardından Diamond & Resort yayılım.

*End of Spec v1.0*
