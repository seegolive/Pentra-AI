# UI SPRINT 2 — Implementation Prompt
> Berikan seluruh isi file ini ke Claude Code sebagai satu prompt

---

Baca file-file berikut sebelum mulai:
1. `CLAUDE.md` — konvensi engineering
2. `PROGRESS.md` — status platform saat ini
3. `apps/web/src/components/AppShell.tsx` — shell yang sudah ada
4. `apps/web/src/index.css` — CSS variables yang sudah ada
5. `pentra-design-system.html` — referensi visual v1 (ada di root repo)
6. `pentra-ui-v2.html` — **referensi visual utama** (ada di root repo, buka di browser untuk preview)

---

## Konteks

Sprint UI-1 sudah selesai: design tokens, CSS variables (Outfit + JetBrains Mono),
dan 3-column AppShell sudah ada. Sprint UI-2 menambahkan 7 fitur baru yang terlihat
di `pentra-ui-v2.html`.

Semua icon menggunakan **Lucide React** (sudah ada di package.json sebagai
`lucide-react@0.383.0`). Tidak boleh menggunakan emoji sebagai icon.

---

## Task 1 — Notification System (Bell + Panel + Toasts)

### 1a. Buat `apps/web/src/hooks/useNotifications.ts`

```typescript
// Notification types yang digunakan di seluruh app
export type NotifType = 'critical' | 'warning' | 'success' | 'info'

export interface Notification {
  id: string
  type: NotifType
  title: string
  message: string
  timestamp: Date
  read: boolean
  engagementId?: string
}

// Hook mengelola notifikasi: add, markRead, markAllRead, clear
export function useNotifications() {
  // State: notifications list
  // Actions: addNotification, markRead, markAllRead, removeNotification
  // Selectors: unreadCount, hasUnread
}
```

**Catatan implementasi:**
- State disimpan di React state (bukan localStorage)
- Real notifications datang dari WebSocket events yang sudah ada
  (`ENGAGEMENT_COMPLETED`, `FINDING_CONFIRMED`, `AWAITING_APPROVAL`)
- Tambahkan ke WebSocket handler yang sudah ada di `useEngagementFeed.ts`
  atau hook serupa

### 1b. Buat `apps/web/src/components/notifications/NotificationBell.tsx`

```typescript
// Bell icon dengan badge count
// Props: count (number), onClick (handler)
// Icon: Bell dari lucide-react
// Badge: muncul hanya jika count > 0, styled seperti di pentra-ui-v2.html
// Posisi di Topbar, kanan sebelum avatar
```

### 1c. Buat `apps/web/src/components/notifications/NotificationPanel.tsx`

```typescript
// Dropdown panel, slide down dari bell
// Props: notifications[], onMarkAllRead, onClose
// Setiap item: icon per type (AlertCircle/CheckCircle/AlertTriangle/Info),
//   unread indicator (border kiri biru), message, relative timestamp
// Footer: "View all" link
// Close: klik di luar panel
// Max height: 320px dengan overflow-y scroll
```

### 1d. Buat `apps/web/src/components/notifications/Toast.tsx` dan `ToastContainer.tsx`

```typescript
// Toast individual: icon + title + message + close button
// 4 variants: ok (hijau), warn (kuning), crit (merah), info (biru)
// Animation: slide in dari kanan, fade out saat dismiss
// Auto-dismiss: 4500ms
// ToastContainer: fixed bottom-right, stack vertikal, gap 7px
// Expose: useToast() hook dengan fungsi toast(type, title, message)
```

**Integrasi:** Update `AppShell.tsx` — tambahkan `<ToastContainer />` dan
`<NotificationBell />` di topbar. Bell trigger `NotificationPanel`.

---

## Task 2 — Scan Wizard (4-Step Modal)

### Buat `apps/web/src/components/engagement/ScanWizard.tsx`

Wizard 4 langkah untuk membuat engagement baru.
Lihat `pentra-ui-v2.html` bagian `<!-- SCAN WIZARD -->` untuk referensi visual.

**Step 1 — Target:**
- Input: domain (required, validate format domain/IP)
- Input: in-scope (comma-separated)
- Input: path exclusion (optional, placeholder contoh regex)
- Input: out-of-scope (optional)
- Validasi: domain tidak boleh kosong saat klik Next

**Step 2 — Preset:**
- 6 preset cards dalam grid 2×3
- Presets: `quick` | `fast` | `full` | `stealth` | `authenticated` | `pentra-ft`
- Setiap card: nama, deskripsi, tags (chip kecil), estimasi waktu
- Card `pentra-ft` highlight khusus (border accent, tag "fine-tuned LLM")
- Default selected: `pentra-ft`

**Step 3 — Auth:**
- Toggle: None | Cookie | Bearer | Auto-login
- Cookie: textarea untuk cookie string
- Bearer: input untuk token
- Auto-login: 3 input (login URL, username, password)
- Conditional render berdasarkan toggle aktif

**Step 4 — Review & Launch:**
- Summary semua pilihan dalam tabel read-only
- Hint box: "Agent will pause at 3 HITL checkpoints…"
- Tombol Next berubah menjadi "Launch Scan" dengan Play icon

**Steps indicator di atas wizard:**
- Dot per step: pending (border only) → active (filled accent) → done (filled green + check icon)
- Line connector antar dot: abu → hijau saat done

**Submit:**
```typescript
// Saat Launch diklik:
// 1. POST /api/v1/engagements dengan data wizard
// 2. Close wizard
// 3. toast('ok', 'Scan started', `${target} · ${preset} preset`)
// 4. Navigate ke halaman engagement baru
```

**Trigger:** Tombol `+` di sidebar header (sudah ada di AppShell.tsx)

---

## Task 3 — Stop All Scans Button

### Update `apps/web/src/components/layout/AppShell.tsx` (Topbar)

Tambahkan tombol Stop All di topbar, sebelah kiri status pill.
Muncul **hanya** ketika ada engagement dengan status `running`.

```typescript
// Icon: Square dari lucide-react (filled, bukan outline)
// Style: border merah, background merah transparan, text merah
// onClick: buka StopAllModal
```

### Buat `apps/web/src/components/engagement/StopAllModal.tsx`

```typescript
// Confirmation modal dengan overlay blur
// List semua running engagements dengan nama dan phase saat ini
// Dua tombol: Cancel (ghost) dan "Stop All" (merah)
// onConfirm: PATCH semua engagement running ke status stopped
//   → PUT /api/v1/engagements/{id}/stop (atau endpoint yang tersedia)
//   → Update local state
//   → toast('warn', 'Scans stopped', 'All engagements terminated')
```

---

## Task 4 — Engagement Overview Card (Sidebar)

### Update logika sidebar di `AppShell.tsx`

Saat user klik engagement di sidebar list:
- Jika engagement `running` → tampilkan OverviewCard di atas list
- Jika bukan running → hilangkan card (atau tidak tampil)

### Buat `apps/web/src/components/engagement/EngagementOverviewCard.tsx`

```typescript
interface Props {
  engagement: Engagement        // dari existing types
  onClose: () => void
  onViewFeed: () => void
  onViewMap: () => void
  onStop: () => void
}
```

Konten card (lihat referensi di `pentra-ui-v2.html` bagian `.ov`):
- Nama engagement (truncated)
- KPI grid 4 kolom: Critical / High / Medium / Hosts (angka + label kecil)
- Phase indicator: teks phase saat ini + running icon (Activity dari lucide)
- 3 tombol: Feed (primary) | Map | Stop

Data diambil dari existing engagement state/API.

---

## Task 5 — Attack Surface Map Page

### Buat `apps/web/src/pages/AttackSurfacePage.tsx`

Halaman baru yang diakses via icon Globe di nav kiri.

**Toolbar:**
- Judul "Attack Surface" + subdomain count
- Tombol Filter dan Export (Export: download JSON dari `/api/v1/engagements/{id}/recon`)

**Canvas:**
- Background: `var(--bg-void)` dengan grid dot pattern (CSS background-image radial-gradient)
- SVG overlay untuk garis koneksi antar node
- Node = subdomain, diposisikan dengan koordinat (kalkulasi sederhana berbasis index)

**Node rendering:**
```typescript
interface SubdomainNode {
  host: string
  type: string          // dari recon data
  waf: string | null
  findings: Finding[]
  isTakeover?: boolean
}

// Warna border/background berdasarkan findings:
// critical findings → var(--critical)
// high only         → var(--high)
// medium/warning    → var(--medium)
// clean             → var(--low)
// root domain       → var(--accent)
```

**Detail panel (slide in dari kanan):**
- Muncul saat node diklik
- Konten: host, type, WAF, findings list, tombol Subscan + Details
- Close: klik di luar panel atau × button
- Subscan: POST ke subscan endpoint dengan host sebagai target

**Data source:** GET `/api/v1/engagements/{id}/recon` → parse subdomains

**Layout:** Gunakan D3 force simulation sederhana ATAU posisikan node secara
kalkulasi (root di tengah, lainnya di sekitar dalam lingkaran) — tidak perlu
library graph kompleks.

---

## Task 6 — API Vault Page

### Buat `apps/web/src/pages/ApiVaultPage.tsx`

Diakses via icon Lock di nav kiri.

**Data:** Ambil dari GET `/api/v1/admin/config` atau endpoint yang tersedia.
Jika tidak ada endpoint khusus, tampilkan status dari health check tiap service.

**Vault item per service:**
```typescript
interface VaultItem {
  id: string
  name: string               // "Burp Suite Pro MCP"
  keyDisplay: string         // "localhost:●●●●7 · SSE /sse" (masked)
  keyRevealed?: string       // value asli setelah reveal
  status: 'connected' | 'active' | 'not_set'
  testEndpoint?: string      // URL untuk test koneksi
  icon: LucideIcon
}
```

**Test button:**
- Klik → fetch test endpoint
- Loading state saat request
- Success: toast ok dengan detail
- Fail: toast error dengan error message

**Reveal button:**
- Toggle: masked ↔ revealed
- Teks button berubah "Reveal" ↔ "Hide"
- Timeout 30 detik → auto-mask kembali

**Add new key:**
- Tombol dashed di bawah list
- Buka mini-modal: nama service + env key name + value input
- Submit: validasi + simpan (note: di self-hosted ini edit .env, tampilkan instruksi jika tidak ada API untuk set)

---

## Task 7 — GF Pattern Manager Page

### Buat `apps/web/src/pages/GFPatternsPage.tsx`

Diakses via icon Search di nav kiri.

**State:**
```typescript
const [patterns, setPatterns] = useState<GFPattern[]>(DEFAULT_PATTERNS)
const [enabled, setEnabled] = useState<Record<string, boolean>>({})
const [testUrl, setTestUrl] = useState('')
const [matchSummary, setMatchSummary] = useState('')
const [editorOpen, setEditorOpen] = useState(false)
const [editorValue, setEditorValue] = useState('')
```

**DEFAULT_PATTERNS:** Hardcode 12 patterns dari `pentra-agent/pentra_agent/recon/gf_filter.py`
ke dalam konstanta TypeScript:
```typescript
const DEFAULT_PATTERNS: GFPattern[] = [
  { name: 'sqli_int', hint: 'Integer param → time-based blind injection', priority: 1,
    regex: /[\?&](id|cat|uid|pid|num|page|item|product)=\d+/i },
  // ... semua 12 patterns
]
```

**Upload zone:**
- Drag & drop area
- `<input type="file" accept=".json" multiple hidden>`
- Saat file dipilih: parse JSON, validasi schema, tambah ke patterns list
- Validasi: harus punya `name`, `regex` (valid regex string), `hint`, `priority`
- Error: toast jika JSON invalid atau regex invalid

**URL tester:**
- Input realtime (oninput) → test semua patterns
- Highlight baris yang match dengan badge hijau "Match"
- Summary text: "N patterns matched out of 22"
- Clear button

**Pattern table:**
- Kolom: name (monospace) | vuln hint | priority (P1/P2/P3 dengan warna) | test result | toggle
- Toggle: enable/disable pattern per baris
- Row hover: background subtle

**Pattern editor:**
- Textarea untuk JSON input
- Tombol "Validate JSON" → parse + test regex, tampilkan toast
- Tombol "Save Pattern" → add to patterns list
- Tombol "Cancel"

---

## Task 8 — Navigation Updates

### Update `apps/web/src/components/layout/AppShell.tsx`

Tambahkan route baru ke icon nav (semua sudah ada ikonnya di pentra-ui-v2.html):

```typescript
const NAV_ITEMS = [
  { icon: ShieldCheck, label: 'Engagements', path: '/' },
  { icon: Globe,       label: 'Attack Surface', path: '/surface' },
  { icon: BarChart2,   label: 'Trends', path: '/trends' },
]

const BOTTOM_ITEMS = [
  { icon: Lock,        label: 'API Vault', path: '/vault' },
  { icon: Search,      label: 'GF Patterns', path: '/patterns' },
  { icon: Settings,    label: 'Settings', path: '/settings' },
]
```

### Update `apps/web/src/App.tsx`

Tambahkan routes baru:
```typescript
<Route path="/surface"  element={<AttackSurfacePage />} />
<Route path="/trends"   element={<TrendsPage />} />
<Route path="/vault"    element={<ApiVaultPage />} />
<Route path="/patterns" element={<GFPatternsPage />} />
```

---

## Task 9 — Trends Page

### Buat `apps/web/src/pages/TrendsPage.tsx`

**Data source:** GET `/api/v1/workspaces/{id}/stats` atau aggregate dari
`/api/v1/engagements` list.

**Konten:**
1. KPI row (3 cards): Total confirmed findings | Engagements completed | KB records
   - Setiap card: big number + label + delta indicator dengan icon ArrowUp/Plus
   
2. Bar chart — Findings per engagement:
   - X axis: engagement names (truncated)
   - Y axis: count
   - Stacked bars per severity (critical merah, high oranye, medium kuning)
   - Library: **Recharts** (sudah ada di stack)
   ```typescript
   import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
   ```

3. Horizontal bar — Vulnerability classes:
   - 2-column grid
   - Setiap row: class name | track bar | count
   - Data dari aggregate findings per vuln_class
   - Warna bar: accent blue (tidak perlu per-severity di sini)

---

## Checklist

```
Task 1 — Notifications
[ ] useNotifications.ts hook
[ ] NotificationBell.tsx dengan badge count
[ ] NotificationPanel.tsx dengan 5 item types
[ ] Toast.tsx + ToastContainer.tsx
[ ] useToast() hook
[ ] Integrasi di AppShell.tsx topbar
[ ] WebSocket events → notifications (FINDING_CONFIRMED, AWAITING_APPROVAL, ENGAGEMENT_COMPLETED)

Task 2 — Scan Wizard
[ ] ScanWizard.tsx dengan 4 langkah
[ ] Step indicator (dot + line + label)
[ ] Step 1: domain + scope + exclusion validation
[ ] Step 2: 6 preset cards, pentra-ft highlighted, default selected
[ ] Step 3: auth toggle + conditional fields
[ ] Step 4: review table + launch hint
[ ] Submit: POST /api/v1/engagements + toast + navigate

Task 3 — Stop All
[ ] Stop button di topbar (muncul hanya saat ada running)
[ ] StopAllModal.tsx dengan list running engagements
[ ] Confirm → PATCH/stop semua + toast

Task 4 — Overview Card
[ ] EngagementOverviewCard.tsx
[ ] Muncul di sidebar saat klik running engagement
[ ] KPI 4 kolom dari real data
[ ] 3 action buttons functional

Task 5 — Attack Surface Map
[ ] AttackSurfacePage.tsx
[ ] Canvas dengan dot grid background
[ ] Node rendering dengan warna berdasarkan finding severity
[ ] SVG lines antar node
[ ] Detail panel slide-in dengan data real
[ ] Subscan button functional

Task 6 — API Vault
[ ] ApiVaultPage.tsx
[ ] Test button dengan loading state + real fetch
[ ] Reveal/hide dengan auto-mask 30s
[ ] Add new key modal

Task 7 — GF Patterns
[ ] GFPatternsPage.tsx
[ ] DEFAULT_PATTERNS dari gf_filter.py (12 patterns)
[ ] Upload .json dengan validasi
[ ] URL tester realtime dengan match highlight
[ ] Pattern editor dengan validate + save
[ ] Toggle enable/disable per pattern

Task 8 — Navigation
[ ] 6 nav items dengan Lucide icons (bukan emoji)
[ ] Routes di App.tsx
[ ] Active state per current route

Task 9 — Trends
[ ] TrendsPage.tsx
[ ] Recharts BarChart stacked per severity
[ ] Horizontal bars vuln classes
[ ] KPI cards dengan real data

Final
[ ] pnpm build — 0 errors, 0 TypeScript errors
[ ] pnpm test:e2e — pastikan tidak ada regression
[ ] Semua icon dari lucide-react, tidak ada emoji sebagai icon
[ ] Semua tombol dan interaksi functional (tidak ada dummy onClick)
[ ] git add apps/web/src/
[ ] git commit -m "feat(ui): Sprint UI-2 — notification system, scan wizard, attack surface map, API vault, GF patterns, trends"
```

---

## Urutan Eksekusi

```
1. Task 1 (Notifications + Toast)  — 45 min
   pnpm build setelah selesai

2. Task 3 (Stop All)               — 20 min
   pnpm build

3. Task 2 (Scan Wizard)            — 45 min
   pnpm build

4. Task 8 (Navigation routes)      — 20 min
   pnpm build

5. Task 4 (Overview Card)          — 25 min
   pnpm build

6. Task 6 (API Vault)              — 30 min
   pnpm build

7. Task 9 (Trends)                 — 30 min
   pnpm build

8. Task 7 (GF Patterns)            — 40 min
   pnpm build

9. Task 5 (Attack Surface Map)     — 45 min
   pnpm build

10. Final: pnpm test:e2e + git commit
```

**Prinsip selama implementasi:**
- Setiap task: `pnpm build` harus pass sebelum lanjut task berikutnya
- TypeScript strict — tidak boleh ada `any` kecuali benar-benar tidak bisa dihindari
- Semua icon dari `lucide-react` — import yang dibutuhkan saja
- Gunakan CSS variables yang sudah ada (`var(--critical)`, `var(--accent)`, dll)
  untuk semua warna — tidak hardcode hex baru
- Komponen baru mengikuti pola file yang sudah ada (hooks di `src/hooks/`,
  pages di `src/pages/`, components di `src/components/`)
