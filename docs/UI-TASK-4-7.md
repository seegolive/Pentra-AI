# UI POLISH — Task 4–7
> Prereq: Task 1–3 selesai (design tokens, CSS vars, AppShell 3-column)
> Referensi visual: `pentra-design-system.html`

---

## Commit Task 1–3 Dulu

```bash
git add apps/web/src/components/AppShell.tsx \
        apps/web/src/index.css \
        apps/web/tailwind.config.ts
git rm --cached apps/web/tailwind.config.js
git add -u apps/web/tailwind.config.js
git commit -m "feat(ui): design system foundation — tokens, CSS vars, 3-column shell"
```

---

## Task 4 — Sidebar Engagement List

> **File:** `apps/web/src/components/AppShell.tsx` (sidebar section)
> atau extract ke `apps/web/src/components/layout/EngagementSidebar.tsx`

### Status dot component

```tsx
// Tambahkan di dalam AppShell atau komponen terpisah

type EngagementStatus = 'running' | 'waiting' | 'complete' | 'failed' | 'idle'

function StatusDot({ status }: { status: EngagementStatus }) {
  const colors: Record<EngagementStatus, string> = {
    running:  'var(--status-running)',
    waiting:  'var(--status-waiting)',
    complete: 'var(--status-complete)',
    failed:   'var(--status-failed)',
    idle:     'var(--text-muted)',
  }
  return (
    <span
      className="inline-block w-1.5 h-1.5 rounded-full shrink-0"
      style={{
        background: colors[status],
        animation: status === 'running'
          ? 'pulseDot 1.4s ease-in-out infinite'
          : undefined,
      }}
    />
  )
}
```

### Sidebar item component

```tsx
interface SidebarEngagementItemProps {
  name: string
  status: EngagementStatus
  meta: string        // e.g. "8 confirmed · 2h ago"
  isActive?: boolean
  onClick?: () => void
}

function SidebarEngagementItem({
  name, status, meta, isActive, onClick
}: SidebarEngagementItemProps) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left px-3 py-2.5 rounded-lg transition-colors duration-100 mb-0.5"
      style={{
        background: isActive ? 'var(--bg-active)' : 'transparent',
      }}
      onMouseEnter={e => {
        if (!isActive)
          (e.currentTarget as HTMLElement).style.background = 'var(--bg-card)'
      }}
      onMouseLeave={e => {
        if (!isActive)
          (e.currentTarget as HTMLElement).style.background = 'transparent'
      }}
    >
      <div
        className="text-[13px] font-medium mb-1 truncate"
        style={{ color: 'var(--text-primary)' }}
      >
        {name}
      </div>
      <div className="flex items-center gap-2">
        <StatusDot status={status} />
        <span className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>
          {meta}
        </span>
      </div>
    </button>
  )
}
```

### Sidebar section label

```tsx
function SidebarSection({ label }: { label: string }) {
  return (
    <div
      className="px-3 pt-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.8px]"
      style={{ color: 'var(--text-muted)' }}
    >
      {label}
    </div>
  )
}
```

### New Engagement button

```tsx
// Di header sidebar, ganti tombol biasa dengan:
<button
  className="w-6 h-6 rounded flex items-center justify-center text-white text-base font-bold transition-opacity hover:opacity-80"
  style={{ background: 'var(--accent)' }}
  onClick={() => { /* navigate to new engagement */ }}
>
  +
</button>
```

---

## Task 5 — Live Feed Component

> **File:** `apps/web/src/components/engagement/LiveFeed.tsx` (atau yang sudah ada)

### Event item

```tsx
type EventType = 'node_start' | 'node_complete' | 'llm_stream' | 'finding' | 'hitl' | 'info'

interface FeedEventProps {
  time: string
  type: EventType
  node: string
  text: string         // HTML allowed — sanitize jika user-generated
  delay?: number       // stagger animation delay in ms
}

const EVENT_ICONS: Record<EventType, string> = {
  node_start:    '▶',
  node_complete: '✓',
  llm_stream:    '◈',
  finding:       '⬤',
  hitl:          '⏸',
  info:          '·',
}

const EVENT_STYLES: Record<EventType, { icon: string; bg?: string; border?: string }> = {
  node_start:    { icon: 'var(--accent-light)' },
  node_complete: { icon: 'var(--status-complete)' },
  llm_stream:    { icon: 'var(--text-muted)' },
  finding:       { icon: 'var(--critical)' },
  hitl:          { icon: 'var(--status-waiting)', bg: 'rgba(245,197,66,0.05)', border: 'rgba(245,197,66,0.18)' },
  info:          { icon: 'var(--text-muted)' },
}

function FeedEvent({ time, type, node, text, delay = 0 }: FeedEventProps) {
  const style = EVENT_STYLES[type]
  return (
    <div
      className="flex gap-3 px-3 py-2 rounded-lg group hover:transition-colors"
      style={{
        background: style.bg,
        border: style.border ? `1px solid ${style.border}` : '1px solid transparent',
        animation: `fadeSlideIn 0.18s ease both`,
        animationDelay: `${delay}ms`,
      }}
      onMouseEnter={e => {
        if (!style.bg)
          (e.currentTarget as HTMLElement).style.background = 'var(--bg-card)'
      }}
      onMouseLeave={e => {
        if (!style.bg)
          (e.currentTarget as HTMLElement).style.background = style.bg || 'transparent'
      }}
    >
      {/* Timestamp */}
      <span
        className="shrink-0 mt-0.5 text-[10px] leading-none"
        style={{ color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace', minWidth: 56 }}
      >
        {time}
      </span>

      {/* Icon */}
      <span
        className="shrink-0 mt-0.5 text-[13px] w-4 text-center"
        style={{ color: style.icon }}
      >
        {EVENT_ICONS[type]}
      </span>

      {/* Body */}
      <div className="flex-1 min-w-0">
        <div
          className="text-[10px] font-semibold uppercase tracking-[0.5px] mb-0.5"
          style={{ color: 'var(--text-muted)' }}
        >
          {node}
        </div>
        <div
          className="text-[12px] leading-relaxed break-all"
          style={{
            color: type === 'llm_stream' ? 'var(--text-code)' : 'var(--text-secondary)',
            fontFamily: type === 'llm_stream' ? 'JetBrains Mono, monospace' : undefined,
          }}
          dangerouslySetInnerHTML={{ __html: text }}  // sanitize jika perlu
        />
      </div>
    </div>
  )
}
```

### HITL Approval Card

```tsx
interface HITLCardProps {
  phase: string
  summary: string
  onApprove: () => void
  onSkip?: () => void
  onStop?: () => void
}

function HITLCard({ phase, summary, onApprove, onSkip, onStop }: HITLCardProps) {
  return (
    <div
      className="rounded-xl p-4 my-3 animate-fade-up"
      style={{
        background: 'var(--bg-card)',
        border: '1px solid rgba(245,197,66,0.28)',
      }}
    >
      <div className="flex items-center gap-2 mb-3">
        <span className="text-base">⏸</span>
        <span className="text-[13px] font-semibold" style={{ color: 'var(--status-waiting)' }}>
          Awaiting Approval — {phase}
        </span>
      </div>
      <p className="text-[12px] leading-relaxed mb-4" style={{ color: 'var(--text-secondary)' }}>
        {summary}
      </p>
      <div className="flex gap-2">
        <button
          onClick={onApprove}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[12px] font-semibold text-white transition-opacity hover:opacity-85"
          style={{ background: 'var(--accent)' }}
        >
          ✓ Approve &amp; Continue
        </button>
        {onSkip && (
          <button
            onClick={onSkip}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[12px] font-semibold transition-colors"
            style={{
              background: 'transparent',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-light)',
            }}
          >
            Skip Phase
          </button>
        )}
        {onStop && (
          <button
            onClick={onStop}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold"
            style={{
              background: 'rgba(255,59,92,0.12)',
              color: 'var(--critical)',
              border: '1px solid rgba(255,59,92,0.25)',
            }}
          >
            ✕ Stop
          </button>
        )}
      </div>
    </div>
  )
}
```

### Feed right panel — stat grid

```tsx
function StatCard({
  value, label, colorVar
}: {
  value: string | number
  label: string
  colorVar?: string
}) {
  return (
    <div
      className="rounded-lg p-3"
      style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}
    >
      <div
        className="text-[22px] font-bold leading-none tracking-tight"
        style={{ color: colorVar || 'var(--text-primary)' }}
      >
        {value}
      </div>
      <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-muted)' }}>
        {label}
      </div>
    </div>
  )
}

// Usage:
// <div className="grid grid-cols-2 gap-2">
//   <StatCard value={critCount} label="Critical" colorVar="var(--critical)" />
//   <StatCard value={highCount} label="High"     colorVar="var(--high)" />
//   <StatCard value={medCount}  label="Medium"   colorVar="var(--medium)" />
//   <StatCard value={subCount}  label="Subdomains" colorVar="var(--low)" />
// </div>
```

---

## Task 6 — Findings Table

> **File:** `apps/web/src/components/engagement/FindingsTable.tsx`

### Severity badge — gunakan CSS class dari index.css

```tsx
function SeverityBadge({ severity }: { severity: 'critical' | 'high' | 'medium' | 'low' | 'info' }) {
  return <span className={`severity-badge ${severity}`}>{severity}</span>
}
```

### Filter chips

```tsx
const SEVERITY_FILTERS = [
  { label: 'All',      key: 'all',      color: undefined },
  { label: 'Critical', key: 'critical', color: 'var(--critical)' },
  { label: 'High',     key: 'high',     color: 'var(--high)' },
  { label: 'Medium',   key: 'medium',   color: 'var(--medium)' },
  { label: 'Low',      key: 'low',      color: 'var(--low)' },
] as const

function FilterChip({
  label, active, color, count, onClick
}: {
  label: string
  active: boolean
  color?: string
  count?: number
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold transition-all"
      style={{
        border: `1px solid ${active && color ? color : 'var(--border)'}`,
        color: active ? (color || 'var(--text-primary)') : 'var(--text-muted)',
        background: active && color
          ? color.replace(')', ', 0.1)').replace('var(--', 'rgba(').replace(')', '')  // crude — better to hardcode
          : 'transparent',
      }}
    >
      {label}
      {count !== undefined && (
        <span
          className="px-1.5 py-0 rounded-full text-[10px] font-bold"
          style={{
            background: active && color ? color : 'var(--bg-hover)',
            color: active && color ? 'white' : 'var(--text-muted)',
          }}
        >
          {count}
        </span>
      )}
    </button>
  )
}
```

### Finding row (expandable)

```tsx
interface FindingRowProps {
  finding: {
    id: string
    severity: 'critical' | 'high' | 'medium' | 'low'
    title: string
    endpoint: string
    cvss: number
    status: 'confirmed' | 'triage' | 'false_positive'
    description?: string
    request?: string
    response?: string
  }
  isExpanded: boolean
  onToggle: () => void
  onConfirm: (id: string) => void
  onFalsePositive: (id: string) => void
}

function FindingRow({ finding, isExpanded, onToggle, onConfirm, onFalsePositive }: FindingRowProps) {
  const cvssColor = finding.cvss >= 9 ? 'var(--critical)'
    : finding.cvss >= 7 ? 'var(--high)'
    : finding.cvss >= 4 ? 'var(--medium)'
    : 'var(--low)'

  return (
    <div
      className="border-b transition-colors cursor-pointer"
      style={{
        borderColor: 'var(--border)',
        background: isExpanded ? 'var(--bg-card)' : 'transparent',
      }}
    >
      {/* Header row */}
      <div
        className="grid items-center gap-4 px-6 py-3 hover:bg-[var(--bg-card)]"
        style={{ gridTemplateColumns: '100px 1fr 160px 72px 104px' }}
        onClick={onToggle}
      >
        <SeverityBadge severity={finding.severity} />
        <span className="text-[13px] font-medium truncate" style={{ color: 'var(--text-primary)' }}>
          {finding.title}
        </span>
        <span
          className="text-[11px] truncate"
          style={{ color: 'var(--text-code)', fontFamily: 'JetBrains Mono, monospace' }}
        >
          {finding.endpoint}
        </span>
        <span className="text-[13px] font-bold" style={{ color: cvssColor }}>
          {finding.cvss.toFixed(1)}
        </span>
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-[0.3px] ${
            finding.status === 'confirmed' ? 'text-[var(--status-complete)]' : 'text-[var(--status-waiting)]'
          }`}
          style={{
            background: finding.status === 'confirmed'
              ? 'rgba(46,207,142,0.1)' : 'rgba(245,197,66,0.1)',
          }}
        >
          {finding.status}
        </span>
      </div>

      {/* Expanded detail */}
      {isExpanded && (
        <div
          className="px-6 pb-5 border-t animate-fade-up"
          style={{ borderColor: 'var(--border)' }}
        >
          <div className="grid grid-cols-2 gap-4 my-4">
            {finding.description && (
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-[0.6px] mb-2" style={{ color: 'var(--text-muted)' }}>
                  Description
                </div>
                <p className="text-[12px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                  {finding.description}
                </p>
              </div>
            )}
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-[0.6px] mb-2" style={{ color: 'var(--text-muted)' }}>
                CVSS Vector
              </div>
              <code className="text-[10px]" style={{ color: 'var(--text-code)' }}>
                CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
              </code>
            </div>
          </div>

          {finding.request && (
            <>
              <div className="text-[10px] font-semibold uppercase tracking-[0.6px] mb-2" style={{ color: 'var(--text-muted)' }}>
                HTTP Request
              </div>
              <div className="code-block">{finding.request}</div>
            </>
          )}

          <div className="flex gap-2 mt-4">
            <button
              onClick={() => onConfirm(finding.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold text-white"
              style={{ background: 'var(--accent)' }}
            >
              ✓ Confirm
            </button>
            <button
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold"
              style={{
                background: 'transparent',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-light)',
              }}
            >
              Add to Report
            </button>
            <button
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold"
              style={{
                background: 'transparent',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-light)',
              }}
            >
              Copy H1 Format
            </button>
            <button
              onClick={() => onFalsePositive(finding.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold"
              style={{
                background: 'rgba(255,59,92,0.1)',
                color: 'var(--critical)',
                border: '1px solid rgba(255,59,92,0.25)',
              }}
            >
              ✕ False Positive
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
```

---

## Task 7 — Report Viewer Polish

> **File:** `apps/web/src/components/engagement/ReportViewer.tsx`

### KPI summary grid

```tsx
function ReportKPI({
  value, label, colorVar
}: {
  value: number | string
  label: string
  colorVar: string
}) {
  return (
    <div
      className="rounded-xl p-4 text-center"
      style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)' }}
    >
      <div
        className="text-[28px] font-bold leading-none tracking-tight"
        style={{ color: colorVar }}
      >
        {value}
      </div>
      <div className="text-[10px] uppercase tracking-[0.5px] mt-1" style={{ color: 'var(--text-muted)' }}>
        {label}
      </div>
    </div>
  )
}

// Usage inside report header:
// <div className="grid grid-cols-4 gap-3 mb-8">
//   <ReportKPI value={2} label="Critical" colorVar="var(--critical)" />
//   <ReportKPI value={0} label="High"     colorVar="var(--high)" />
//   <ReportKPI value={2} label="Medium"   colorVar="var(--medium)" />
//   <ReportKPI value={4} label="Confirmed" colorVar="var(--low)" />
// </div>
```

### Report action bar (sticky bottom)

```tsx
function ReportActionBar({ onDownloadPDF, onDownloadMD }: {
  onDownloadPDF: () => void
  onDownloadMD: () => void
}) {
  return (
    <div
      className="sticky bottom-0 flex items-center gap-3 px-10 py-3 border-t"
      style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
    >
      <button
        onClick={onDownloadPDF}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-[12px] font-semibold text-white"
        style={{ background: 'var(--accent)' }}
      >
        ↓ Download PDF
      </button>
      <button
        onClick={onDownloadMD}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-[12px] font-semibold"
        style={{
          background: 'transparent',
          color: 'var(--text-secondary)',
          border: '1px solid var(--border-light)',
        }}
      >
        ↓ Markdown
      </button>
      <button
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-[12px] font-semibold"
        style={{
          background: 'transparent',
          color: 'var(--text-secondary)',
          border: '1px solid var(--border-light)',
        }}
      >
        H1 Format
      </button>
    </div>
  )
}
```

---

## Checklist Task 4–7

```
Task 4 — Sidebar
[ ] StatusDot dengan pulse animation untuk "running"
[ ] SidebarEngagementItem dengan nama, dot, meta text
[ ] SidebarSection label (Active / Recent)
[ ] + button untuk new engagement
[ ] Tidak ada regression di existing sidebar behavior

Task 5 — Live Feed
[ ] FeedEvent dengan 6 tipe (node_start, complete, llm_stream, finding, hitl, info)
[ ] Timestamps dengan JetBrains Mono font
[ ] HITL approval card dengan 3 actions (Approve, Skip, Stop)
[ ] Stat grid (Critical / High / Medium / Subdomains)
[ ] Tool pipeline progress list
[ ] Scroll to bottom saat event baru masuk

Task 6 — Findings Table
[ ] SeverityBadge menggunakan class dari index.css
[ ] FilterChip dengan count dan active state
[ ] Expandable row — click untuk expand, click lagi untuk collapse
[ ] Hanya satu row yang expanded sekaligus
[ ] 4 action buttons di expanded state
[ ] Grid columns: severity | title | endpoint | cvss | status

Task 7 — Report Viewer
[ ] KPI grid 4 kolom dengan warna per severity
[ ] Section headers dengan border-bottom
[ ] Finding cards dengan dl.report-dl layout
[ ] Sticky action bar di bottom dengan PDF/MD/H1 buttons
[ ] ToC sidebar jika layout memungkinkan

Final commit:
[ ] git add apps/web/src/
[ ] git commit -m "feat(ui): polish components — sidebar, live feed, findings, report"
[ ] pnpm build — no error
[ ] pnpm test:e2e — Playwright masih pass (atau update jika selector berubah)
```

---

## Urutan Eksekusi yang Disarankan

```
1. Task 4 (Sidebar)         — 30 menit  → visual impact langsung saat buka app
2. Task 5 (Live Feed)       — 45 menit  → halaman yang paling sering dilihat
3. Task 6 (Findings Table)  — 45 menit  → core workflow
4. Task 7 (Report Viewer)   — 30 menit  → output final

Total estimasi: ~2.5 jam
```
