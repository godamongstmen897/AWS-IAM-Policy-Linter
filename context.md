# SentinelIAM — Project Context & Progress Log

> This file is a living document. It is updated after every meaningful edit or commit to track what was built, what changed, and what's next.

---

## Project Overview

**Name:** SentinelIAM  
**Type:** React + TypeScript single-page app (Vite)  
**Purpose:** An AWS IAM policy linter and security analyzer with AI-powered insights.

Users paste an IAM policy JSON into a code editor panel, get instant static validation feedback with a live animated security score ring, and can trigger an AI analysis (powered by Anthropic Claude) for a detailed threat assessment. A "Smart Auto-Fix" feature rewrites the policy to follow the principle of least privilege.

**Tagline from metadata:** _"An instant AWS IAM policy validator that highlights overly permissive actions and resource risks."_

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | React 19 + TypeScript |
| Build tool | Vite 6 |
| Styling | Tailwind CSS v4 (via `@tailwindcss/vite`) + inline styles for component-level design tokens |
| Animation | CSS keyframes (`sentinelSlideIn`, `sentinelFadeIn`, `sentinelSpin`, `sentinelPulse`) |
| Icons | Inline SVG components (self-contained, no dependency) |
| AI | Anthropic Claude (`claude-sonnet-4-6`) via direct `fetch` to `api.anthropic.com` |
| Fonts | Space Grotesk (UI chrome) + JetBrains Mono (editor + metrics) via Google Fonts |
| Runtime env | Node.js, `.env.local` for secrets |

---

## Project Structure

```
AWS-IAM-Policy-Linter/
├── src/
│   ├── App.tsx          # Main application component (all UI + logic)
│   ├── types.ts         # TypeScript interfaces (IAMPolicy, IAMStatement, ValidationIssue, PolicyAnalysis)
│   ├── main.tsx         # React entry point
│   └── index.css        # Global styles
├── index.html           # HTML shell
├── vite.config.ts       # Vite config — injects GEMINI_API_KEY from .env
├── metadata.json        # App metadata (name, description)
├── package.json         # Dependencies & scripts
├── .env.example         # Environment variable template
└── context.md           # ← This file
```

---

## Core Features (Current State)

### 1. Policy Editor
- Full-height `textarea` with `JetBrains Mono`, amber caret
- Pre-loaded with a sample insecure policy (`Action: "*"`, `Resource: "*"`)
- Live badges in the editor header: Critical count / Warning count / ✓ Valid
- Copy-to-clipboard (with "Copied" confirmation) and Clear buttons in the navbar
- Footer bar: UTF-8 encoding, character length, pulsing LIVE indicator

### 2. Static Validator (`validatePolicy`)
Runs on every keystroke via `useEffect`. Checks for:

| Check | Severity |
|-------|----------|
| JSON syntax errors | Critical |
| Missing `Version` field | Info |
| Missing `Statement` field | Critical |
| Invalid/missing `Effect` (must be Allow/Deny) | Critical |
| Missing `Action` or `NotAction` | Critical |
| Full admin wildcard `Action: "*"` | Critical |
| Service-wide wildcard `Action: "s3:*"` etc. | Warning |
| Missing `Resource` or `NotResource` | Critical |
| Unrestricted `Resource: "*"` with Effect Allow | Warning |
| Privilege escalation actions (11 checked, e.g. `iam:PassRole`) | Critical |
| Sensitive Allow action with no `Condition` block | Warning |

### 3. Animated Security Score Ring
- SVG arc that redraws live on every keystroke
- CSS transition: `stroke-dasharray 0.6s cubic-bezier(.4,0,.2,1)`
- Color transitions: `#E5484D` (0–49) → `#F0A500` (50–79) → `#30A46C` (80–100)
- `drop-shadow` glow effect matches the current score color
- Label beneath ring: **CRITICAL** / **AT RISK** / **SECURE**
- Score formula: `max(0, 100 − criticals×35 − warnings×10)`

### 4. Stat Grid
- Three tiles: Critical / Warning / Info counts
- Numbers are dimmed `#2D3748` when zero, colored when non-zero

### 5. AI Security Analysis (Anthropic Claude)
- Calls `claude-sonnet-4-6` via direct `fetch` to `https://api.anthropic.com/v1/messages`
- Prompt asks for: key risks, least-privilege violations, specific remediation steps
- Clicking the button auto-switches to the AI Advisory tab
- Lightweight inline markdown renderer (bold, inline code, headers, bullets)
- Works on any valid-JSON policy (not gated on `isValid`)

### 6. Smart Auto-Fix (Anthropic Claude)
- Asks Claude to rewrite the policy following least privilege
- Returns only JSON — strips any markdown fences before setting editor state
- Works on **any** policy regardless of issue count — always available
- Falls back silently if the returned text isn't valid JSON

### 7. Tabbed Right Panel
- **Issues tab** — animated issue cards with stagger delay, severity bar, field tag, statement index, suggestion
- **AI Advisory tab** — AI output or empty state prompt
- Tab labels show live issue count: `Issues (4)`

### 8. UI / Design System
- Palette: `#060B18` base → `#080D1A` navbar/footer → `#0D1526` panels — 3-step depth
- Amber `#F0A500` brand accent, `#E5484D` critical red, `#30A46C` pass green
- `Space Grotesk` for all UI chrome; `JetBrains Mono` for editor and all metric values
- Inline SVG icon system — no icon library dependency
- Global keyframe animations scoped with `sentinel` prefix to avoid collisions

---

## Environment Setup

```bash
npm install
cp .env.example .env.local
# No API key needed in .env for current Claude integration
# (API key handled via Anthropic's environment in this setup)
npm run dev   # Starts on http://localhost:3000
```

---

## Known Issues / Limitations

- **No multi-policy support** — one policy at a time; no diffing between before/after fix.
- **No export** — results exist only in-session; no download as JSON or PDF report.
- **Condition block not deeply validated** — presence is checked for sensitive actions, but the actual condition keys/values are not evaluated.
- **AI calls are unauthenticated client-side** — `callClaude` sends directly from the browser; fine for this environment, but would need a backend proxy for production.
- **Score is heuristic** — formula is `100 - crits×35 - warns×10`; doesn't account for policy complexity, effective permissions, or cross-statement interactions.
- **No responsive/mobile layout** — right panel is fixed 380px; below ~900px the layout breaks.
- **`motion` and `lucide-react` still in `package.json`** — unused after the redesign; safe to remove for a clean dependency tree.

---

## Progress Log

### Session 1 — June 19, 2026
- **Status:** Project initialized from Google AI Studio scaffold.
- **What exists:** Full working single-file app (`App.tsx`) with static validator, AI analysis, smart fix, dark theme UI.
- **Created `context.md`** to track ongoing development.

---

### Session 2 — June 19, 2026 — Full UI Redesign

**Goal:** Transform the competent-but-generic dark-theme dev tool into a real security product with a distinct visual identity.

#### What changed

**Palette overhaul**
- Base: `#060B18` deep navy (replaces muddy `#0B0E14`)
- Panels: `#080D1A` / `#0D1526` — deliberate 3-step depth system
- Amber `#F0A500` retained as brand equity
- Critical red `#E5484D`, pass green `#30A46C`, neutral `#8B949E`

**Signature element: Animated Score Ring**
- SVG arc redraws live on every keystroke
- Transitions color: red → amber → green with a `drop-shadow` glow
- Score label beneath the ring: CRITICAL / AT RISK / SECURE
- First thing the eye lands on — communicates risk posture in 2 seconds

**Layout restructured (two-column)**
- Score ring now anchors the top of the right panel
- Stat grid (Critical / Warning / Info counts) sits directly below the ring
- AI Analysis + Smart Fix buttons follow immediately — all above the fold
- Tabbed panel: `Issues` | `AI Advisory` — clean separation, no scrolling past issues to find AI output

**Typography**
- `Space Grotesk` for all UI chrome — precise/technical without being generic
- `JetBrains Mono` stays for the editor textarea and all code/metric values
- The pairing reads "engineering tool" not "weekend project"

**AI backend switched**
- Was: `@google/genai` Gemini SDK
- Now: Direct `fetch` to Anthropic Claude (`claude-sonnet-4-6`) — functional in this environment
- `callClaude()` utility handles prompt → response cleanly
- Smart Fix now works on **any** policy (not gated on `isValid`) — removed that UX friction

**Removed**
- Decorative 40-line number column (non-functional)
- Fake `MEM: PAS` footer stats
- Disabled-state Smart Fix button — it now always works

**Validator improvements**
- Added `info` severity for missing `Version` field
- Added `Condition` block check: sensitive Allow actions with no Condition → warning
- `score` field added to `PolicyAnalysis` type in `types.ts`
- Score formula: `max(0, 100 - criticals×35 - warnings×10)`

**TypeScript**
- All components properly typed — `tsc --noEmit` passes clean

---

_Last updated: June 19, 2026 — context.md fully synced with current codebase_
