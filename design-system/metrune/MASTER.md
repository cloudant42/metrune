# Design System Master File

> **LOGIC:** When building a specific page, first check `design-system/pages/[page-name].md`.
> If that file exists, its rules **override** this Master file.
> If not, strictly follow the rules below.

---

**Project:** Metrune
**Updated:** 2026-07-28
**Category:** Analytics Dashboard
**Design Dials:** Variance 3/10 (Centered / Minimal) | Motion 2/10 (Subtle) | Density 7/10 (Dashboard)

The implementation of record is `web/app/globals.css`. Every value below exists
there as a CSS custom property — read tokens from the variable, never hard-code
a hex in a component.

---

## Global Rules

### Theming

Light is the default. Dark is a **selected** set of steps, not an inversion, and
is declared twice: under `@media (prefers-color-scheme: dark)` scoped with
`:root:where(:not([data-theme="light"]))` (the OS preference) and under
`:root[data-theme="dark"]` (the viewer's own choice, which must win both ways).
The choice lives in `localStorage` under `metrune-theme` and is stamped on
`<html>` before first paint by `ThemeScript` in `web/components/theme.tsx`.

### Brand

The logo (`Metrune_logo.png`) is the source of the palette and the type: a deep
navy wordmark, an electric-blue peak, and a geometric sans. Two colors are
sampled straight from it and everything else is derived from them:

| Brand color | Hex | Role |
|-------------|-----|------|
| Metrune navy | `#001553` | Primary ink, darkest heatmap step, ink on bright fills in dark mode |
| Metrune blue | `#007cf1` | Accent family, categorical slot 1, the mark's bright peak |

The mark itself is `MarkIcon` in `web/components/icons.tsx` — the one two-tone
icon in the set (`--mark-deep` / `--mark-bright`). It sits on the page plane at
26px, never inside a colored tile, so it reads as the logo rather than an app
badge. `web/app/icon.svg` is the same mark reversed out of a navy tile.

### Color palette

| Role | Variable | Light | Dark |
|------|----------|-------|------|
| Page plane | `--bg` | `#f4f7fc` | `#050a18` |
| Surface (cards, panels) | `--surface` | `#ffffff` | `#0c1224` |
| Raised / inset fill | `--surface-2` | `#eef2f9` | `#121a30` |
| Track / chip fill | `--surface-3` | `#e3eaf6` | `#1a2440` |
| Hairline border | `--border` | `#dde4f0` | `#1e2947` |
| Border (hover) | `--border-strong` | `#c6d1e4` | `#2c3a5f` |
| Primary ink | `--fg` | `#001553` | `#eaeffb` |
| Secondary ink | `--fg-2` | `#38456b` | `#aebbd8` |
| Muted ink | `--muted` | `#5f6b8f` | `#8492b8` |
| Accent (marks, fills) | `--accent` | `#0070e0` | `#2b90ff` |
| Accent ink (text/links) | `--accent-ink` | `#0059bd` | `#86bfff` |
| Accent wash | `--accent-soft` | `#e6f1fe` | `#0d2044` |
| Ink on accent / danger fills | `--on-accent` `--on-danger` | `#ffffff` | `#001553` |
| Good / warning / danger | `--good` `--warn` `--danger` | `#0ca30c` `#fab219` `#d03b3b` | `#0ca30c` `#fab219` `#e66767` |

Neutrals are navy-tinted rather than grey — they are the logo's navy desaturated
toward the plane, which is what keeps the chrome and the mark in one family.
In the dark theme the accent is a *light* plane, so its ink is the brand navy
(`--on-accent`), not white; white would fall to 3.2:1 on `#2b90ff`.

Status colors are reserved for state and never reused as a series color; each
ships with a label, never color alone.

### Data visualization

Follows the `dataviz` method. Series slots come from the validated categorical
order — slot 1 blue `#0070e0` / `#2b90ff`, slot 2 orange `#eb6834` / `#f0794a`,
slot 3 aqua `#1baf7a` / `#22c08a` (`--series-1..3`), assigned in fixed order and
never cycled.

The heatmap ramp is eight paired steps (`--hm-1..8` with `--hm-ink-1..8`), and
it **runs in opposite directions per theme**: on the light plane it darkens
toward navy `#001553`, on the dark plane it brightens toward `#a7ceff`, so the
heaviest cell is always the one carrying the most weight against its own
surface. `web/components/charts.tsx` reads the steps as variables and holds no
hexes of its own.

Mark specs: 2px lines with round caps, ~10–18% area wash under the line, ≥8px
end markers with a 2px surface ring, 4px rounded data-ends on bars (square at
the baseline), hairline recessive gridlines. Every chart ships a hover tooltip
and a "View chart as table" fallback; a single-series chart carries no legend.

### Typography

Two faces, both vendored under `web/app/fonts/` and loaded with
`next/font/local` in `web/app/layout.tsx` — a build never calls a font CDN.

- **Display (`--font-display`, Poppins 600):** the wordmark's geometric face.
  It carries `h1, h2, h3` and the sidebar brand name, nothing else. Only weight
  600 ships, so never set 650/680 on a heading — the browser would synthesize it.
- **UI and figures (`--font-sans`, Inter 400–700 variable):** everything dense —
  body, controls, tables, stat values — at 14px base.
- **Code and identifiers only:** `--font-mono`.
- Large standalone values (stat tiles) use proportional figures;
  `font-variant-numeric: tabular-nums` is reserved for columns that must align
  (table cells, axis ticks).

### Shape and elevation

| Token | Value | Usage |
|-------|-------|-------|
| `--r-xs` | `6px` | Menu items, tab pills, inner cells |
| `--r-sm` | `8px` | Buttons, inputs, small chips |
| `--r` | `12px` | Panels, cards, filter bar |
| `--r-lg` | `16px` | Auth card, modals |
| `--shadow-sm` | hairline lift | Resting cards and panels |
| `--shadow` | soft ambient | Hover state of cards |
| `--shadow-lg` | deep ambient | Menus, popovers, auth card |

Spacing runs on a 4px rhythm: 4 / 8 / 12 / 16 / 22 / 28.

---

## Component Specs

### Navigation

- **Left sidebar** (236px) carries all chrome: the two-tone logo mark with the
  organization name beneath the wordmark, grouped nav (`Analyze`, `Manage`), and the account button in
  the footer.
- **Account menu** (sidebar footer): profile, settings, the Light/Dark/Auto
  theme switch, and sign in/out. This is the single home for account and
  appearance controls.
- **Page header** lives in the content column, not in a separate chrome band:
  a 26px title with a one-line description beneath it. No sticky top bar, no
  uppercase eyebrow, no status chips — connection state is already carried by
  the demo banner on the pages that have data.
- Below 1100px the sidebar collapses to icons; below 720px it becomes a bottom
  tab bar.

### Panel headers

Markup keeps the caption before the heading; the header renders it
`column-reverse` so the **title reads first and the caption sits under it**.
Captions are sentence-case descriptions ("Daily cost across the selected range"),
never uppercase labels.

### Buttons

```css
.btn        /* accent fill, 34px, radius 8, weight 600 */
.btn.ghost  /* surface fill, hairline border */
.btn.danger /* destructive fill */
.btn.small  /* 30px */
```

### Inputs

34px min height, hairline border, radius 8, `--ring` focus glow. Selects draw
their own chevron; native appearance is reset.

---

## Motion

Subtle only: 120–180ms `ease` on color, border, background and shadow. Menus
fade and rise 4px over 140ms. No layout-shifting hovers; cards change border and
shadow, never scale. `prefers-reduced-motion: reduce` collapses all durations.

---

## Anti-Patterns (Do NOT Use)

- ❌ Uppercase letter-spaced eyebrows above titles
- ❌ Emojis as icons — use the SVG set in `web/components/icons.tsx`
  (24px grid, 1.75 stroke, round caps)
- ❌ Hard-coded hex values in components — use the tokens (including the
  heatmap ramp, which is theme-aware and would otherwise invert in dark mode)
- ❌ Dual-axis charts, rainbow sequential ramps, cycled categorical hues
- ❌ Colored text carrying series identity (the mark beside it carries it)
- ❌ Instant state changes, invisible focus states, layout-shifting hovers
- ❌ Text contrast below 4.5:1

---

## Pre-Delivery Checklist

- [ ] Colors read from tokens, and the view was checked in light **and** dark
- [ ] Chart palette validated (`dataviz` validator) against both surfaces
- [ ] Charts ship a tooltip and a table fallback
- [ ] Icons from `components/icons.tsx`; no emoji
- [ ] Headings on Poppins at weight 600 only; no synthesized weights
- [ ] `cursor: pointer` and a visible focus ring on every control
- [ ] Transitions 120–300ms; `prefers-reduced-motion` respected
- [ ] Responsive at 375px, 768px, 1024px, 1440px, no horizontal scroll
- [ ] No content hidden behind the sticky top bar or the mobile tab bar
