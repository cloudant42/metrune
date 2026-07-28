# Bundled webfonts

Vendored so a build (including an air-gapped one) never reaches a font CDN.
Both families are licensed under the SIL Open Font License 1.1.

| File | Family | Weights | Subset | Upstream |
|------|--------|---------|--------|----------|
| `inter-latin.woff2` | Inter | 400–700 (variable) | latin | https://fonts.google.com/specimen/Inter |
| `inter-latin-ext.woff2` | Inter | 400–700 (variable) | latin-ext | ” |
| `poppins-600-latin.woff2` | Poppins | 600 | latin | https://fonts.google.com/specimen/Poppins |
| `poppins-600-latin-ext.woff2` | Poppins | 600 | latin-ext | ” |

Inter is the UI face (`--font-sans`); Poppins matches the wordmark and is used
for titles only (`--font-display`), which is why a single weight is enough.
Both are wired up with `next/font/local` in `web/app/layout.tsx` — if you add a
weight, add the file here and a `src` entry there, and never set a display
weight the file does not contain (the browser would synthesize it).
