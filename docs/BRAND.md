# Maltrail logo

| asset | file | use |
| --- | --- | --- |
| lockup | [`logo.svg`](logo.svg), [`logo-dark.svg`](logo-dark.svg) | README and large surfaces: 爪 + wordmark + foot |
| icon | [`../html/images/mlogo.svg`](../html/images/mlogo.svg), [`../html/favicon.ico`](../html/favicon.ico) | anything under ~64 px: dashboard header, favicon, avatars. The 爪 alone, never the foot |
| social preview | [`social-preview.png`](social-preview.png) | GitHub link previews; uploaded by hand under Settings → General → Social preview |

* **Wordmark** — JetBrains Mono Bold (OFL), converted to outlines, the same in the README and the dashboard
  (`main.js` injects it inline in `currentColor`, so it follows the theme).
* **Gold** `#f2b705`, outline `#111`, then a white keyline: the keyline carries the glyph on dark backgrounds.
* **The foot** is the crisp print over its own 10-unit mosaic, cell opacity = ink coverage: the trail as lossy
  data, and Maltrail recovering it. It only works large, which is why the icon leaves it out.
