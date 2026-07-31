import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://keystore-explorer.org',
  // Astro's default ("jsx") strips whitespace-only text nodes that span a
  // newline entirely, unlike plain HTML which collapses them to one space.
  // That silently ate the space before inline tags (e.g. text ending a line
  // followed by <a> on the next line). `true` gives HTML-aware collapsing
  // instead, still minifying but never dropping a needed space.
  compressHTML: true,
  // Allow both "/history" and "/history/" (dev/preview server otherwise 404s
  // on the trailing-slash form for directory-style routes like /history/).
  trailingSlash: 'ignore',
  // The Contribute page was retired; forward old bookmarks/search-engine
  // links straight to the contribution guide on GitHub. GitHub Pages serves
  // static files only, so with no adapter installed this renders as a
  // client-side <meta http-equiv="refresh"> redirect page at contribute.html.
  redirects: {
    '/contribute': 'https://github.com/kaikramer/keystore-explorer/blob/main/CONTRIBUTING.md',
  },
  build: {
    // Emit "page.html" instead of "page/index.html" to keep the exact
    // original URLs (e.g. /doc/5.4/certificateExtensions.html).
    format: 'file',
  },
});
