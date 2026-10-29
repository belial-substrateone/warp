# Vendored third-party files

Obtained 2026-10-29 with `npm pack @xterm/xterm@5.5.0 @xterm/addon-fit@0.10.0 @xterm/addon-web-links@0.11.0` (all MIT; license texts in LICENSE-*).
UMD builds (`lib/*.js`), loaded as classic scripts exposing globals `Terminal`, `FitAddon.FitAddon`, `WebLinksAddon.WebLinksAddon`.

| file | package | version | source path in tarball |
|---|---|---|---|
| xterm.js | @xterm/xterm | 5.5.0 | lib/xterm.js |
| xterm.css | @xterm/xterm | 5.5.0 | css/xterm.css |
| addon-fit.js | @xterm/addon-fit | 0.10.0 | lib/addon-fit.js |
| addon-web-links.js | @xterm/addon-web-links | 0.11.0 | lib/addon-web-links.js |

Only modification: the trailing `//# sourceMappingURL=...` comment was stripped from the three .js files (the .map files are not vendored,
so the browser would 404 on them). Original sha256 (xterm.js, addon-fit.js, addon-web-links.js): 1f991ac3b4b283ebf96e60ae23a00a52765dd3a2e46fa6fdda9f1aab032f7495 bdaefa370b1bfc42ee88d46fe6072400902a4d4b2d45cd93438dda9b23c97089 f230a6c8211ce4614dda5441f27b603c7c1ca95151a655bc0efac6377ee643f0 

## sha256 of files as vendored
```
7a88e46a58847d3f17109e3d48cc8aa056a01997d00ceb76035f63370712d858  xterm.js
ba8e6985669488981ccf40c0cefe3aba80722cb6c92de7ad628b0bd717faf2b6  xterm.css
3e9ae6f6965ee1269d5574b905cf1bf559c2f44c784255b0034a71387e7719c9  addon-fit.js
2ddb5fa9fca2c1d2bc47dd9480f4ff41a38cb44e1ff32001a72ba074c01c723f  addon-web-links.js
e256f01188af527e4d06d21d06fbf785ae9c50d4b328bf03cbe0ba7f0aa4228f  LICENSE-addon-fit
689ceb10716bd7a87a804c14951d7c2b818cbd60aab83d540902470ce3b13444  LICENSE-addon-web-links
b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd  LICENSE-xterm
```
