// A stand-in for a fingerprinted build asset (the kind bundlers emit into a
// hashed directory like `_astro/`, `_next/`, or `assets/`). Because its name
// changes whenever its contents change, it is safe to cache immutably — which
// is exactly what the `/_astro/*` rule in `_headers` does.
console.log("Hello from a long-lived, immutable asset.");
