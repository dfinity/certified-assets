// Served only to authenticated requests. A logged-out visitor gets a certified
// 401 here instead of this file — a redirect would hand a <script> tag the wrong
// content type. Proof that *every* asset is gated, not just HTML pages.
document.getElementById("loaded-by").textContent =
  "app.js loaded — even scripts are gated behind the access cookie.";
