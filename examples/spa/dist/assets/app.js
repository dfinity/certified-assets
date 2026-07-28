// A deliberately tiny client-side router — no framework, no build step.
//
// The point of the example is the *server* contract: because `_redirects` maps
// `/*` to `/index.html` with a 200, this script runs no matter which URL the
// visitor loads or reloads, and can read `location.pathname` to decide what to
// render.

const routes = {
  "/": "Home — you loaded the shell at the root.",
  "/dashboard": "Dashboard — a client route with no file behind it.",
  "/dashboard/settings/deep":
    "Deeply nested client route — still the same shell, still a 200.",
};

function render() {
  const path = location.pathname;
  const known = routes[path];
  document.getElementById("app").innerHTML = `
    <p><strong>Route:</strong> <code>${path}</code></p>
    <p>${known ?? "Unknown client route — the app decides this is a 404, not the canister."}</p>
  `;
}

// Intercept in-app navigation so it never round-trips to the canister.
document.addEventListener("click", (event) => {
  const link = event.target.closest("a[data-link]");
  if (!link) return;
  event.preventDefault();
  history.pushState({}, "", link.getAttribute("href"));
  render();
});

// Back/forward buttons.
addEventListener("popstate", render);

render();
