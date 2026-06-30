import './style.css'
import logo from '/logo.png'

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div>
    <a href="https://internetcomputer.org" target="_blank">
      <img src="${logo}" class="logo" alt="DFINITY logo" />
    </a>
    <button id="clear-token">
      Clear Password 
    </button>
  </div>
`

/** Clears the IC_AUTH_TOKEN cookie by expiring it (path `/`, matching how it's set). */
function clearAuthToken() {
  document.cookie = 'IC_AUTH_TOKEN=; path=/; Max-Age=0; SameSite=Lax'
}

document
  .querySelector<HTMLButtonElement>('#clear-token')!
  .addEventListener('click', clearAuthToken)
