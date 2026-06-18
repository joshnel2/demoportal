/* STA Admin Portal — login + dashboard. */

console.log('[asa] admin.js loaded');

// Global error handler so failures show up on the page, not in silence.
window.addEventListener('error', (ev) => {
  try {
    console.error('[asa] global error:', ev.error || ev.message);
    const err = document.getElementById('loginError');
    if (err) {
      err.hidden = false;
      err.textContent = 'JS error: ' + (ev.message || 'unknown') + (ev.filename ? ' (' + ev.filename.split('/').pop() + ':' + ev.lineno + ')' : '');
    }
  } catch {}
});

const VAULT_URL = 'vault.json';
const SESSION_KEY = 'asa_session_v3';

/* When the Azure backend is deployed, set this to your Function App URL,
 * e.g. 'https://asa-api-yourname.azurewebsites.net'. Empty = local mode
 * (login uses FALLBACK_USERS, uploads go straight to GitHub from browser,
 * dashboards read admin/data.json). */
// Azure backend retired — the portal now runs entirely on the static site +
// GitHub + admin/data.json. Empty API_BASE makes login/dashboard skip Azure
// (faster login, and the Azure App Service / Storage / SQL can be deleted safely).
const API_BASE = '';

async function apiPost(path, body) {
  if (!API_BASE) return null;
  const r = await fetch(API_BASE + path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error('API ' + path + ' returned ' + r.status);
  return r.json();
}
async function apiGet(path) {
  if (!API_BASE) return null;
  const r = await fetch(API_BASE + path, { credentials: 'include' });
  if (!r.ok) throw new Error('API ' + path + ' returned ' + r.status);
  return r.json();
}
async function apiDelete(path) {
  if (!API_BASE) return null;
  const r = await fetch(API_BASE + path, { method: 'DELETE', credentials: 'include' });
  if (!r.ok) throw new Error('API ' + path + ' returned ' + r.status);
  return r.json();
}
function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  return d.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
}

// Emergency reset: /admin/?reset clears any stuck session.
if (location.search.includes('reset')) {
  try { sessionStorage.clear(); localStorage.clear(); } catch {}
  history.replaceState(null, '', location.pathname);
}

/* ----- ATTACH LOGIN HANDLER FIRST, before any other code that might throw ----- */
// Login credentials are stored as SHA-256 hashes — the plaintext passwords are
// no longer present in this file. The same passwords still work; sha256Hex()
// below hashes what the user types and compares it to pwHash.
const FALLBACK_USERS = {
  jdorf:      { pwHash: 'ef4055eed6265c545094a05ba018033373895870a1620e5fb0b546aa45b0e4fe', role: 'admin',      name: 'A. Stone',         section: null },
  gdorf:      { pwHash: '237224c132e17f7f73113f25b4f5ef5b1969d82561d3a9bcb490b05c5d5a9343', role: 'admin',      name: 'M. Stone',         section: null, keyEnc: {"salt": "VZ+6FfCenAprrQfZPf8SNA==", "iv": "DohARhe/cCEbL3ip", "ct": "zqPl/onrj9nTaCRk2DJI5l5/ICZPBRnDCjKJ"} },
  shipping:   { pwHash: '97dfaf4a063c11b2bcf57e02c2aaac0d775221758ffbfce63032f4c150e3eb6a', role: 'shipping',   name: 'Shipping Lead',   section: 'shipping' },
  sales:      { pwHash: '461b044de28dfc23bd8c473ddf5ca23bd569e06707f4f7f20d5f1522fae4f715', role: 'sales',      name: 'Sales Lead',      section: 'sales' },
  production: { pwHash: '9fcabdebccc325b087043b46810c03deaf87e341f1192e5dbd7e9c8b4c3fc362', role: 'production', name: 'Production Lead', section: 'production' },
  finance:    { pwHash: '498418da9f82668419fb396cfc86997f5a620a5a1d332d0d8a99cf5aec0b3e7f', role: 'finance',    name: 'Finance Lead',    section: 'finance' },
  // Per-user accounts. `sections` = their allow-list (nav + access restricted to
  // these; everyone also gets 'upload'). `keyEnc` = the shared master password
  // wrapped under the user's own password, so on login we recover the master and
  // decrypt the encrypted dashboard exactly like jdorf — only their sections show.
  oscar911: { pwHash: '159d773a742f7a77d2b6716b19b121a6cae2a8f223b6f0cf513e5848372ac11c', role: 'multi', name: "Felipe Cordero", section: null, sections: ["capacityWip", "employees", "executiveOps", "forecastVsActual", "invAccum", "inventory", "priceList", "productionFlow", "rawlings", "shipping", "ua"], keyEnc: {"salt": "5WDEjgEVjQs6TQuOUeOIFw==", "iv": "OPcLOxrTGZAodJEU", "ct": "F539AIPLtSDfVWgeQvuAy9KoCGHZYuJ5oB7b"} },
  karlis885: { pwHash: '6165418e77eaeb2916a3617f29a896a6753b5a826e19f353e78f3746812c2873', role: 'multi', name: "Bruno Acosta", section: null, sections: ["capacityWip", "executiveOps", "invAccum", "inventory", "priceList", "productionFlow", "rawlings", "shipping", "ua"], keyEnc: {"salt": "NoOz6r83Pd7JhfModh/UVQ==", "iv": "uRl04E+769zfJ+bt", "ct": "vH71dgqOebBzFAvUpU+q+jh8wQRxxG3k0pDF"} },
  milton433: { pwHash: 'c4c6e30ae051a6556fd1a639f17f92093be42eca6e8da3198d61a346d2444490', role: 'multi', name: "Hugo Peralta", section: null, sections: ["capacityWip", "executiveOps", "forecastVsActual", "invAccum", "inventory", "priceList", "productionFlow", "rawlings", "shipping", "ua"], keyEnc: {"salt": "6eq6qfCHx8cQhfQaOfhoSA==", "iv": "9Oy6h7hYp31N68W1", "ct": "Qk9qEoRswLa3emFqVZcFeistpzAawoeW4cWA"} },
  marcia797: { pwHash: '183e5ff7ea6ea0d8ed0e9ae9fa59fe230e3df012d3229e2e1e71bd8142f01db9', role: 'multi', name: "Marcia Sabatini", section: null, sections: ["collections", "expenses", "priceList", "sales"], keyEnc: {"salt": "rJJc4pP60JwxOA8APybpOg==", "iv": "Mp0wP4Q1yGtI89WS", "ct": "HvwmRgbDmktmoZPkE3FMB6yq3/kRkskb4Xp2"} },
  lendy551: { pwHash: 'd030f496204c05f5891e16f76b08ddc04a3cc47ac2e26636f2355021d668f371', role: 'multi', name: "Noelia Cabrera", section: null, sections: ["collections", "expenses", "forecastVsActual", "priceList", "sales"], keyEnc: {"salt": "ZD9rVD4R1rgFZrj8J81C6A==", "iv": "6TIONRSobTBbVC8e", "ct": "w2bHF6/y7dWcVbfGtFyT4djXquvDBxPaOEhW"} },
  maria575: { pwHash: 'fe3e47774af13964a2eb771b787952e024a0761036c3d8beee3fe4026438eed9', role: 'multi', name: "Adriana Fuentes", section: null, sections: ["employees"], keyEnc: {"salt": "x3kxVtYf8GHKKFLiahpJ8w==", "iv": "9213gGrG5vjXlrK0", "ct": "PAw1eaxo+OpWZm5B/Oe4iqaBebPQteaOnjpu"} },
};
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(str)));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
const REPO = { owner: 'joshnel2', repo: 'demoportal' };

// GitHub PAT is now stored AES-256-GCM encrypted in admin/secrets.enc.json,
// decrypted in-browser after a successful master-password login. No PAT bytes
// live in this file anymore — nothing useful for someone who fetches admin.js
// without the password.
//
// MASTER_PASSWORD is captured at login (form submit handler below) into the
// in-memory variable below; never persisted to localStorage in plaintext.
let MASTER_PASSWORD = null;
const SHARED_GH_TOKEN = ''; // legacy placeholder for code paths that still reference it
// A pasted GitHub key lives in localStorage('asa_github_token') and persists
// across reloads so uploads stay enabled — see the Upload view's key box.

(function attachLoginHandlerASAP() {
  const form = document.getElementById('loginForm');
  if (!form) {
    console.error('[asa] loginForm not found at script load');
    return;
  }
  console.log('[asa] attaching login handler');
  window.__asaLoginHandlerAttached = true;

  form.addEventListener('submit', async (e) => {
    console.log('[asa] login submitted');
    e.preventDefault();
    const errEl = document.getElementById('loginError');
    if (errEl) errEl.hidden = true;

    const fd = new FormData(form);
    const username = (fd.get('username') || '').toString().trim();
    const password = (fd.get('password') || '').toString();
    // Capture the master password into module-scope memory so the encrypted
    // PAT (secrets.enc.json) and encrypted data (data.enc.json) can be
    // decrypted. Persisted to sessionStorage ONLY (tab-scoped, cleared when the
    // tab closes / on logout) so a page reload can re-decrypt the dashboard
    // without re-login. Never written to localStorage and never served.
    MASTER_PASSWORD = password;
    try { sessionStorage.setItem('asa_mpw', password); } catch {}

    // DEMO MODE — accept any username/password and sign in as a full-access
    // admin so every dashboard section is visible. No encryption, no GitHub
    // token: data is read from the plaintext data.json bundled with the demo.
    MASTER_PASSWORD = null;
    try { sessionStorage.removeItem('asa_mpw'); } catch {}
    const session = {
      username: username || 'demo',
      role: 'admin', name: 'Demo Admin', section: null, sections: null,
      repo: REPO, secrets: { githubToken: null, anthropicKey: null }, backend: 'local',
    };

    SESSION = session;
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)); } catch {}
    try { bootApp(session); }
    catch (err) {
      console.error('[asa] bootApp failed:', err);
      if (errEl) { errEl.textContent = 'Boot error: ' + (err && err.message ? err.message : String(err)); errEl.hidden = false; }
    }
  });
})();

// DR Labor Code Article 88 — English labels for managerial review.
// Source-of-truth Spanish text lives in admin/data.json (employees.drGrounds)
// because the AI cites it verbatim when generating the formal termination
// paperwork (Carta de Despido + Comunicación al Ministerio de Trabajo).
const ART88_EN = {
  '88-1':  'Dishonesty / theft',
  '88-2':  'Acts of violence against employer or coworkers',
  '88-3':  'Intentional damage to machinery or product',
  '88-4':  'Compromising workshop safety through negligence',
  '88-5':  'Immoral acts at work',
  '88-6':  'Disclosing employer trade secrets',
  '88-9':  'Unjustified absence (2+ days in one month)',
  '88-10': 'Refusal to adopt preventive safety measures',
  '88-11': 'Leaving the workplace without authorization',
  '88-12': 'Insubordination on work matters',
  '88-13': 'Negligence harming production',
  '88-14': 'Intoxication or drugs at work',
  '88-15': 'Repeated tardiness',
  '88-19': 'Any other serious breach of obligations',
};

const SECTIONS = {
  shipping:    { label: 'Shipping & Logistics',   icon: 'truck'   },
  sales:       { label: 'Sales & Invoices',       icon: 'invoice' },
  ua:          { label: 'Northwind (Coreline)', icon: 'spark'  },
  rawlings:    { label: 'Granite',               icon: 'spark'   },
  productionFlow: { label: 'Production',          icon: 'factory' },
  inventory:   { label: 'Inventory',              icon: 'factory' },
  capacityWip: { label: 'Capacity & WIP',         icon: 'factory' },
  finance:     { label: 'Finance & Receivables',  icon: 'cash'    },
};

const ICON = {
  dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>',
  stock:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 17l5-5 4 4 8-8"/><path d="M16 8h5v5"/></svg>',
  truck:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7h11v9H3zM14 10h4l3 3v3h-7zM7 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm10 0a2 2 0 1 0 0-4 2 2 0 0 0 0 4z"/></svg>',
  invoice:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 3h12v18l-3-2-3 2-3-2-3 2zM9 8h6M9 12h6M9 16h4"/></svg>',
  factory:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 21V10l5 3V10l5 3V10l5 3v8z"/><path d="M7 16h2M11 16h2M15 16h2"/></svg>',
  cash:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="6" width="18" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 9v6M18 9v6"/></svg>',
  upload:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4M7 9l5-5 5 5M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3"/></svg>',
  spark:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l2 6 6 2-6 2-2 6-2-6-6-2 6-2z"/></svg>',
  settings:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1A2 2 0 1 1 4.4 17l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8L4.2 7a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1A2 2 0 1 1 19.7 7l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
};

let SESSION = null;   // { username, role, name, section, secrets:{githubToken, anthropicKey}, repo:{owner, repo} }
let VAULT = null;     // raw vault.json
let activeChart = [];

function showLoginError(msg) {
  const err = document.getElementById('loginError');
  err.textContent = msg || 'Incorrect username or password.';
  err.hidden = false;
}
function hideLoginError() {
  const err = document.getElementById('loginError');
  if (err) err.hidden = true;
}

/* ============================================================
 * Encrypted-blob loaders — secrets.enc.json holds the GitHub PAT,
 * data.enc.json holds the full dashboard payload. Both are AES-256-GCM
 * with PBKDF2-SHA256-600000 key derivation from the master password.
 * Python writer: scripts/encryption.py
 * Browser reader: admin/crypto.js (window.AsaCrypto.decryptJSON)
 * ============================================================ */
async function tryRecoverTokenFromSecrets(password) {
  if (!password) return null;
  try {
    const r = await fetch('/admin/secrets.enc.json?t=' + Date.now(), { cache: 'no-store' });
    if (!r.ok) return null;
    const text = await r.text();
    if (!text || text.trim().startsWith('<')) return null;
    const blob = JSON.parse(text);
    if (!window.AsaCrypto) { console.warn('[asa] AsaCrypto missing'); return null; }
    // The same GitHub PAT is encrypted once per authorized password. Try every
    // encrypted copy with whatever password was typed — whichever decrypts wins.
    // This lets jdorf AND oscar (and any future user) unlock the same token,
    // each with their own password.
    const candidates = [];
    if (blob.githubToken) candidates.push(blob.githubToken);          // legacy/top-level (jdorf)
    if (blob.byUser) Object.values(blob.byUser).forEach(b => candidates.push(b));
    for (const c of candidates) {
      try {
        const tok = await window.AsaCrypto.decryptJSON(c, password);
        if (typeof tok === 'string' && tok.length > 10) {
          console.log('[asa] PAT decrypted from secrets.enc.json');
          return tok;
        }
      } catch (_) { /* wrong password for this copy — try next */ }
    }
    return null;
  } catch (e) {
    console.warn('[asa] secrets.enc.json decrypt failed:', e.message || e);
    return null;
  }
}

async function tryLoadEncryptedData(password) {
  if (!password) return null;
  try {
    const r = await fetch('/admin/data.enc.json?t=' + Date.now(), { cache: 'no-store' });
    if (!r.ok) return null;
    const text = await r.text();
    if (!text || text.trim().startsWith('<')) return null;
    const blob = JSON.parse(text);
    if (!blob || !blob.ct) return null;
    if (!window.AsaCrypto) return null;
    const obj = await window.AsaCrypto.decryptJSON(blob, password);
    if (obj && typeof obj === 'object') {
      console.log('[asa] data.enc.json decrypted; lastUpdated:', obj.lastUpdated || 'never');
      return obj;
    }
    return null;
  } catch (e) {
    console.warn('[asa] data.enc.json decrypt failed:', e.message || e);
    return null;
  }
}

async function loadVault() {
  try {
    const r = await fetch('vault.json?t=' + Date.now(), { cache: 'no-store' });
    if (!r.ok) return null;
    const text = await r.text();
    if (!text || text.trim().startsWith('<')) return null; // 404 served as HTML fallback
    return JSON.parse(text);
  } catch (e) { return null; }
}

async function commitVault(vault, ghToken) {
  const path = 'admin/vault.json';
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(vault, null, 2))));
  let sha = null;
  try {
    const r = await fetch(`https://api.github.com/repos/${REPO.owner}/${REPO.repo}/contents/${path}`, {
      headers: { 'Authorization': `Bearer ${ghToken}`, 'Accept': 'application/vnd.github+json' }
    });
    if (r.ok) sha = (await r.json()).sha;
  } catch {}
  const body = { message: 'Update encrypted vault', content, branch: 'main' };
  if (sha) body.sha = sha;
  const r = await fetch(`https://api.github.com/repos/${REPO.owner}/${REPO.repo}/contents/${path}`, {
    method: 'PUT',
    headers: { 'Authorization': `Bearer ${ghToken}`, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error('Failed to save vault to repo (status ' + r.status + '). ' + (t.slice(0, 200)));
  }
}

/* On first admin login, encrypt the secrets once for each of the 5 users
 * (using each user's hardcoded password) so all of them can later log in
 * with just username + password. */
async function setupVaultAllUsers(secrets) {
  // Plaintext passwords were removed, so we can only (re-)encrypt the CURRENT
  // user's vault blob — their password is in MASTER_PASSWORD from login. Every
  // other user's existing encrypted blob is carried over from vault.json
  // unchanged (they keep recovering whatever token was last encrypted for them;
  // each user can paste their own token in Settings if it ever rotates).
  let existing = null;
  try { existing = await loadVault(); } catch (_) {}
  const vault = {
    version: 1,
    owner: REPO.owner,
    repo: REPO.repo,
    createdAt: new Date().toISOString(),
    users: {},
  };
  const curUser = (typeof SESSION === 'object' && SESSION) ? SESSION.username : null;
  for (const [username, u] of Object.entries(FALLBACK_USERS)) {
    if (username === curUser && MASTER_PASSWORD) {
      const blob = await AsaCrypto.encryptJSON(secrets, username + ':' + MASTER_PASSWORD);
      vault.users[username] = { role: u.role, name: u.name, section: u.section, ...blob };
    } else if (existing && existing.users && existing.users[username]) {
      vault.users[username] = existing.users[username];
    } else {
      vault.users[username] = { role: u.role, name: u.name, section: u.section };
    }
  }
  return vault;
}

/* (login handler is attached at the top of this file) */

document.getElementById('logoutBtn').addEventListener('click', () => {
  sessionStorage.clear();
  location.reload();
});

/* ============================================================
 * GITHUB CONTENTS API
 * ============================================================ */
const GH = {
  base() { return `https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}`; },
  token() {
    return (SESSION.secrets && SESSION.secrets.githubToken) || localStorage.getItem('asa_github_token') || null;
  },
  headers() {
    const h = {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    const t = this.token();
    if (t) h['Authorization'] = `Bearer ${t}`;
    return h;
  },
  async listDir(path) {
    // Cache-bust: GitHub's directory-listing CDN lags 30-60s behind commits.
    // Without this, just-uploaded files vanish on the next refresh.
    const url = `${this.base()}/contents/${path}?ref=main&_=${Date.now()}`;
    const r = await fetch(url, { headers: { ...this.headers(), 'Cache-Control': 'no-cache' }, cache: 'no-store' });
    if (r.status === 404) return [];
    if (r.status === 403) throw new Error('GitHub rate limit hit. Unlock your token (red banner) to lift the 60/hr anonymous cap.');
    if (!r.ok) throw new Error('GitHub list failed: ' + r.status);
    return r.json();
  },
  async getFile(path) {
    const r = await fetch(`${this.base()}/contents/${path}`, { headers: this.headers() });
    if (!r.ok) throw new Error('GitHub get failed');
    const j = await r.json();
    return { sha: j.sha, content: atob(j.content.replace(/\n/g, '')) };
  },
  async putFile(path, contentBytes, message) {
    // contentBytes: ArrayBuffer or Uint8Array
    const b64 = bytesToB64(contentBytes);
    const r = await fetch(`${this.base()}/contents/${path}`, {
      method: 'PUT',
      headers: { ...this.headers(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, content: b64, branch: 'main' }),
    });
    if (!r.ok) throw new Error('Upload failed: ' + r.status + ' ' + (await r.text()));
    return r.json();
  },
  async deleteFile(path, sha) {
    const r = await fetch(`${this.base()}/contents/${path}`, {
      method: 'DELETE',
      headers: { ...this.headers(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: `Delete ${path}`, sha, branch: 'main' }),
    });
    if (!r.ok) throw new Error('Delete failed: ' + r.status);
    return r.json();
  },
};

function bytesToB64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/* recursively list /uploads. Errors propagate so callers can show a real message
 * — previously a swallowed .catch was hiding rate-limit failures behind a silent "no uploads". */
async function listAllUploads() {
  const sectionFolders = await GH.listDir('uploads'); // let errors bubble
  if (!Array.isArray(sectionFolders)) return [];
  const all = [];
  // Parallelize per-section listings — keeps API calls fast and still well under any reasonable budget.
  const folderResults = await Promise.all(
    sectionFolders.filter(f => f.type === 'dir').map(async (folder) => {
      try {
        const files = await GH.listDir(`uploads/${folder.name}`);
        return Array.isArray(files) ? files.map(f => ({ ...f, _section: folder.name })) : [];
      } catch (e) {
        // Re-throw rate-limit / auth errors so caller can show them; swallow only 404.
        if (/404/.test(e.message)) return [];
        throw e;
      }
    })
  );
  for (const files of folderResults) {
    for (const f of files) {
      if (f.type !== 'file') continue;
      const meta = parseUploadName(f.name);
      all.push({
        path: f.path, name: f.name, section: f._section, size: f.size,
        sha: f.sha, downloadUrl: f.download_url, ...meta,
      });
    }
  }
  return all.sort((a,b) => (b.uploadedAt||'').localeCompare(a.uploadedAt||''));
}

function parseUploadName(filename) {
  // expected format: {ISOdate}__{user}__{originalName}
  const m = filename.match(/^([\dT:.\-Z]+)__([^_]+)__(.+)$/);
  if (!m) return { uploadedAt: '', uploader: '', original: filename };
  return { uploadedAt: m[1].replace(/-/g, ':').replace(/^(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3'), uploader: m[2], original: m[3] };
}

/* ============================================================
 * MOCK DATA  (replace once GitHub uploads have real CSVs)
 * ============================================================ */
const today = new Date();
const dayLabels = Array.from({ length: 14 }, (_, i) => {
  const d = new Date(today); d.setDate(d.getDate() - (13 - i));
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
});
const weekLabels = Array.from({ length: 8 }, (_, i) => `W${i+1}`);
const customers = ['Brand A','Brand B','Brand C','Brand D','Brand E'];

/* Empty default — charts render with proper axes (14 days / 8 weeks of zeros)
 * but no fake brand names or business data. Real numbers replace these once
 * uploads are processed. */
const zeros14 = Array.from({ length: 14 }, () => 0);
const zeros8 = Array.from({ length: 8 }, () => 0);

const MOCK = {
  shipping: {
    perDay: zeros14.slice(),
    forecastVsActual: { forecast: zeros8.slice(), actual: zeros8.slice() },
    byCustomer: [],
  },
  sales: {
    invoicesPerDay: zeros14.slice(),
    receivablesPerDay: zeros14.slice(),
    receivableSummary: [],
  },
  production: {
    capacityByWeek: zeros8.slice(),
    capacityCommitted: zeros8.slice(),
    inventoryByCustomer: [],
    wip: [],
  },
  finance: {
    pastDueExpenses: [],
    openExpenses: [],
    shippedByCustomer: [],
  },
};

/* ============================================================
 * DATA LOADER — fetches admin/data.json (updated by a scheduled
 * Claude Code routine) and merges any non-empty fields into MOCK
 * so dashboards show real numbers when available.
 * ============================================================ */
let DASHBOARD_DATA_LOADED = false;
async function loadDashboardData() {
  if (DASHBOARD_DATA_LOADED) return;
  DASHBOARD_DATA_LOADED = true;

  // Reset MOCK to empty so we don't show stale sample data when nothing real is loaded.
  resetMockToEmpty();

  // Layer 1a: encrypted data.enc.json (preferred). Falls back to plaintext
  // data.json below if decryption fails (stage 1 dual-write — to be removed
  // in stage 2 once encryption is verified working in production).
  let encryptedLoaded = false;
  if (MASTER_PASSWORD) {
    const obj = await tryLoadEncryptedData(MASTER_PASSWORD);
    if (obj) { mergeIntoMock(obj); encryptedLoaded = true; }
  }

  // Layer 1b: plaintext data.json (legacy fallback).
  if (!encryptedLoaded) {
    try {
      const r = await fetch('data.json?t=' + Date.now(), { cache: 'no-store' });
      if (r.ok) {
        const text = await r.text();
        if (text && !text.trim().startsWith('<')) {
          const data = JSON.parse(text);
          mergeIntoMock(data);
          console.log('[asa] data.json (plaintext) merged; lastUpdated:', data.lastUpdated || 'never');
        }
      }
    } catch (e) { console.warn('[asa] data.json load skipped:', e.message); }
  }

  // Layer 2: Azure SQL via /api/dashboard (overlays anything in data.json).
  if (API_BASE) {
    try {
      const data = await apiGet('/api/dashboard');
      if (data) { mergeIntoMock(data); console.log('[asa] /api/dashboard merged; lastUpdated:', data.lastUpdated); }
    } catch (e) { console.warn('[asa] /api/dashboard skipped:', e.message); }
  }
}

function resetMockToEmpty() {
  MOCK.shipping = { perDay: [], dayLabels: [], forecast: [], actual: [], weekLabels: [], byCustomer: [], forecastVsActual: { forecast: [], actual: [] } };
  MOCK.sales = { invoicesPerDay: [], receivablesPerDay: [], receivableSummary: [] };
  MOCK.production = { capacityByWeek: [], capacityCommitted: [], inventoryByCustomer: [], wip: [] };
  MOCK.finance = { pastDueExpenses: [], openExpenses: [], shippedByCustomer: [] };
}

function replaceMock(data) {
  // Full replacement when Azure responds — real numbers (or empty) win.
  ['shipping','sales','production','finance'].forEach((section) => {
    if (!data[section]) return;
    Object.keys(data[section]).forEach((k) => {
      const v = data[section][k];
      if (v == null) return;
      MOCK[section][k] = v;
    });
  });
  // Employees section — full graft (no defaults to merge into; just take whatever ships)
  if (data.employees) {
    MOCK.employees = data.employees;
  }
}

function mergeIntoMock(data) {
  try {
    ['shipping','sales','production','finance'].forEach((section) => {
      if (!data[section]) return;
      Object.keys(data[section]).forEach((k) => {
        const v = data[section][k];
        if (Array.isArray(v) && v.length === 0) return; // skip empty
        if (v == null) return;
        MOCK[section][k] = v;
      });
    });
    // Back-compat: renderShipping reads MOCK.shipping.forecastVsActual.{forecast,actual}
    // but the AI loop writes MOCK.shipping.forecast/actual directly. Bridge them here.
    if (data.shipping) {
      MOCK.shipping.forecastVsActual = MOCK.shipping.forecastVsActual || { forecast: [], actual: [] };
      if (Array.isArray(data.shipping.forecast) && data.shipping.forecast.length) MOCK.shipping.forecastVsActual.forecast = data.shipping.forecast;
      if (Array.isArray(data.shipping.actual) && data.shipping.actual.length) MOCK.shipping.forecastVsActual.actual = data.shipping.actual;
      if (Array.isArray(data.shipping.dayLabels) && data.shipping.dayLabels.length) window.__dayLabels = data.shipping.dayLabels;
      if (Array.isArray(data.shipping.weekLabels) && data.shipping.weekLabels.length) window.__weekLabels = data.shipping.weekLabels;
      // Normalize byCustomer to expose a `units` field for the chart, falling back across shapes.
      if (Array.isArray(data.shipping.byCustomer)) {
        MOCK.shipping.byCustomer = data.shipping.byCustomer.map(c => ({
          ...c,
          units: c.units != null ? c.units : (c.shipped != null ? c.shipped : (c.forecast2026 != null ? c.forecast2026 : (c.planned || 0))),
        }));
      }
    }
    // Employees section — full graft (no defaults to merge into; just take whatever ships)
    if (data.employees) {
      MOCK.employees = data.employees;
    }
    console.log('[asa] dashboard data loaded; lastUpdated:', data.lastUpdated || 'never');
  } catch (e) {
    console.warn('[asa] could not load data.json — falling back to sample data:', e.message);
  }
}

/* ============================================================
 * APP BOOT + ROUTING
 * ============================================================ */
async function tryRecoverTokenFromVault(username, password) {
  const v = await loadVault();
  if (!v || !v.users || !v.users[username]) throw new Error('vault missing for ' + username);
  const entry = v.users[username];
  const dec = await AsaCrypto.decryptJSON({ salt: entry.salt, iv: entry.iv, ct: entry.ct }, username + ':' + password);
  if (!dec || !dec.githubToken) throw new Error('decrypt returned no token');
  return dec.githubToken;
}

async function ensureTokenOrShowBanner(session) {
  return; // DEMO MODE — no GitHub token needed; never show the upload-key banner.
  const existing = (session.secrets && session.secrets.githubToken) || localStorage.getItem('asa_github_token');
  if (existing) {
    try { localStorage.setItem('asa_github_token', existing); } catch {}
    if (session.secrets) session.secrets.githubToken = existing;
    const b = document.getElementById('asaTokenBanner'); if (b) b.remove();
    return;
  }
  // No token. Show the banner with an inline "Unlock" form (re-enters password and re-decrypts vault).
  let banner = document.getElementById('asaTokenBanner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'asaTokenBanner';
    banner.style.cssText = 'background:#7a1f1f;color:#fff;padding:12px 16px;font-size:13px;text-align:center;font-weight:500';
    document.querySelector('.app-shell')?.prepend(banner);
  }
  const u = session.username;
  banner.innerHTML = `
    ⚠ Upload key missing on this device. Uploads and comments will not commit until unlocked.
    <div style="margin-top:8px;display:flex;gap:8px;justify-content:center;align-items:center;flex-wrap:wrap">
      <span>Re-enter <strong>${escapeHtml(u)}</strong>'s password to unlock:</span>
      <input type="password" id="asaUnlockPw" placeholder="password" style="padding:6px 10px;border-radius:6px;border:1px solid #aaa;font-size:13px;color:#000;min-width:180px" />
      <button id="asaUnlockBtn" style="padding:6px 14px;border-radius:6px;background:#fff;color:#7a1f1f;font-weight:700;border:none;cursor:pointer;font-size:13px">Unlock</button>
      <span id="asaUnlockMsg" style="margin-left:8px"></span>
    </div>
  `;
  const pwEl = document.getElementById('asaUnlockPw');
  const btn = document.getElementById('asaUnlockBtn');
  const msg = document.getElementById('asaUnlockMsg');
  const doUnlock = async () => {
    const pw = pwEl.value;
    if (!pw) { msg.textContent = 'enter password'; return; }
    btn.disabled = true; msg.textContent = 'unlocking…';
    try {
      // Try the encrypted secrets file first (works for any authorized password,
      // jdorf or oscar), then fall back to the legacy per-user vault.
      let tok = await tryRecoverTokenFromSecrets(pw);
      if (!tok) tok = await tryRecoverTokenFromVault(u, pw);
      if (!tok) throw new Error('wrong password');
      localStorage.setItem('asa_github_token', tok);
      if (session.secrets) session.secrets.githubToken = tok;
      try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)); } catch {}
      msg.textContent = '✓ unlocked, reloading…';
      setTimeout(() => location.reload(), 600);
    } catch (e) {
      btn.disabled = false;
      msg.textContent = '✗ ' + (e.message || 'failed');
    }
  };
  btn.addEventListener('click', doUnlock);
  pwEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doUnlock(); } });
  pwEl.focus();
}

async function bootApp(session) {
  document.getElementById('loginView').hidden = true;
  document.getElementById('appView').hidden = false;
  document.getElementById('userName').textContent = session.name;
  document.getElementById('userRole').textContent = session.role === 'admin' ? 'Administrator' : sectionLabelFor(session.section);
  document.getElementById('userAvatar').textContent = session.name.split(' ').map(s=>s[0]).join('').slice(0,2).toUpperCase();

  // Vault-recovery fallback: if this user has no token yet (stale session, or first
  // login on a brand-new browser without password re-entry), try the vault now.
  if (!session.secrets || !session.secrets.githubToken) {
    if (!localStorage.getItem('asa_github_token')) {
      try {
        const v = await loadVault();
        if (v && v.users && v.users[session.username]) {
          // Can't decrypt without the password — but at least surface this in the UI later.
          console.warn('[asa] vault present but no token in session — user may need to sign out and back in.');
        }
      } catch {}
    }
  }
  // Mirror SESSION.secrets.githubToken into localStorage so every legacy
  // localStorage.getItem('asa_github_token') call works (uploads, comments, settings).
  if (session.secrets && session.secrets.githubToken) {
    try { localStorage.setItem('asa_github_token', session.secrets.githubToken); } catch {}
  }

  // Self-healing token banner: if no token is in localStorage, try vault decrypt
  // with the user's password before showing the warning. One-click fix on stale sessions.
  await ensureTokenOrShowBanner(session);

  await loadDashboardData();
  buildSidebar(session);
  navigate(session.role === 'admin' ? 'overview' : firstAllowedView(session));
}

// Resolve a display label for any view, including the ones not in SECTIONS
// (employees, forecastVsActual, etc.) so restricted users don't crash the nav.
const VIEW_EXTRA = {
  employees: 'Employees', forecastVsActual: 'Forecast vs Actual', executiveOps: 'On-Time Delivery',
  aiCoaching: 'AI Coaching', invAccum: 'Inventory Accumulation', collections: 'Collections',
  expenses: 'Expenses', priceList: 'Price List', asaStock: '$STA', upload: 'Upload Data',
};
const VIEW_ICON = {
  invAccum: 'factory', collections: 'cash', expenses: 'cash', priceList: 'invoice',
  executiveOps: 'spark', forecastVsActual: 'spark', employees: 'spark', upload: 'upload', asaStock: 'stock',
};
function navLabel(view) { return SECTIONS[view] ? SECTIONS[view].label : (VIEW_EXTRA[view] || view); }
function navIcon(view) { return SECTIONS[view] ? SECTIONS[view].icon : (VIEW_ICON[view] || 'spark'); }
function sectionLabelFor(section) {
  if (SECTIONS[section]) return SECTIONS[section].label;
  return VIEW_EXTRA[section] || (section || '—');
}
// Display order for a per-user account's sidebar sections.
const NAV_ORDER = ['shipping','sales','ua','rawlings','productionFlow','inventory','capacityWip','finance',
                   'invAccum','collections','expenses','priceList','executiveOps','forecastVsActual','employees'];
// Views a non-admin per-user account may open (their sections + always-allowed upload).
function allowedViews(session) {
  if (!session || session.role === 'admin') return null;       // admin = everything
  if (Array.isArray(session.sections) && session.sections.length) return new Set([...session.sections, 'upload']);
  if (session.section) return new Set([session.section, 'upload']);
  return null;
}
function firstAllowedView(session) {
  if (Array.isArray(session.sections) && session.sections.length) {
    return NAV_ORDER.find(v => session.sections.includes(v)) || session.sections[0];
  }
  return session.section;
}

function buildSidebar(session) {
  const nav = document.getElementById('sidebarNav');
  let html = '';
  if (session.role === 'admin') {
    html += `<button data-view="overview">${ICON.dashboard}<span>Overview</span></button>`;
    html += `<div class="sidebar-nav-section">Sections</div>`;
    Object.entries(SECTIONS).forEach(([key, s]) => {
      html += `<button data-view="${key}">${ICON[s.icon]}<span>${s.label}</span></button>`;
    });
    html += `<button data-view="invAccum">${ICON.factory}<span>Inventory Accumulation</span></button>`;
    html += `<button data-view="collections">${ICON.cash}<span>Collections</span></button>`;
    html += `<button data-view="expenses">${ICON.cash}<span>Expenses</span></button>`;
    html += `<button data-view="priceList">${ICON.invoice}<span>Price List</span></button>`;
    html += `<button data-view="asaStock">${ICON.stock}<span>$STA</span></button>`;
    html += `<button data-view="forecastVsActual">${ICON.spark}<span>Forecast vs Actual</span></button>`;
    html += `<button data-view="executiveOps">${ICON.spark}<span>On-Time Delivery</span></button>`;
    html += `<button data-view="aiCoaching">${ICON.spark}<span>AI Coaching</span></button>`;
    html += `<button data-view="employees">${ICON.spark}<span>Employees</span></button>`;
    html += `<div class="sidebar-nav-section">Files</div>`;
    html += `<button data-view="upload">${ICON.upload}<span>Upload Data</span></button>`;
    html += `<button data-view="uploads">${ICON.upload}<span>All Uploads</span></button>`;
    html += `<div class="sidebar-nav-section">Tracker</div>`;
    html += `<button data-view="comments">${ICON.spark}<span>AI Comments</span></button>`;
    if (session.secrets && session.secrets.anthropicKey) {
      html += `<button data-view="ai">${ICON.spark}<span>AI Summary</span></button>`;
    }
    html += `<div class="sidebar-nav-section">Admin</div>`;
    html += `<button data-view="settings">${ICON.settings}<span>Settings</span></button>`;
  } else if (Array.isArray(session.sections) && session.sections.length) {
    // Per-user account: only their allowed sections, in a sensible order. Everyone can upload.
    NAV_ORDER.filter(v => session.sections.includes(v)).forEach(v => {
      html += `<button data-view="${v}">${ICON[navIcon(v)]}<span>${navLabel(v)}</span></button>`;
    });
    html += `<div class="sidebar-nav-section">Files</div>`;
    html += `<button data-view="upload">${ICON.upload}<span>Upload Data</span></button>`;
  } else if (session.section === 'employees') {
    // Employees-only user (e.g. Oscar, plant manager): just the Employees section.
    html += `<button data-view="employees">${ICON.spark}<span>Employees</span></button>`;
  } else {
    const s = SECTIONS[session.section];
    if (s) {
      html += `<button data-view="${session.section}">${ICON[s.icon]}<span>${s.label}</span></button>`;
      if (session.section === 'finance') html += `<button data-view="asaStock">${ICON.stock}<span>$STA</span></button>`;
      html += `<button data-view="upload">${ICON.upload}<span>Upload Data</span></button>`;
      html += `<button data-view="comments">${ICON.spark}<span>AI Comments</span></button>`;
    } else {
      // Fallback: a restricted view not in SECTIONS — show just that view.
      html += `<button data-view="${session.section}">${ICON.spark}<span>${sectionLabelFor(session.section)}</span></button>`;
    }
  }
  nav.innerHTML = html;
  nav.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => navigate(b.dataset.view)));
}

function navigate(view) {
  // Access control: a per-user account can only open its allowed views (Overview
  // is finance-wide, so admin-only — restricted users land on their first section).
  const allow = allowedViews(SESSION);
  if (allow && !allow.has(view)) {
    const first = firstAllowedView(SESSION);
    if (first && first !== view) return navigate(first);
  }
  document.querySelectorAll('#sidebarNav button').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  activeChart.forEach((c) => { try { c.destroy(); } catch {} });
  activeChart = [];
  const root = document.getElementById('content');
  setTimeout(() => { injectExportButtons(view); injectUAFootprint(view); applyLang(); }, 0);  // export buttons + NW footprint + translate, after render
  if (view === 'overview') return renderOverview(root);
  if (view === 'forecastVsActual') return renderForecastVsActual(root);
  if (view === 'shipping') return renderShipping(root);
  if (view === 'sales') return renderSales(root);
  if (view === 'ua') return renderUA(root);
  if (view === 'rawlings') return renderRawlings(root);
  if (view === 'productionFlow') return renderProductionFlow(root);
  if (view === 'inventory') return renderProduction(root);
  if (view === 'production') return renderProduction(root); // legacy alias
  if (view === 'capacityWip') return renderCapacityWip(root);
  if (view === 'executiveOps') return renderExecutiveOps(root);
  if (view === 'aiCoaching') return renderAICoaching(root);
  if (view === 'employees') return renderEmployees(root);
  if (view === 'finance') return renderFinance(root);
  if (view === 'asaStock') return renderASAStock(root);
  if (view === 'invAccum') return renderInventoryAccumulation(root);
  if (view === 'collections') return renderCollections(root);
  if (view === 'expenses') return renderExpenses(root);
  if (view === 'priceList') return renderPriceList(root);
  if (view === 'uploads') return renderUploadsList(root);
  if (view === 'upload') return renderUpload(root);
  if (view === 'ai') return renderAI(root);
  if (view === 'settings') return renderSettings(root);
  if (view === 'comments') return renderComments(root);
}

/* ============================================================
 * SECTION EXPORTS — download a presentation-grade Excel or PDF of any
 * data section (refreshed every loop by scripts/build_exports.py, stored
 * AES-GCM encrypted in /admin/exports/, decrypted client-side on click).
 * ============================================================ */
// view -> export key (sections that have a generated export)
const EXPORT_KEY = {
  shipping: 'shipping', sales: 'sales', finance: 'finance',
  inventory: 'inventory', production: 'inventory', aiCoaching: 'aiCoaching', ua: 'ua',
  priceList: 'prices',
};

// view -> client brief (English + Dominican-Spanish)
const BRIEFS = {
  ua:       { key: 'ua-brief',       label: 'NW',       to: 'Northwind' },
  rawlings: { key: 'rawlings-brief', label: 'Granite', to: 'Granite' },
};

function injectExportButtons(view) {
  const key = EXPORT_KEY[view];
  const brief = BRIEFS[view];
  const isOverview = (view === 'overview');
  if (!key && !brief && !isOverview) return;
  const head = document.querySelector('#content .page-head');
  if (!head || head.querySelector('.asa-export-btns')) return;
  const wrap = document.createElement('div');
  wrap.className = 'asa-export-btns';
  wrap.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-left:auto;align-items:center';
  let html = '';
  if (isOverview) html +=
    `<button class="btn btn-primary btn-sm" title="One-page executive brief — finances, pipeline, cash, inventory, key accounts" onclick="__asaExport('owner-brief','pdf')" style="background:linear-gradient(135deg,#0a1633,#16306b);border:0">★&nbsp;Owner's Brief</button>`;
  if (key) html +=
    `<button class="btn btn-ghost btn-sm" title="Download a formatted Excel of this section" onclick="__asaExport('${key}','xlsx')">⬇&nbsp;Excel</button>` +
    `<button class="btn btn-ghost btn-sm" title="Open a print-ready PDF of this section" onclick="__asaExport('${key}','pdf')">⬇&nbsp;PDF</button>`;
  if (brief) html +=
    `<button class="btn btn-primary btn-sm" title="Polished brief to send to ${brief.to}" onclick="__asaExport('${brief.key}','pdf')">📄&nbsp;${brief.label} Brief</button>` +
    `<button class="btn btn-primary btn-sm" title="Resumen para ${brief.to}, en español (dominicano)" onclick="__asaExport('${brief.key}-es','pdf')">📄&nbsp;${brief.label} Brief (Español)</button>`;
  wrap.innerHTML = html;
  head.appendChild(wrap);
}

/* NW footprint — "how much of this section is NW". Reads the precomputed
 * MOCK.uaShare (correct totals incl NW, no double-count) and shows the NW share
 * for the metrics relevant to each section. Injected after the page header. */
function uaFootprintFor(view) {
  const us = MOCK.uaShare; if (!us) return '';
  const M = (k) => us[k] || {};
  let metrics = [];
  if (view === 'overview') metrics = [['Revenue · shipped YTD', M('revenueUsd'), 'money'], ['Units shipped YTD', M('shippedUnits'), 'num'], ['Open orders ($)', M('openOrdersUsd'), 'money'], ['Inventory on hand', M('inventoryUnits'), 'num']];
  else if (view === 'shipping') metrics = [['Revenue · shipped YTD', M('revenueUsd'), 'money'], ['Units shipped YTD', M('shippedUnits'), 'num']];
  else if (view === 'sales') metrics = [['Revenue · shipped YTD', M('revenueUsd'), 'money'], ['Units shipped YTD', M('shippedUnits'), 'num']];
  else if (view === 'inventory' || view === 'production') metrics = [['On-hand units', M('inventoryUnits'), 'num'], ['On-hand cost', M('inventoryCost'), 'money']];
  else if (view === 'productionFlow') metrics = [['Open orders ($)', M('openOrdersUsd'), 'money'], ['Open order units', M('openOrderUnits'), 'num']];
  else return '';
  metrics = metrics.filter(m => (m[1].total || 0) > 0);
  if (!metrics.length) return '';
  const f = (v, k) => k === 'money' ? fmtMoney(v) : fmtNum(v);
  const note = view === 'sales'
    ? 'NW/Coreline is prepaid — its shipments count toward revenue, but it carries no A/R.'
    : 'NW/Coreline is prepaid. Totals here include NW; the standalone NW tab has full detail.';
  return `<div class="panel asa-ua-footprint" style="border-left:4px solid #1c1c3a">
    <div class="panel-head"><h2 style="font-size:15px">Northwind footprint <span style="font-size:11px;font-weight:500;color:var(--ink-dim)">— how much of this section is NW</span></h2><span class="panel-meta"><a href="#" onclick="navigate('ua');return false;">full NW detail →</a></span></div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px;padding:14px 18px">
    ${metrics.map(([label, s, fmt]) => { const pct = s.pct || 0; return `
      <div>
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">${label}</div>
        <div style="font-size:20px;font-weight:800;color:#14142b">${f(s.total, fmt)} <span style="font-size:12px;font-weight:700;color:#1c1c3a">· NW ${pct}%</span></div>
        <div style="height:7px;background:#eef2f5;border-radius:4px;margin-top:5px;overflow:hidden"><div style="height:100%;width:${Math.min(100, pct)}%;background:linear-gradient(90deg,#2a2a5a,#1c1c3a)"></div></div>
        <div style="font-size:11px;color:var(--ink-dim);margin-top:3px">NW ${f(s.ua, fmt)} · rest ${f(s.nonUA, fmt)}</div>
      </div>`; }).join('')}
    </div>
    <p style="padding:0 18px 12px;font-size:11px;color:var(--ink-dim)">${note}</p>
  </div>`;
}

function injectUAFootprint(view) {
  if (document.querySelector('#content .asa-ua-footprint')) return;
  const html = uaFootprintFor(view); if (!html) return;
  const head = document.querySelector('#content .page-head');
  if (head) head.insertAdjacentHTML('afterend', html);
}

window.__asaExport = async function (key, kind) {
  try {
    if (!MASTER_PASSWORD) { alert('Please sign in again so the file can be decrypted.'); return; }
    const r = await fetch(`/admin/exports/${key}__${kind}.json?t=` + Date.now(), { cache: 'no-store' });
    if (!r.ok) { alert('This export isn’t generated yet — it refreshes on the next loop pass.'); return; }
    const blob = await r.json();
    const obj = await AsaCrypto.decryptJSON(blob, MASTER_PASSWORD);
    if (!obj || !obj.b64) { alert('Could not decrypt the file (wrong password?).'); return; }
    const bytes = Uint8Array.from(atob(obj.b64), (c) => c.charCodeAt(0));
    if (kind === 'pdf') {
      const html = new TextDecoder('utf-8').decode(bytes);
      const w = window.open('', '_blank');
      if (!w) { alert('Allow pop-ups to open the printable PDF view.'); return; }
      w.document.open(); w.document.write(html); w.document.close();
    } else {
      const file = new Blob([bytes], { type: obj.type || 'application/octet-stream' });
      const url = URL.createObjectURL(file);
      const a = document.createElement('a');
      a.href = url; a.download = obj.name || (key + '.xlsx');
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    }
  } catch (e) {
    alert('Download failed: ' + (e && e.message ? e.message : e));
  }
};

/* ============================================================
 * $STA — weekly revenue as a stock ticker (just for fun, real numbers).
 * Full SHIPPINGREPORT history, NW/Coreline excluded. Dashed average line,
 * hover any week for its revenue + units.
 * ============================================================ */
function renderASAStock(root) {
  const wr = (MOCK.shipping && MOCK.shipping.weeklyRevenue) || {};
  const weeks = Array.isArray(wr.weeks) ? wr.weeks : [];
  if (!weeks.length) {
    root.innerHTML = `<div class="page-head"><div><p class="eyebrow">Markets</p><h1>$STA</h1><p>No weekly revenue yet — upload a SHIPPINGREPORT to populate.</p></div></div>`;
    return;
  }
  const wkLabel = (iso) => new Date(iso + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const labels = weeks.map(w => wkLabel(w.week));
  const data = weeks.map(w => Math.round(w.usd));
  const units = weeks.map(w => w.units || 0);
  const avg = Math.round(wr.avgUsd || 0);
  const lastDone = weeks.filter(w => !w.partial);
  const latest = Math.round((lastDone[lastDone.length - 1] || {}).usd || 0);  // last COMPLETED week — the in-progress week isn't a "close"
  const prev = lastDone.length > 1 ? Math.round(lastDone[lastDone.length - 2].usd || 0) : latest;
  const chg = prev ? ((latest - prev) / prev * 100) : 0;
  const up = latest >= prev;
  const hi = Math.max(...data), lo = Math.min(...data);
  const hiWk = weeks[data.indexOf(hi)], loWk = weeks[data.indexOf(lo)];
  const total = data.reduce((a, b) => a + b, 0);
  const first = data[0] || 0;
  const periodChg = first ? ((latest - first) / first * 100) : 0;
  const lineColor = latest >= first ? '#16a34a' : '#dc2626';
  const money = (n) => '$' + Math.round(n).toLocaleString('en-US');
  const chip = (v) => `<span style="color:${v >= 0 ? '#22c55e' : '#f87171'};font-weight:700">${v >= 0 ? '▲' : '▼'} ${Math.abs(v).toFixed(1)}%</span>`;

  root.innerHTML = `
    <div class="page-head"><div>
      <p class="eyebrow">Markets · for fun</p><h1>$STA</h1>
      <p>Summit Team Apparel — weekly shipped revenue · ${weeks.length} weeks since ${wkLabel(weeks[0].week)}.</p>
    </div></div>

    <div class="panel" style="background:linear-gradient(135deg,#0b1020 0%,#14223b 100%);color:#e8eef6;padding:22px 26px;border:1px solid #1e2a44">
      <div style="display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:14px">
        <div>
          <div style="display:flex;align-items:center;gap:10px">
            <span style="font-family:'Bebas Neue',Impact,sans-serif;font-size:32px;letter-spacing:2px;color:#fff">$STA</span>
            <span style="display:inline-flex;align-items:center;gap:5px;font-size:11px;color:#86efac"><span style="width:7px;height:7px;border-radius:50%;background:#22c55e;display:inline-block;animation:asapulse 1.6s infinite"></span>WEEKLY CLOSE</span>
          </div>
          <div style="font-size:13px;color:#8595ad;margin-top:2px">Summit Team Apparel · NYSE: vibes only</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:36px;font-weight:800;font-variant-numeric:tabular-nums;color:#fff">${money(latest)}</div>
          <div style="font-size:13px">${chip(chg)} <span style="color:#8595ad">wk / wk</span></div>
        </div>
      </div>
      <div style="height:300px;margin-top:16px"><canvas id="asaChart"></canvas></div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px;margin-top:16px;font-variant-numeric:tabular-nums">
        ${[['Latest close', money(latest), lastDone.length ? wkLabel(lastDone[lastDone.length - 1].week) + ' (last full wk)' : '—'],
           ['Avg / wk', money(avg), 'dashed line'],
           ['Period high', money(hi), wkLabel(hiWk.week)],
           ['Period low', money(lo), wkLabel(loWk.week)],
           ['Since start', (periodChg >= 0 ? '+' : '') + periodChg.toFixed(1) + '%', wkLabel(weeks[0].week)],
           ['Total', money(total), weeks.length + ' wks']
          ].map(([l, v, s]) => `<div style="background:rgba(255,255,255,.04);border:1px solid #1e2a44;border-radius:10px;padding:10px 12px">
            <div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#8595ad">${l}</div>
            <div style="font-size:18px;font-weight:700;color:#e8eef6">${v}</div>
            <div style="font-size:10px;color:#6b7a93">${s}</div></div>`).join('')}
      </div>
    </div>
    <style>@keyframes asapulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.6)}70%{box-shadow:0 0 0 7px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}</style>
    <p style="font-size:11px;color:var(--ink-dim);margin-top:8px">Weekly shipped revenue (US$) from SHIPPINGREPORT — NW/Coreline excluded (prepaid). Hover the line for any week's revenue + units. Dashed line = ${money(avg)}/wk average.</p>
  `;

  const cv = document.getElementById('asaChart');
  if (!cv || !window.Chart) return;
  const ctx = cv.getContext('2d');
  const grad = ctx.createLinearGradient(0, 0, 0, 300);
  grad.addColorStop(0, up ? 'rgba(34,197,94,.35)' : 'rgba(220,38,38,.32)');
  grad.addColorStop(1, 'rgba(20,34,59,0)');
  activeChart.push(new Chart(cv, {
    type: 'line',
    data: { labels, datasets: [
      { label: 'Weekly revenue', data, borderColor: lineColor, backgroundColor: grad, fill: true, tension: .25, borderWidth: 2, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: '#fff', pointHoverBorderColor: lineColor },
      { label: `Avg ${money(avg)}/wk`, data: data.map(() => avg), borderColor: '#9aa6b1', borderDash: [6, 6], borderWidth: 1.5, fill: false, pointRadius: 0, pointHoverRadius: 0 },
    ] },
    options: {
      responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0b1020', borderColor: '#1e2a44', borderWidth: 1, titleColor: '#fff', bodyColor: '#cfe0f5', padding: 10,
          callbacks: {
            title: (items) => { const w = weeks[items[0].dataIndex]; return w ? 'Week of ' + new Date(w.week + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : items[0].label; },
            label: (item) => item.datasetIndex === 0 ? `  ${money(item.parsed.y)}  ·  ${(units[item.dataIndex] || 0).toLocaleString('en-US')} units` : `  avg ${money(avg)}`,
          },
        },
      },
      scales: {
        y: { grid: { color: 'rgba(255,255,255,.06)' }, ticks: { color: '#8595ad', font: { size: 10 }, callback: (v) => '$' + (v / 1000).toFixed(0) + 'k' } },
        x: { grid: { display: false }, ticks: { color: '#8595ad', font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 12 } },
      },
    },
  }));
}

/* ============================================================
 * Inventory Accumulation — produced (Bihorario) vs shipped (SHIPPINGREPORT).
 * Positive gap = finished goods piling up in the warehouse.
 * ============================================================ */
function renderInventoryAccumulation(root) {
  const pvs = (MOCK.production && MOCK.production.producedVsShipped) || {};
  const rows = (pvs.byProduct || []).slice().sort((a, b) => (b.gap || 0) - (a.gap || 0));
  if (!rows.length) {
    root.innerHTML = `<div class="page-head"><div><p class="eyebrow">Production</p><h1>Inventory Accumulation</h1><p>Awaiting Bihorario + SHIPPINGREPORT to compute produced vs shipped.</p></div></div>`;
    return;
  }
  const produced = pvs.totalProduced || 0, shipped = pvs.totalShipped || 0, net = produced - shipped;
  const pilingUp = rows.filter(r => (r.gap || 0) > 0);
  const pileUnits = pilingUp.reduce((s, r) => s + r.gap, 0);
  const gapColor = (g) => g > 0 ? '#b45309' : g < 0 ? '#16a34a' : 'var(--ink-dim)';

  // BY CUSTOMER — produced tied to customers (each product's produced units split
  // across its buyers by shipping share) vs shipped. From producedVsShipped.byCustomer.
  const byCust = (pvs.byCustomer || []);

  // BY WEEK — weekly produced (Bihorario sewByDate) vs weekly shipped (weeklyRevenue units).
  const _mon = (iso) => { const d = new Date(iso + 'T00:00:00'); d.setDate(d.getDate() - ((d.getDay() + 6) % 7)); return d.toISOString().slice(0, 10); };
  const _prodWk = {}; ((MOCK.production.floorProduction || {}).sewByDate || []).forEach(x => { const k = _mon(x.date); _prodWk[k] = (_prodWk[k] || 0) + (x.units || 0); });
  const _shipWk = {}; ((MOCK.shipping.weeklyRevenue || {}).weeks || []).forEach(w => { _shipWk[w.week] = w.units || 0; });
  const wkKeys = Object.keys(_prodWk).sort();  // weeks where we have produced data
  const wkLabels = wkKeys.map(k => new Date(k + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
  const wkProd = wkKeys.map(k => Math.round(_prodWk[k]));
  const wkShip = wkKeys.map(k => Math.round(_shipWk[k] || 0));

  root.innerHTML = `
    <div class="page-head"><div>
      <p class="eyebrow">Production</p><h1>Inventory Accumulation</h1>
      <p>What's been produced but not yet shipped — finished goods building up in the warehouse.</p>
    </div></div>

    <div class="panel">
      <div class="panel-head"><h2>How this is computed — the pipeline</h2><span class="panel-meta">two files, one subtraction</span></div>
      <div style="display:flex;align-items:stretch;gap:0;padding:14px 18px 6px;flex-wrap:wrap">
        <div style="flex:1;min-width:170px;background:#f0f7ff;border-radius:10px;padding:12px 14px">
          <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#185fa5;font-weight:700">1 · Sewn on the floor</div>
          <div style="font-size:24px;font-weight:800;color:#0c447c">${fmtNum(produced)}</div>
          <div style="font-size:12px;color:#185fa5;margin-top:4px">Every unit that came off the SEW lines this year. Counted from the <strong>Bihorario</strong> — the floor's daily production log, by product.</div>
        </div>
        <div style="display:flex;align-items:center;padding:0 10px;font-size:22px;font-weight:800;color:var(--ink-dim)">−</div>
        <div style="flex:1;min-width:170px;background:#f2fbf7;border-radius:10px;padding:12px 14px">
          <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#0f6e56;font-weight:700">2 · Shipped to customers</div>
          <div style="font-size:24px;font-weight:800;color:#085041">${fmtNum(shipped)}</div>
          <div style="font-size:12px;color:#0f6e56;margin-top:4px">The same products that left the building, from the <strong>SHIPPINGREPORT</strong>. Once it ships, we invoice — shipped = money in.</div>
        </div>
        <div style="display:flex;align-items:center;padding:0 10px;font-size:22px;font-weight:800;color:var(--ink-dim)">=</div>
        <div style="flex:1;min-width:170px;background:#fff7ed;border-radius:10px;padding:12px 14px;border:1px solid #fcd9b6">
          <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#b45309;font-weight:700">3 · Sitting in the warehouse</div>
          <div style="font-size:24px;font-weight:800;color:#92400e">${net>=0?'+':''}${fmtNum(net)}</div>
          <div style="font-size:12px;color:#b45309;margin-top:4px">Finished goods sewn but not yet shipped — cash spent on labor + fabric that hasn't been invoiced yet.</div>
        </div>
      </div>
      <div style="padding:8px 18px 14px;font-size:13px;color:var(--ink-dim);line-height:1.5">
        <strong style="color:#14142b">Reading the tables below:</strong>
        <strong>Produced</strong> = column 1 (sewn) · <strong>Shipped</strong> = column 2 (out the door) · <strong>Gap</strong> = the difference.
        A <strong style="color:#b45309">+gap</strong> means we sewed more than we shipped — those units are in the warehouse (usually goods being built for an order that hasn't shipped yet).
        A <strong style="color:#16a34a">−gap</strong> means we shipped more than we sewed this year — those orders were filled from stock already on the shelf in January.
        ${(pvs.shippedNotSewn||[]).length ? `Items we ship but don't sew on the tracked lines (${pvs.shippedNotSewn.map(x=>escapeHtml(x.product)).join(', ')} — ${fmtNum(pvs.shippedNotSewnUnits||0)} units) are left out of the math entirely; they're listed at the bottom.` : ''}
      </div>
    </div>

    ${(pvs.warehouse||[]).length ? `<div class="panel" style="border-left:3px solid #b45309">
      <div class="panel-head"><h2>What's in the warehouse — by customer and product</h2><span class="panel-meta">${fmtNum((pvs.warehouse||[]).reduce((s,r)=>s+(r.total||0),0))} units sewn, not yet shipped (estimated)</span></div>
      <table>
        <thead><tr><th>Customer</th><th style="text-align:right">Units waiting</th><th>What it is</th></tr></thead>
        <tbody>${pvs.warehouse.map(r => `<tr>
          <td><strong>${escapeHtml(r.customer)}</strong></td>
          <td style="text-align:right;font-weight:800;color:#b45309">${fmtNum(r.total)}</td>
          <td style="font-size:13px">${r.products.map(p => `${escapeHtml(p.product)} <strong>${fmtNum(p.units)}</strong>${p.openOrderUnits>0?` <span style="color:var(--ink-dim)">(they have ${fmtNum(p.openOrderUnits)} on order)</span>`:''}`).join(' &nbsp;·&nbsp; ')}</td></tr>`).join('')}
        </tbody>
      </table>
      <p style="padding:8px 18px 12px;font-size:12px;color:var(--ink-dim)">Estimated: the floor log doesn't say who each unit is for, so produced units are attributed by each customer's share of that product's shipments + open orders. "On order" = units in their open WIP order book — goods usually sewn ahead of those orders.</p>
    </div>` : ''}

    <div class="kpi-grid">
      <div class="kpi" style="border-left:3px solid ${net>0?'#b45309':'#16a34a'}"><div class="kpi-label">Net accumulation</div><div class="kpi-value" style="color:${net>0?'#b45309':'#16a34a'}">${net>=0?'+':''}${fmtNum(net)}</div><div class="kpi-delta flat">in the warehouse = sewn − shipped</div></div>
      <div class="kpi"><div class="kpi-label">Produced YTD</div><div class="kpi-value">${fmtNum(produced)}</div><div class="kpi-delta flat">units sewn · Bihorario floor log</div></div>
      <div class="kpi"><div class="kpi-label">Shipped YTD</div><div class="kpi-value">${fmtNum(shipped)}</div><div class="kpi-delta flat">units out the door · SHIPPINGREPORT</div></div>
      <div class="kpi"><div class="kpi-label">Piling up</div><div class="kpi-value" style="color:#b45309">${fmtNum(pileUnits)}</div><div class="kpi-delta flat">sum of the +gaps · ${pilingUp.length} product${pilingUp.length===1?'':'s'}</div></div>
    </div>

    <div class="grid-2">
      <div class="panel"><div class="panel-head"><h2>Produced vs shipped — top products</h2><span class="panel-meta">by volume</span></div><div class="chart-wrap"><canvas id="accChart"></canvas></div></div>
      <div class="panel">
        <div class="panel-head"><h2>By product</h2><span class="panel-meta">+gap = in the warehouse · −gap = filled from January stock</span></div>
        <div style="overflow-x:auto"><table>
          <thead><tr><th>Product</th><th style="text-align:right">Sewn (produced)</th><th style="text-align:right">Out the door (shipped)</th><th style="text-align:right">Gap (in warehouse)</th></tr></thead>
          <tbody>${rows.map(r => `<tr>
            <td>${escapeHtml(r.product)}</td>
            <td style="text-align:right">${fmtNum(r.produced)}</td>
            <td style="text-align:right">${fmtNum(r.shipped)}</td>
            <td style="text-align:right;font-weight:700;color:${gapColor(r.gap)}">${r.gap>=0?'+':''}${fmtNum(r.gap)}</td></tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td style="text-align:right">${fmtNum(produced)}</td><td style="text-align:right">${fmtNum(shipped)}</td><td style="text-align:right;color:${gapColor(net)}">${net>=0?'+':''}${fmtNum(net)}</td></tr>
          </tbody></table></div>
      </div>
    </div>

    ${wkKeys.length ? `<div class="panel">
      <div class="panel-head"><h2>Produced vs shipped — by week</h2><span class="panel-meta">units sewn vs shipped each week · the gap is what's accumulating</span></div>
      <div class="chart-wrap"><canvas id="accWeekChart"></canvas></div>
    </div>` : ''}

    <div class="panel">
      <div class="panel-head"><h2>Produced vs shipped — by customer</h2><span class="panel-meta">whose goods are in the warehouse — usually orders sewn but not yet shipped</span></div>
      <table>
        <thead><tr><th>Customer</th><th style="text-align:right">Sewn for them (est.)</th><th style="text-align:right">Shipped to them</th><th style="text-align:right">Gap (in warehouse)</th></tr></thead>
        <tbody>${byCust.map(r => `<tr>
          <td><strong>${escapeHtml(r.customer)}</strong></td>
          <td style="text-align:right">${fmtNum(r.produced||0)}</td>
          <td style="text-align:right">${fmtNum(r.shipped||0)}</td>
          <td style="text-align:right;font-weight:700;color:${gapColor(r.gap||0)}">${(r.gap||0)>=0?'+':''}${fmtNum(r.gap||0)}</td></tr>`).join('')}
        <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td style="text-align:right">${fmtNum(byCust.reduce((s,r)=>s+(r.produced||0),0))}</td><td style="text-align:right">${fmtNum(byCust.reduce((s,r)=>s+(r.shipped||0),0))}</td><td style="text-align:right;color:${gapColor(byCust.reduce((s,r)=>s+(r.gap||0),0))}">${fmtNum(byCust.reduce((s,r)=>s+(r.gap||0),0))}</td></tr>
        </tbody>
      </table>
      <p style="padding:8px 18px;font-size:11px;color:var(--ink-dim)">Produced is tied to each customer by its share of that product's shipments <strong>plus open WIP orders</strong> — so goods being built for an order that hasn't shipped yet (e.g. Terraweave shorts) show under that customer. Per-customer figures are estimates. NW/Coreline included.</p>
    </div>
    ${(pvs.shippedNotSewn||[]).length ? `<div class="panel"><div class="panel-head"><h2>Shipped, but not sewn on the tracked lines</h2><span class="panel-meta">${fmtNum(pvs.shippedNotSewnUnits||0)} units excluded from the accumulation math</span></div>
      <p style="padding:6px 18px 12px;font-size:13px;color:var(--ink-dim)">${pvs.shippedNotSewn.map(x => `<strong style="color:#14142b">${escapeHtml(x.product)}</strong> ${fmtNum(x.units)}`).join(' &nbsp;·&nbsp; ')} — embellishment/specialty items with no SEW-line production record; counting them as "shipped" was distorting the gap.</p></div>` : ''}
    <p style="font-size:11px;color:var(--ink-dim);margin-top:8px">${escapeHtml(pvs.note||'')} Positive gap = produced more than shipped (accumulating); negative = shipped drew down prior stock. NW/Coreline is included.</p>
  `;

  const top = rows.slice().sort((a, b) => (b.produced + b.shipped) - (a.produced + a.shipped)).slice(0, 10);
  const cv = document.getElementById('accChart');
  if (cv && window.Chart) {
    activeChart.push(new Chart(cv, {
      type: 'bar',
      data: { labels: top.map(r => r.product), datasets: [
        { label: 'Produced', data: top.map(r => r.produced), backgroundColor: '#1c1c3a' },
        { label: 'Shipped', data: top.map(r => r.shipped), backgroundColor: '#f5a623' },
      ] },
      options: { responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { font: { size: 11 } } } },
        scales: { y: { beginAtZero: true, ticks: { font: { size: 10 } } }, x: { ticks: { font: { size: 9 }, maxRotation: 45, minRotation: 30 } } } }
    }));
  }
  const cvw = document.getElementById('accWeekChart');
  if (cvw && window.Chart && wkKeys.length) {
    activeChart.push(new Chart(cvw, {
      type: 'bar',
      data: { labels: wkLabels, datasets: [
        { label: 'Produced', data: wkProd, backgroundColor: '#1c1c3a', order: 2 },
        { label: 'Shipped', data: wkShip, backgroundColor: '#f5a623', order: 2 },
        { label: 'Gap (prod − ship)', type: 'line', data: wkProd.map((p, i) => p - wkShip[i]), borderColor: '#b45309', backgroundColor: 'rgba(180,69,9,.12)', fill: true, tension: .25, pointRadius: 3, order: 1 },
      ] },
      options: { responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: { legend: { position: 'bottom', labels: { font: { size: 11 } } } },
        scales: { y: { beginAtZero: true, ticks: { font: { size: 10 } } }, x: { grid: { display: false }, ticks: { font: { size: 10 } } } } }
    }));
  }
}

/* ============================================================
 * Collections — when we get paid + who to chase. From the QuickBooks A/R
 * open-invoice list (due dates + days past due).
 * ============================================================ */
function renderCollections(root) {
  const inv = (MOCK.sales.arOpenInvoicesSource || []).filter(x => (x.open || 0) > 0);
  if (!inv.length) {
    root.innerHTML = `<div class="page-head"><div><p class="eyebrow">Finance · Cash in</p><h1>Collections — getting paid</h1><p>Awaiting a QuickBooks A/R aging export (with due dates) to compute the collections timeline.</p></div></div>`;
    return;
  }
  const sum = (a) => a.reduce((s, x) => s + (x.open || 0), 0);
  const dp = (x) => x.daysPast || 0;
  const overdue = inv.filter(x => dp(x) > 0);
  const due7 = inv.filter(x => dp(x) <= 0 && dp(x) >= -7);
  const due30 = inv.filter(x => dp(x) < -7 && dp(x) >= -30);
  const due31 = inv.filter(x => dp(x) < -30);
  const total = sum(inv);
  const byC = {};
  overdue.forEach(x => { const g = byC[x.customer] = byC[x.customer] || { customer: x.customer, amt: 0, oldest: 0, n: 0 }; g.amt += x.open || 0; g.oldest = Math.max(g.oldest, dp(x)); g.n++; });
  const chase = Object.values(byC).sort((a, b) => b.amt - a.amt);
  const byU = {};
  inv.filter(x => dp(x) <= 0).forEach(x => { const g = byU[x.customer] = byU[x.customer] || { customer: x.customer, amt: 0, soon: 1e9 }; g.amt += x.open || 0; g.soon = Math.min(g.soon, -dp(x)); });
  const coming = Object.values(byU).sort((a, b) => a.soon - b.soon);
  const bucket = (label, arr, color) => { const v = sum(arr); return { label, v, n: arr.length, color, pct: total ? Math.round(v / total * 100) : 0 }; };
  const buckets = [bucket('Overdue — chase now', overdue, '#b91c1c'), bucket('Due ≤ 7 days', due7, '#b45309'), bucket('Due 8–30 days', due30, '#0a3d62'), bucket('Due 31+ days', due31, '#16a34a')];

  root.innerHTML = `
    <div class="page-head"><div><p class="eyebrow">Finance · Cash in</p><h1>Collections — when we get paid</h1>
      <p>Open A/R sorted by when it's due. Overdue = follow up now; the rest is expected cash by its due date.</p></div></div>

    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Open A/R</div><div class="kpi-value">${fmtMoney(total)}</div><div class="kpi-delta flat">${inv.length} invoices</div></div>
      <div class="kpi" style="border-left:3px solid #b91c1c"><div class="kpi-label">Overdue — chase now</div><div class="kpi-value" style="color:#b91c1c">${fmtMoney(sum(overdue))}</div><div class="kpi-delta flat">${overdue.length} invoices · ${chase.length} customers</div></div>
      <div class="kpi"><div class="kpi-label">Due in 7 days</div><div class="kpi-value">${fmtMoney(sum(due7))}</div><div class="kpi-delta flat">expected cash in</div></div>
      <div class="kpi"><div class="kpi-label">Due in 30 days</div><div class="kpi-value">${fmtMoney(sum(due7) + sum(due30))}</div><div class="kpi-delta flat">expected cash in</div></div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>Expected cash by due date</h2><span class="panel-meta">when the open A/R should land</span></div>
      <div style="padding:14px 18px;display:flex;flex-direction:column;gap:11px">
        ${buckets.map(b => `<div><div style="display:flex;justify-content:space-between;font-size:13px"><span><strong>${b.label}</strong> · ${b.n} inv</span><strong>${fmtMoney(b.v)} <span style="color:var(--ink-dim);font-weight:500">${b.pct}%</span></strong></div><div style="height:9px;background:#eef2f5;border-radius:5px;margin-top:4px;overflow:hidden"><div style="height:100%;width:${b.pct}%;background:${b.color}"></div></div></div>`).join('')}
      </div>
    </div>

    <div class="panel" style="border-left:4px solid #b91c1c">
      <div class="panel-head"><h2>Who to chase now</h2><span class="panel-meta">overdue A/R — approach these customers, biggest first</span></div>
      <table><thead><tr><th>Customer</th><th style="text-align:right">Overdue</th><th style="text-align:right">Oldest</th><th style="text-align:right">Invoices</th></tr></thead>
        <tbody>${chase.length ? chase.map(g => `<tr><td><strong>${escapeHtml(g.customer)}</strong></td><td style="text-align:right;font-weight:700;color:#b91c1c">${fmtMoney(g.amt)}</td><td style="text-align:right">${g.oldest}d late</td><td style="text-align:right;color:var(--ink-dim)">${g.n}</td></tr>`).join('') : emptyRow(4, 'Nothing overdue — nice.')}</tbody></table>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>Coming due (not yet overdue)</h2><span class="panel-meta">expected cash, soonest first</span></div>
      <table><thead><tr><th>Customer</th><th style="text-align:right">Amount</th><th style="text-align:right">Due in</th></tr></thead>
        <tbody>${coming.length ? coming.map(g => `<tr><td><strong>${escapeHtml(g.customer)}</strong></td><td style="text-align:right">${fmtMoney(g.amt)}</td><td style="text-align:right">${g.soon <= 0 ? 'now' : g.soon + 'd'}</td></tr>`).join('') : emptyRow(3, 'Nothing upcoming.')}</tbody></table>
    </div>
    <p style="font-size:11px;color:var(--ink-dim);margin-top:8px">Expected pay date = each invoice's due date (from QuickBooks terms). "Overdue" = already past due — follow up now. A true average days-to-pay would need a payments-received report (not yet uploaded).</p>
  `;
}

/* ============================================================
 * Price List — what each customer pays per item. Actual = shipped $ / units;
 * planned/forecast only when nothing has shipped yet.
 * ============================================================ */
function renderPriceList(root) {
  const pl = (MOCK.sales && MOCK.sales.priceList) || {};
  const items = pl.items || [];
  if (!items.length) {
    root.innerHTML = `<div class="page-head"><div><p class="eyebrow">Sales</p><h1>Price List</h1><p>Awaiting a SHIPPINGREPORT to derive prices.</p></div></div>`;
    return;
  }
  const groups = {};
  items.forEach(i => { (groups[i.customer] = groups[i.customer] || []).push(i); });
  const custs = Object.keys(groups).sort((a, b) => {
    const rev = (g) => groups[g].reduce((s, x) => s + (x.revenue || 0), 0);
    return rev(b) - rev(a);
  });
  const basisTag = (b) => b === 'actual' ? '<span class="tag tag-good">actual</span>' : b === 'planned' ? '<span class="tag tag-warn">planned</span>' : '<span class="tag" style="background:#e0e7ff;color:#3730a3">forecast</span>';
  const money2 = (n) => n == null ? '—' : '$' + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  root.innerHTML = `
    <div class="page-head"><div><p class="eyebrow">Sales · Pricing</p><h1>Price List — by customer &amp; item</h1>
      <p>What each customer pays per item. <strong>Actual</strong> = real shipped dollars ÷ units. Planned/forecast shown only where nothing has shipped yet.</p></div></div>
    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Customers</div><div class="kpi-value">${pl.customers || custs.length}</div><div class="kpi-delta flat">with prices</div></div>
      <div class="kpi"><div class="kpi-label">Items priced</div><div class="kpi-value">${items.length}</div><div class="kpi-delta flat">${items.filter(i => i.basis === 'actual').length} from real shipments</div></div>
      <div class="kpi"><div class="kpi-label">Highest price</div><div class="kpi-value">${money2(Math.max(...items.map(i => i.price)))}</div><div class="kpi-delta flat">${escapeHtml((items.slice().sort((a, b) => b.price - a.price)[0] || {}).product || '')}</div></div>
      <div class="kpi"><div class="kpi-label">Lowest price</div><div class="kpi-value">${money2(Math.min(...items.map(i => i.price)))}</div><div class="kpi-delta flat">${escapeHtml((items.slice().sort((a, b) => a.price - b.price)[0] || {}).product || '')}</div></div>
    </div>
    ${custs.map(c => { const g = groups[c]; const rev = g.reduce((s, x) => s + (x.revenue || 0), 0); return `
    <div class="panel">
      <div class="panel-head"><h2>${escapeHtml(c)}</h2><span class="panel-meta">${g.length} item${g.length === 1 ? '' : 's'}${rev > 0 ? ' · ' + fmtMoney(Math.round(rev)) + ' revenue YTD' : ' · no shipments yet'}</span></div>
      <table>
        <thead><tr><th>Item</th><th style="text-align:right">Price</th><th>Basis</th><th style="text-align:right">Units shipped</th><th style="text-align:right">Revenue</th><th style="text-align:right">Planned / fcst price</th></tr></thead>
        <tbody>${g.map(i => { const alt = i.basis === 'actual' ? (i.plannedPrice || i.forecastPrice) : i.forecastPrice; return `<tr>
          <td><strong>${escapeHtml(i.product)}</strong></td>
          <td style="text-align:right;font-weight:800;color:#0a3d62">${money2(i.price)}</td>
          <td>${basisTag(i.basis)}</td>
          <td style="text-align:right">${i.unitsShipped ? fmtNum(i.unitsShipped) : '—'}</td>
          <td style="text-align:right">${i.revenue ? fmtMoney(Math.round(i.revenue)) : '—'}</td>
          <td style="text-align:right;color:var(--ink-dim)">${alt && alt !== i.price ? money2(alt) : '—'}</td></tr>`; }).join('')}
        </tbody>
      </table>
    </div>`; }).join('')}
    <p style="font-size:11px;color:var(--ink-dim);margin-top:8px">${escapeHtml(pl.note || '')} Source: ${escapeHtml(pl.source || '')} · as of ${escapeHtml(pl.asOf || '')}. Excel copy: use the ⬇ Excel button above.</p>
  `;
}

/* ============================================================
 * Expenses — where the money goes. AP by category (paper, fabric, supplies…),
 * top vendors, and capital tied up in materials. For budgeting & cutbacks.
 * ============================================================ */
function renderExpenses(root) {
  const apc = MOCK.finance.apByCategory || {};
  const cats = (apc.byCategory || []).slice().sort((a, b) => (b.open || 0) - (a.open || 0));
  if (!cats.length) {
    root.innerHTML = `<div class="page-head"><div><p class="eyebrow">Finance</p><h1>Expenses</h1><p>Awaiting a categorized A/P / expense report (FINANCE_PARA_REPORTES) to break down spend.</p></div></div>`;
    return;
  }
  const totOpen = cats.reduce((s, c) => s + (c.open || 0), 0);
  const totPast = cats.reduce((s, c) => s + (c.pastDue || 0), 0);
  const vmap = {};
  (MOCK.finance.pastDueExpenses || []).concat(MOCK.finance.openExpenses || []).forEach(x => { vmap[x.vendor || '?'] = (vmap[x.vendor || '?'] || 0) + (x.amount || 0); });
  const vendors = Object.entries(vmap).map(([vendor, amt]) => ({ vendor, amt })).sort((a, b) => b.amt - a.amt).slice(0, 12);
  const mats = (MOCK.production.polypm || {}).byCategory || [];
  const matTotal = mats.reduce((s, c) => s + (c.cost || 0), 0);
  const pct = (v) => totOpen ? Math.round(v / totOpen * 100) : 0;

  root.innerHTML = `
    <div class="page-head"><div><p class="eyebrow">Finance · Spend</p><h1>Expenses</h1>
      <p>Where the money goes — A/P by category, top vendors, and capital tied up in materials. Use this to set budgets and find what to cut.</p></div></div>

    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">A/P open</div><div class="kpi-value">${fmtMoney(totOpen)}</div><div class="kpi-delta flat">${cats.length} categories</div></div>
      <div class="kpi" style="border-left:3px solid #b91c1c"><div class="kpi-label">Past due</div><div class="kpi-value" style="color:#b91c1c">${fmtMoney(totPast)}</div><div class="kpi-delta flat">${Math.round(totPast/totOpen*100)}% of open</div></div>
      <div class="kpi"><div class="kpi-label">Biggest category</div><div class="kpi-value" style="font-size:22px">${escapeHtml(cats[0].category)}</div><div class="kpi-delta flat">${fmtMoney(cats[0].open)} · ${pct(cats[0].open)}%</div></div>
      <div class="kpi"><div class="kpi-label">Materials on hand</div><div class="kpi-value">${fmtMoney(matTotal)}</div><div class="kpi-delta flat">capital tied up</div></div>
    </div>

    <div class="grid-2">
      <div class="panel"><div class="panel-head"><h2>Spend by category</h2><span class="panel-meta">open A/P · biggest first</span></div><div class="chart-wrap"><canvas id="expChart"></canvas></div></div>
      <div class="panel"><div class="panel-head"><h2>Materials on hand</h2><span class="panel-meta">inventory value — capital tied up</span></div>
        <table><thead><tr><th>Category</th><th style="text-align:right">Value</th><th style="text-align:right">% of materials</th></tr></thead>
          <tbody>${mats.map(c => `<tr><td><strong>${escapeHtml(c.category)}</strong></td><td style="text-align:right">${fmtMoney(c.cost||0)}</td><td style="text-align:right;color:var(--ink-dim)">${matTotal?Math.round((c.cost||0)/matTotal*100):0}%</td></tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:700"><td>TOTAL</td><td style="text-align:right">${fmtMoney(matTotal)}</td><td></td></tr></tbody></table>
        <p style="padding:8px 18px;font-size:11px;color:var(--ink-dim)">Fabric/trims/supplies sitting in the warehouse — over-buying here ties up cash.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>A/P by category</h2><span class="panel-meta">what we owe by type — the budget lines to target</span></div>
      <div style="overflow-x:auto"><table>
        <thead><tr><th>Category</th><th style="text-align:right">Open</th><th style="text-align:right">% of A/P</th><th style="text-align:right">Past due</th><th style="text-align:right">Bills</th><th style="text-align:right">Suppliers</th></tr></thead>
        <tbody>${cats.map(c => `<tr>
          <td><strong>${escapeHtml(c.category)}</strong></td>
          <td style="text-align:right;font-weight:700">${fmtMoney(c.open||0)}</td>
          <td style="text-align:right">${pct(c.open||0)}%</td>
          <td style="text-align:right;color:${(c.pastDue||0)>0?'#b91c1c':'var(--ink-dim)'}">${fmtMoney(c.pastDue||0)}</td>
          <td style="text-align:right;color:var(--ink-dim)">${fmtNum(c.bills||0)}</td>
          <td style="text-align:right;color:var(--ink-dim)">${fmtNum(c.suppliers||0)}</td></tr>`).join('')}
        <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td style="text-align:right">${fmtMoney(totOpen)}</td><td style="text-align:right">100%</td><td style="text-align:right">${fmtMoney(totPast)}</td><td></td><td></td></tr>
        </tbody></table></div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>Top vendors</h2><span class="panel-meta">open A/P by supplier</span></div>
      <table><thead><tr><th>Vendor</th><th style="text-align:right">Open A/P</th></tr></thead>
        <tbody>${vendors.map(v => `<tr><td><strong>${escapeHtml(v.vendor)}</strong></td><td style="text-align:right">${fmtMoney(v.amt)}</td></tr>`).join('')}</tbody></table>
    </div>
    <p style="font-size:11px;color:var(--ink-dim);margin-top:8px">Source: ${escapeHtml((apc.source||'').split('__').pop()||'FINANCE_PARA_REPORTES')} (categorized A/P, as of ${escapeHtml(apc.asOf||'—')}). This is what's owed (A/P) by category — the best spend proxy we have. For true budget-vs-actual you'd upload a P&L / expense report with paid amounts by period; drop it in Upload Data and this gets sharper.</p>
  `;

  const top = cats.slice(0, 12);
  const cv = document.getElementById('expChart');
  if (cv && window.Chart) {
    activeChart.push(new Chart(cv, {
      type: 'bar',
      data: { labels: top.map(c => c.category), datasets: [
        { label: 'Open', data: top.map(c => Math.round(c.open || 0)), backgroundColor: '#0a3d62' },
        { label: 'Past due', data: top.map(c => Math.round(c.pastDue || 0)), backgroundColor: '#e63027' },
      ] },
      options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { font: { size: 11 } } } },
        scales: { x: { beginAtZero: true, ticks: { font: { size: 9 }, callback: (v) => '$' + (v / 1000).toFixed(0) + 'k' } }, y: { ticks: { font: { size: 9 } } } } }
    }));
  }
}

/* ============================================================
 * SUPPORT — anyone can ask the AI tracker to do something.
 * Tickets feed into the 15-minute scheduled loop.
 * ============================================================ */
async function renderSupport(root) {
  const isAdmin = SESSION.role === 'admin';
  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Support · Requests</p>
        <h1>${isAdmin ? 'Open requests' : 'Ask AI for help'}</h1>
        <p>${isAdmin
          ? 'Anyone on the team can drop a request here — site changes, dashboard tweaks, data corrections, anything. The 15-minute AI loop reads pending tickets and acts on them.'
          : 'Need anything done to the site, dashboards or data? Drop a request — the AI will pick it up on its next pass and reply.'}</p>
      </div>
    </div>
    <div class="panel" style="margin-bottom:18px">
      <div class="panel-head"><h2>New request</h2></div>
      <form id="ticketForm" onsubmit="return false" style="display:grid;gap:12px">
        <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2);font-weight:800">
          Subject
          <input id="ticketSubject" placeholder="Short summary…" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-family:inherit;font-size:14px" />
        </label>
        <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2);font-weight:800">
          What do you need?
          <textarea id="ticketBody" placeholder="Describe the change or task…" rows="4" style="background:var(--paper-2);border:1px solid var(--line);border-radius:10px;padding:12px 14px;font-family:inherit;font-size:14px;resize:vertical"></textarea>
        </label>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2);font-weight:800">
            Section
            <select id="ticketSection" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-family:inherit;font-size:14px">
              ${Object.entries(SECTIONS).map(([k, s]) => `<option value="${k}" ${SESSION.section===k?'selected':''}>${s.label}</option>`).join('')}
              <option value="admin" ${isAdmin?'selected':''}>Overall / site</option>
            </select>
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2);font-weight:800">
            Priority
            <select id="ticketPriority" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-family:inherit;font-size:14px">
              <option value="normal">Normal</option>
              <option value="high">High</option>
              <option value="low">Low</option>
            </select>
          </label>
        </div>
        <div style="display:flex;gap:10px;align-items:center">
          <button class="btn btn-primary btn-sm" id="ticketSubmit">Submit request</button>
          <span id="ticketStatus" style="font-size:12px;color:var(--ink-dim)"></span>
        </div>
      </form>
    </div>
    <div class="panel">
      <div class="panel-head">
        <h2>${isAdmin ? 'All tickets' : 'Your tickets'}</h2>
        <span class="panel-meta" id="ticketCount">loading…</span>
      </div>
      <div id="ticketList" style="display:flex;flex-direction:column;gap:12px">
        <p style="color:var(--ink-dim);font-size:13px">Loading…</p>
      </div>
    </div>
  `;

  document.getElementById('ticketSubmit').addEventListener('click', async () => {
    const status = document.getElementById('ticketStatus');
    const subject = document.getElementById('ticketSubject').value.trim();
    const body = document.getElementById('ticketBody').value.trim();
    const section = document.getElementById('ticketSection').value;
    const priority = document.getElementById('ticketPriority').value;
    if (!body) { status.style.color='var(--red)'; status.textContent='Description can\'t be empty.'; return; }
    status.style.color='var(--ink-dim)'; status.textContent='Submitting…';
    try {
      const localToken = localStorage.getItem('asa_github_token');
      if (localToken) {
        // Commit ticket JSON to repo so the AI loop reads it.
        const ticketId = Date.now() + '-' + Math.random().toString(36).slice(2, 8);
        const ticket = {
          id: ticketId, requester: SESSION.username,
          subject, request_text: body, section, priority,
          status: 'open', created_at: new Date().toISOString(),
        };
        const json = JSON.stringify(ticket, null, 2);
        const path = `tickets/open/${ticketId}.json`;
        const contentBase64 = btoa(unescape(encodeURIComponent(json)));
        const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${path}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${localToken}`,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message: `Support ticket: ${subject || '(no subject)'} — ${SESSION.username}`,
            content: contentBase64,
            branch: 'main',
          }),
        });
        if (!r.ok) throw new Error(`GitHub ${r.status}: ${(await r.text()).slice(0,200)}`);
      } else if (API_BASE) {
        await apiPost('/api/support', { subject, request_text: body, section, priority });
      } else {
        throw new Error('No support backend configured. Open Settings and paste a GitHub token.');
      }
      document.getElementById('ticketSubject').value = '';
      document.getElementById('ticketBody').value = '';
      status.style.color='var(--green)'; status.textContent='✓ Submitted. The AI will pick this up on its next pass (within 15 min).';
      loadTicketList();
    } catch (e) {
      status.style.color='var(--red)'; status.textContent='✗ ' + e.message;
    }
  });

  loadTicketList();
}

async function loadTicketList() {
  const list = document.getElementById('ticketList');
  const counter = document.getElementById('ticketCount');
  if (!list) return;
  try {
    let tickets = [];
    const localToken = localStorage.getItem('asa_github_token');
    if (localToken) {
      // Read from repo (open + done folders)
      const fetchDir = async (dir) => {
        const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/tickets/${dir}`, {
          headers: { 'Authorization': `Bearer ${localToken}`, 'Accept': 'application/vnd.github+json' },
        });
        if (!r.ok) return [];
        const items = await r.json();
        if (!Array.isArray(items)) return [];
        const out = [];
        for (const it of items) {
          if (it.type !== 'file' || !it.name.endsWith('.json')) continue;
          try {
            const fr = await fetch(it.download_url);
            const t = await fr.json();
            t._sha = it.sha; t._dir = dir;
            out.push(t);
          } catch {}
        }
        return out;
      };
      const [openT, doneT] = await Promise.all([fetchDir('open'), fetchDir('done')]);
      tickets = [...openT, ...doneT].map((t) => ({
        id: t.id, subject: t.subject, request_text: t.request_text,
        section: t.section, priority: t.priority || 'normal',
        status: t._dir === 'done' ? (t.status || 'done') : (t.status || 'open'),
        ai_response: t.ai_response, requester_username: t.requester,
        created_at: t.created_at, resolved_at: t.resolved_at,
      })).sort((a,b) => (b.created_at || '').localeCompare(a.created_at || ''));
      // sub-account scoped client-side
      if (SESSION.role !== 'admin') {
        tickets = tickets.filter((t) => t.requester_username === SESSION.username);
      }
    } else {
      const data = await apiGet('/api/support');
      tickets = (data && data.tickets) || [];
    }
    if (counter) counter.textContent = tickets.length + ' ticket' + (tickets.length === 1 ? '' : 's');
    if (!tickets.length) {
      list.innerHTML = '<p style="color:var(--ink-dim);font-size:13px;padding:8px 4px">No tickets yet.</p>';
      return;
    }
    list.innerHTML = tickets.map(renderTicketCard).join('');
  } catch (e) {
    list.innerHTML = `<p style="color:var(--red);font-size:13px">Could not load: ${escapeHtml(e.message)}</p>`;
  }
}

function renderTicketCard(t) {
  const statusColor = {
    open: 'tag-warn', working: 'tag-info', done: 'tag-good',
    rejected: 'tag-bad', cancelled: 'tag-bad',
  }[t.status] || 'tag-info';
  const priorityColor = { high: 'tag-bad', normal: 'tag-info', low: 'tag-good' }[t.priority] || 'tag-info';
  const sectionLabel = SECTIONS[t.section] ? SECTIONS[t.section].label : (t.section || 'admin');
  const responseBlock = t.ai_response ? `
    <div style="margin-top:10px;padding:12px;background:linear-gradient(135deg,#f0f6ff 0%,#fff8e6 100%);border:1px solid #d8e3f5;border-radius:10px;font-size:13px">
      <strong>🤖 AI Response:</strong>
      <div style="margin-top:6px;white-space:pre-wrap">${escapeHtml(t.ai_response)}</div>
    </div>
  ` : '';
  return `
    <div style="background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;${t.status==='working'?'border-left:4px solid var(--gold)':''}${t.status==='done'?'border-left:4px solid var(--green)':''}">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">
        <strong>${escapeHtml(t.subject || '(no subject)')}</strong>
        <span class="tag ${statusColor}">${t.status}</span>
        <span class="tag ${priorityColor}">${t.priority}</span>
        <span class="tag" style="background:#eef2f9;color:var(--navy)">${escapeHtml(sectionLabel)}</span>
        <span style="margin-left:auto;font-size:11px;color:var(--ink-dim)">${escapeHtml(t.requester_username)} · ${new Date(t.created_at).toLocaleString()}</span>
      </div>
      <div style="font-size:14px;line-height:1.5;white-space:pre-wrap;color:var(--ink-2)">${escapeHtml(t.request_text)}</div>
      ${responseBlock}
    </div>
  `;
}

/* ============================================================
 * AI COMMENTS — threaded notes between the AI tracker and section users.
 * Admin sees every section. Sub-accounts see only their own.
 * Users can reply with a goal (metric + target + deadline).
 * ============================================================ */
async function renderComments(root) {
  // Full parity: every user (admin and section users) gets the same AI Comments UI as jdorf.
  const isAdmin = SESSION.role === 'admin';
  const sections = Object.keys(SECTIONS);
  const sectionSelector = `
    <label style="display:flex;align-items:center;gap:10px;font-size:13px;color:var(--ink-2);font-weight:600;margin-bottom:18px">
      Section
      <select id="commentsSection" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-family:inherit;font-size:13px">
        <option value="">All sections</option>
        ${sections.map(s => `<option value="${s}"${s === SESSION.section ? ' selected' : ''}>${SECTIONS[s].label}</option>`).join('')}
      </select>
    </label>
  `;

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">AI Tracker · Comments</p>
        <h1>AI Comments</h1>
        <p>Notes from the AI tracker about each section. Reply with your goals — the AI uses them to score progress on the dashboards. You can post to any section, view all sections, and the AI will execute your directives.</p>
      </div>
    </div>
    ${sectionSelector}
    <div class="panel" style="margin-bottom:18px">
      <div class="panel-head"><h2>Post a comment</h2></div>
      <form id="commentForm" onsubmit="return false" style="display:grid;gap:12px">
        <input type="hidden" id="newCommentSection" value="${SESSION.section || 'admin'}" />
        <input type="hidden" id="newCommentKind" value="reply" />
        <textarea id="newCommentText" placeholder="What's on your mind…" rows="3" style="background:var(--paper-2);border:1px solid var(--line);border-radius:10px;padding:12px 14px;font-family:inherit;font-size:14px;resize:vertical"></textarea>
        <div id="goalFields" style="display:none;grid-template-columns:1fr 1fr 1fr;gap:10px">
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2);font-weight:800">
            Metric
            <input id="newGoalMetric" placeholder="e.g. units_per_week" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-family:inherit;font-size:14px" />
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2);font-weight:800">
            Target
            <input id="newGoalTarget" type="number" placeholder="2000" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-family:inherit;font-size:14px" />
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2);font-weight:800">
            By date
            <input id="newGoalDeadline" type="date" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-family:inherit;font-size:14px" />
          </label>
        </div>
        <div style="display:flex;gap:10px;align-items:center">
          <button class="btn btn-primary btn-sm" id="postCommentBtn">Post</button>
          <span id="commentStatus" style="font-size:12px;color:var(--ink-dim)"></span>
        </div>
      </form>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Thread</h2><span class="panel-meta" id="commentCount">loading…</span></div>
      <div id="commentsList" style="display:flex;flex-direction:column;gap:14px">
        <p style="color:var(--ink-dim);font-size:13px">Loading comments…</p>
      </div>
    </div>
  `;

  document.getElementById('newCommentKind').addEventListener('change', (e) => {
    document.getElementById('goalFields').style.display = e.target.value === 'goal' ? 'grid' : 'none';
  });
  {
    const sel = document.getElementById('commentsSection');
    if (sel) sel.addEventListener('change', () => loadCommentsList(sel.value));
  }
  document.getElementById('postCommentBtn').addEventListener('click', async () => {
    const status = document.getElementById('commentStatus');
    const text = document.getElementById('newCommentText').value.trim();
    if (!text) { status.style.color = 'var(--red)'; status.textContent = 'Comment can\'t be empty.'; return; }
    const kind = document.getElementById('newCommentKind').value;
    const section = document.getElementById('newCommentSection').value || SESSION.section;
    const payload = { section, kind, text };
    if (kind === 'goal') {
      payload.goalMetric = document.getElementById('newGoalMetric').value.trim() || null;
      payload.goalTarget = document.getElementById('newGoalTarget').value || null;
      payload.goalDeadline = document.getElementById('newGoalDeadline').value || null;
    }
    status.style.color = 'var(--ink-dim)'; status.textContent = 'Posting…';
    const id = Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    try {
      const localToken = localStorage.getItem('asa_github_token');
      if (!localToken && !API_BASE) {
        throw new Error('No upload key on this device. Unlock the token banner at the top of the page first.');
      }
      if (localToken) {
        // Commit comment JSON to repo so the AI loop can read it
        const comment = {
          section: payload.section,
          author_type: 'user',
          author_username: SESSION.username,
          kind: payload.kind,
          text: payload.text,
          goal_metric: payload.goalMetric || null,
          goal_target: payload.goalTarget != null ? Number(payload.goalTarget) : null,
          goal_deadline: payload.goalDeadline || null,
          created_at: new Date().toISOString(),
        };
        const path = `comments/user/${id}.json`;
        const contentBase64 = btoa(unescape(encodeURIComponent(JSON.stringify(comment, null, 2))));
        const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${path}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${localToken}`,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message: `Comment from ${SESSION.username} on ${payload.section}`,
            content: contentBase64,
            branch: 'main',
          }),
        });
        if (!r.ok) throw new Error(`GitHub ${r.status}: ${(await r.text()).slice(0,200)}`);
      } else {
        await apiPost('/api/comments', payload);
      }
      document.getElementById('newCommentText').value = '';
      status.style.color = 'var(--green)'; status.textContent = '✓ Posted.';
      showToast('✓ Comment posted to ' + payload.section, 'success');
      // Track in sessionStorage so re-renders (after GitHub's stale directory
      // listing comes back) still show this comment until the canonical version lands.
      const optimistic = {
        id, // commit path id (matches filename) so we can dedupe when GitHub catches up
        section: payload.section,
        author_type: 'user',
        author_username: SESSION.username,
        comment_kind: payload.kind,
        comment_text: payload.text,
        goal_metric: payload.goalMetric || null,
        goal_target: payload.goalTarget != null ? Number(payload.goalTarget) : null,
        goal_deadline: payload.goalDeadline || null,
        created_at: new Date().toISOString(),
        _pending_until: Date.now() + 10 * 60 * 1000, // 10 min max
      };
      addPendingComment(optimistic);
      const filterSection = (document.getElementById('commentsSection') && document.getElementById('commentsSection').value) || '';
      // Background refresh — pending list ensures the new comment stays visible
      // even if GitHub's directory cache hasn't propagated.
      loadCommentsList(filterSection);
      setTimeout(() => loadCommentsList(filterSection), 6000);
      setTimeout(() => loadCommentsList(filterSection), 20000);
    } catch (e) {
      status.style.color = 'var(--red)'; status.textContent = '✗ ' + e.message;
      showToast('Post failed: ' + (e.message || 'unknown error'), 'error');
    }
  });
  loadCommentsList('');
}

const PENDING_KEY = 'asa_pending_comments_v1';
function getPendingComments() {
  try {
    const raw = sessionStorage.getItem(PENDING_KEY) || localStorage.getItem(PENDING_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    const now = Date.now();
    return arr.filter(p => !p._pending_until || p._pending_until > now);
  } catch { return []; }
}
function addPendingComment(c) {
  const arr = getPendingComments();
  arr.push(c);
  try { sessionStorage.setItem(PENDING_KEY, JSON.stringify(arr)); } catch {}
  try { localStorage.setItem(PENDING_KEY, JSON.stringify(arr)); } catch {}
}
function dropPendingByIds(ids) {
  if (!ids || !ids.size) return;
  const arr = getPendingComments().filter(p => !ids.has(p.id));
  try { sessionStorage.setItem(PENDING_KEY, JSON.stringify(arr)); } catch {}
  try { localStorage.setItem(PENDING_KEY, JSON.stringify(arr)); } catch {}
}

async function loadCommentsList(section) {
  const list = document.getElementById('commentsList');
  const counter = document.getElementById('commentCount');
  if (!list) return;
  try {
    let comments = [];
    const localToken = localStorage.getItem('asa_github_token');
    // Path 1: decrypted snapshot (commentsIndex from MOCK / data.enc.json).
    try {
      const d = await getSnapshotData();
      if (d && Array.isArray(d.commentsIndex) && d.commentsIndex.length) {
        comments = d.commentsIndex.slice();
      }
    } catch {}

    // Path 2: live GitHub fetch (used as fallback if snapshot is missing/empty).
    const useGitHub = comments.length === 0;

    if (useGitHub) {
      const baseHeaders = { 'Accept': 'application/vnd.github+json', 'Cache-Control': 'no-cache' };
      if (localToken) baseHeaders['Authorization'] = 'Bearer ' + localToken;
      // Use git/trees for ONE directory listing per session (cheaper than per-dir),
      // and raw.githubusercontent.com for file content (no API rate limit).
      const bust = '?ref=main&_=' + Date.now();
      const fetchDir = async (dir) => {
        const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${dir}${bust}`, {
          headers: baseHeaders,
          cache: 'no-store',
        });
        if (!r.ok) {
          // 403 → rate limited (anonymous = 60/hour/IP). Caller will show error.
          if (r.status === 403) throw new Error('GitHub rate limit hit. Unlock your token via the banner at top to get 5000/hr instead of 60/hr.');
          return { items: [], names: new Set() };
        }
        const items = await r.json();
        if (!Array.isArray(items)) return { items: [], names: new Set() };
        const out = [];
        const names = new Set();
        // Parallel raw fetches — no API rate limit, just CDN cached.
        const rawBase = `https://raw.githubusercontent.com/${SESSION.repo.owner}/${SESSION.repo.repo}/main`;
        const fileResults = await Promise.all(items.filter(it => it.type === 'file' && it.name.endsWith('.json')).map(async (it) => {
          names.add(it.name.replace(/\.json$/, ''));
          try {
            const fr = await fetch(`${rawBase}/${it.path}?_=${Date.now()}`, { cache: 'no-store' });
            if (!fr.ok) return null;
            const c = await fr.json();
            return {
              section: c.section, author_type: c.author_type || 'ai',
              author_username: c.author_username || c.author || null,
              comment_kind: c.kind || c.comment_kind || 'note',
              comment_text: c.text || c.comment_text || '',
              goal_metric: c.goal_metric, goal_target: c.goal_target, goal_deadline: c.goal_deadline,
              created_at: c.created_at,
            };
          } catch { return null; }
        }));
        for (const x of fileResults) if (x) out.push(x);
        return { items: out, names };
      };
      const [ai, user] = await Promise.all([
        fetchDir('comments/ai'),
        fetchDir('comments/user'),
      ]);
      comments = [...ai.items, ...user.items]
        .sort((a,b) => (b.created_at || '').localeCompare(a.created_at || ''));
      // Drop any pending entries that GitHub has now confirmed (filename matches).
      dropPendingByIds(user.names);
      if (section) comments = comments.filter(c => c.section === section);
      // (All users now see every section, matching admin behavior.)
    } else {
      const path = section ? `/api/comments?section=${encodeURIComponent(section)}` : '/api/comments';
      const data = await apiGet(path);
      comments = (data && data.comments) || [];
    }

    // Merge pending (just-posted, not yet visible in GitHub) comments so they
    // never flash out after the reload. They get dropped automatically once
    // GitHub's directory listing catches up (see dropPendingByIds above).
    let pending = getPendingComments();
    if (section) pending = pending.filter(p => p.section === section);
    if (pending.length) {
      const existingIds = new Set(comments.map(c => c.created_at + '|' + (c.comment_text || '')));
      const fresh = pending.filter(p => !existingIds.has(p.created_at + '|' + (p.comment_text || '')));
      comments = [...fresh, ...comments].sort((a,b) => (b.created_at || '').localeCompare(a.created_at || ''));
    }

    if (counter) counter.textContent = comments.length + ' comment' + (comments.length === 1 ? '' : 's');
    if (!comments.length) {
      list.innerHTML = '<p style="color:var(--ink-dim);font-size:13px;padding:8px 4px">No comments yet. Be the first to drop a note.</p>';
      return;
    }

    // Build maps for threading and resolution.
    // Each comment gets a stable id (from its filename, falling back to created_at|text).
    comments.forEach(c => { if (!c.id) c.id = (c.created_at || '') + '|' + (c.comment_text || '').slice(0,40); });
    const byId = new Map(comments.map(c => [c.id, c]));
    const childrenByParent = new Map();
    const resolvedByUserId = new Map(); // user_comment_id -> resolution AI comment
    for (const c of comments) {
      if (c.parent_id && byId.has(c.parent_id)) {
        if (!childrenByParent.has(c.parent_id)) childrenByParent.set(c.parent_id, []);
        childrenByParent.get(c.parent_id).push(c);
      }
      if (c.resolves_id && byId.has(c.resolves_id)) {
        resolvedByUserId.set(c.resolves_id, c);
      }
    }
    // Render top-level comments (no parent_id) — each card pulls its own thread.
    const topLevel = comments.filter(c => !c.parent_id);
    list.innerHTML = topLevel.map(c => renderThread(c, childrenByParent, resolvedByUserId, 0)).join('');
    attachCommentInteractions(list);
  } catch (e) {
    let hint = '';
    if (/401/.test(e.message)) hint = ' Your session expired — sign in again.';
    else if (/rate limit/i.test(e.message) || /403/.test(e.message)) hint = ' Unlock your token via the red banner up top — that switches you to 5000 requests/hour.';
    list.innerHTML = `<p style="color:var(--red);font-size:13px">Could not load chat history: ${escapeHtml(e.message)}.${hint}</p>`;
  }
}

function renderThread(c, childrenByParent, resolvedByUserId, depth) {
  const indent = depth > 0 ? `margin-left:${Math.min(depth, 3) * 24}px;` : '';
  const resolution = resolvedByUserId.get(c.id);
  const card = renderCommentCard(c, resolution);
  const children = (childrenByParent.get(c.id) || []).sort((a,b) => (a.created_at||'').localeCompare(b.created_at||''));
  const kids = children.map(k => renderThread(k, childrenByParent, resolvedByUserId, depth + 1)).join('');
  return `<div style="${indent}margin-bottom:10px">${card}${kids}</div>`;
}

function renderCommentCard(c, resolution) {
  const isMine = c.author_type !== 'ai' && c.author_username && SESSION.username && c.author_username === SESSION.username;
  const who = c.author_type === 'ai'
    ? '<span class="tag tag-info">🤖 AI Tracker</span>'
    : `<span class="tag tag-good">${escapeHtml(c.author_username || 'user')}${isMine ? ' (you)' : ''}</span>`;
  const when = c.created_at ? new Date(c.created_at).toLocaleString() : '';
  const sectionTag = c.section
    ? `<span class="tag" style="background:#eef2f9;color:var(--navy)">${escapeHtml(SECTIONS[c.section] ? SECTIONS[c.section].label : c.section)}</span>`
    : '';
  const KIND_LABELS = { reply: '↳ Reply', observation: '👁 Observation', goal: '🎯 Goal', note: 'Note', resolution: '✓ Resolution' };
  const kindLabel = c.comment_kind && KIND_LABELS[c.comment_kind] ? KIND_LABELS[c.comment_kind] : null;
  const kindTag = kindLabel ? `<span class="tag" style="background:#f3f4f6;color:var(--ink-2);font-size:11px">${kindLabel}</span>` : '';
  const goalBlock = c.comment_kind === 'goal' && c.goal_metric ? `
    <div style="margin-top:10px;padding:10px 12px;background:linear-gradient(135deg,#fff8e6 0%,#fef0d6 100%);border:1px dashed var(--gold);border-radius:10px;font-size:13px">
      <strong>🎯 Goal:</strong> ${escapeHtml(c.goal_metric)} → <strong>${fmtNum(c.goal_target)}</strong>
      ${c.goal_deadline ? ` by <strong>${new Date(c.goal_deadline).toLocaleDateString()}</strong>` : ''}
    </div>` : '';
  const resolvedBadge = resolution
    ? `<span class="tag" style="background:#dcfce7;color:#166534;font-weight:700">✓ Resolved</span>`
    : '';
  const mineBorder = isMine ? 'border-left:4px solid var(--green,#16a34a);' : '';
  const aiBorder = c.author_type === 'ai' ? 'border-left:4px solid var(--navy);' : '';
  const resolvedTint = resolution ? 'background:linear-gradient(180deg,#f0fdf4 0%,#fff 60%);' : 'background:#fff;';
  // Buttons (only when posting is possible — token present)
  const localToken = (typeof localStorage !== 'undefined') ? localStorage.getItem('asa_github_token') : null;
  const canPost = !!localToken;
  const isAdmin = SESSION && SESSION.role === 'admin';
  const replyBtn = canPost ? `<button class="asa-comment-action" data-action="reply" data-id="${escapeHtml(c.id||'')}" data-section="${escapeHtml(c.section||'')}" style="font-size:12px;color:var(--navy);background:none;border:0;cursor:pointer;font-weight:600">↳ Reply</button>` : '';
  const resolveBtn = (canPost && c.author_type === 'user' && !resolution)
    ? `<button class="asa-comment-action" data-action="resolve" data-id="${escapeHtml(c.id||'')}" data-section="${escapeHtml(c.section||'')}" style="font-size:12px;color:#166534;background:none;border:0;cursor:pointer;font-weight:600">✓ Mark resolved</button>`
    : '';
  return `
    <div data-comment-id="${escapeHtml(c.id||'')}" style="border:1px solid var(--line);border-radius:12px;padding:16px;${aiBorder}${mineBorder}${resolvedTint}">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">
        ${who} ${kindTag} ${sectionTag} ${resolvedBadge}
        <span style="margin-left:auto;font-size:11px;color:var(--ink-dim)">${when}</span>
      </div>
      <div style="font-size:14px;line-height:1.5;white-space:pre-wrap">${escapeHtml(c.comment_text || '')}</div>
      ${goalBlock}
      ${(replyBtn || resolveBtn) ? `<div style="margin-top:10px;display:flex;gap:14px">${replyBtn}${resolveBtn}</div>` : ''}
      <div class="asa-reply-host" style="margin-top:8px"></div>
    </div>
  `;
}

function attachCommentInteractions(root) {
  root.querySelectorAll('.asa-comment-action').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const action = btn.dataset.action;
      const parentId = btn.dataset.id;
      const section = btn.dataset.section;
      const card = btn.closest('[data-comment-id]');
      if (!card) return;
      const host = card.querySelector('.asa-reply-host');
      if (action === 'reply') {
        if (host.querySelector('textarea')) return; // already open
        host.innerHTML = `
          <div style="margin-top:6px;padding:10px 12px;background:var(--paper-2);border:1px solid var(--line);border-radius:10px">
            <textarea class="asa-reply-text" rows="2" placeholder="Type a reply…" style="width:100%;border:1px solid var(--line);border-radius:8px;padding:8px 10px;font:inherit;font-size:13px;resize:vertical"></textarea>
            <div style="display:flex;gap:8px;margin-top:8px"><button class="btn btn-primary btn-sm asa-reply-send">Post reply</button><button class="btn btn-ghost btn-sm asa-reply-cancel">Cancel</button></div>
          </div>`;
        host.querySelector('.asa-reply-cancel').onclick = () => { host.innerHTML = ''; };
        host.querySelector('.asa-reply-send').onclick = async () => {
          const text = host.querySelector('.asa-reply-text').value.trim();
          if (!text) return;
          await postReplyComment({ section, text, parent_id: parentId });
          host.innerHTML = '';
        };
      } else if (action === 'resolve') {
        await postResolutionComment({ section, resolves_id: parentId, text: 'Marked resolved by ' + (SESSION.username || 'admin') + '.' });
      }
    });
  });
}

async function postReplyComment({ section, text, parent_id }) {
  return postCommentRaw({ section, kind: 'reply', text, parent_id });
}
async function postResolutionComment({ section, resolves_id, text }) {
  return postCommentRaw({ section, kind: 'resolution', text, resolves_id, author_type: 'ai' });
}

async function postCommentRaw({ section, kind, text, parent_id, resolves_id, author_type }) {
  const id = Date.now() + '-' + Math.random().toString(36).slice(2, 8);
  const isAi = author_type === 'ai';
  const folder = isAi ? 'ai' : 'user';
  const comment = {
    section,
    author_type: author_type || 'user',
    author_username: isAi ? null : SESSION.username,
    kind,
    text,
    parent_id: parent_id || null,
    resolves_id: resolves_id || null,
    id,
    created_at: new Date().toISOString(),
  };
  const path = `comments/${folder}/${id}.json`;
  const localToken = localStorage.getItem('asa_github_token');
  if (!localToken) { showToast('Cannot post — unlock the token first.', 'error'); return; }
  const contentBase64 = btoa(unescape(encodeURIComponent(JSON.stringify(comment, null, 2))));
  try {
    const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${path}`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${localToken}`, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: `${kind} from ${SESSION.username} on ${section}`, content: contentBase64, branch: 'main' }),
    });
    if (!r.ok) throw new Error(`GitHub ${r.status}: ${(await r.text()).slice(0,200)}`);
    addPendingComment({ id, ...comment, comment_kind: kind, comment_text: text, author_type: comment.author_type, author_username: comment.author_username, _pending_until: Date.now() + 10*60*1000 });
    showToast(kind === 'resolution' ? '✓ Marked resolved' : '✓ Reply posted', 'success');
    loadCommentsList((document.getElementById('commentsSection')?.value || ''));
    setTimeout(() => loadCommentsList((document.getElementById('commentsSection')?.value || '')), 6000);
  } catch (e) {
    showToast('Failed: ' + e.message, 'error');
  }
}

/* ============================================================
 * SETTINGS — admin only.
 * Manages the GitHub PAT and Anthropic key. Saving re-encrypts
 * the vault for all 5 users and commits vault.json to the repo.
 * ============================================================ */
function maskKey(s) {
  if (!s) return '';
  if (s.length <= 8) return '•'.repeat(s.length);
  return s.slice(0, 4) + '•'.repeat(Math.max(8, s.length - 8)) + s.slice(-4);
}

async function renderSettings(root) {
  const localToken = localStorage.getItem('asa_github_token') || '';
  const tokenStatus = localToken
    ? `<span class="tag tag-good">Set · ${escapeHtml(maskKey(localToken))}</span>`
    : `<span class="tag tag-bad">Not set</span>`;

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Admin · Settings</p>
        <h1>Upload key</h1>
        <p>Paste a GitHub Personal Access Token here once. It will be encrypted with each user's password and committed to <code>admin/vault.json</code> in the repo, so all 5 users can sign in from any browser/device — no re-paste needed.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>Diagnose</h2><span class="panel-meta">use this to see why uploads/comments aren't working</span></div>
      <p style="font-size:13px;color:var(--ink-dim);margin:0 0 10px">If a teammate signs in but their uploads or comments fail, click this and screenshot the output.</p>
      <button class="btn btn-ghost btn-sm" id="diagBtn" type="button">Run diagnostics</button>
      <pre id="diagOut" style="margin-top:14px;padding:12px;background:#0e1116;color:#cfe9ff;border-radius:8px;font-size:12px;line-height:1.5;white-space:pre-wrap;display:none"></pre>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>GitHub token</h2><span class="panel-meta">encrypted &amp; persisted to repo vault.json</span></div>
      <form id="settingsForm" autocomplete="off" onsubmit="return false">
        <label class="settings-label">GitHub Personal Access Token ${tokenStatus}</label>
        <input type="password" id="ghToken" placeholder="${localToken ? 'Leave blank to keep current token' : 'github_pat_…'}" autocomplete="off" />
        <p class="settings-help">Needs <strong>Contents: Read and write</strong> on this repo. Create at <code>github.com/settings/personal-access-tokens/new</code>, scope to <code>summitteamapparel-site</code> only.</p>

        <div style="display:flex;gap:10px;margin-top:20px;flex-wrap:wrap">
          <button class="btn btn-primary" id="saveBtn">Save token</button>
          <button class="btn btn-ghost btn-sm" id="clearBtn" type="button">Clear token</button>
        </div>
        <p id="settingsStatus" style="margin-top:14px;font-size:13px"></p>
      </form>
    </div>
  `;

  document.getElementById('diagBtn').addEventListener('click', async () => {
    const out = document.getElementById('diagOut');
    out.style.display = 'block';
    const lines = [];
    const stamp = new Date().toISOString();
    lines.push('STA Admin Diagnostics — ' + stamp);
    lines.push('user: ' + (SESSION && SESSION.username));
    lines.push('admin.js loaded ✓');
    // vault.json fetch
    let vault = null;
    try {
      const r = await fetch('vault.json?t=' + Date.now(), { cache: 'no-store' });
      lines.push('vault.json fetch: ' + r.status + ' ' + r.statusText);
      if (r.ok) { vault = await r.json(); lines.push('vault users: ' + Object.keys(vault.users || {}).join(', ')); }
    } catch (e) { lines.push('vault.json fetch FAILED: ' + e.message); }
    // localStorage token
    const lt = localStorage.getItem('asa_github_token');
    lines.push('localStorage token: ' + (lt ? maskKey(lt) + ' (length ' + lt.length + ')' : 'EMPTY'));
    // SESSION secrets token
    const st = SESSION && SESSION.secrets && SESSION.secrets.githubToken;
    lines.push('SESSION secrets token: ' + (st ? maskKey(st) + ' (length ' + st.length + ')' : 'EMPTY'));
    // GitHub ping with whichever token we have
    const tok = lt || st;
    if (tok) {
      try {
        const r = await fetch('https://api.github.com/repos/' + REPO.owner + '/' + REPO.repo, { headers: { Authorization: 'Bearer ' + tok, Accept: 'application/vnd.github+json' } });
        lines.push('GitHub API repo check: ' + r.status + ' ' + r.statusText);
        if (!r.ok) { const t = await r.text(); lines.push('  -> ' + t.slice(0, 200)); }
      } catch (e) { lines.push('GitHub API check FAILED: ' + e.message); }
    } else {
      lines.push('SKIP GitHub API check (no token)');
    }
    out.textContent = lines.join('\n');
  });

  document.getElementById('saveBtn').addEventListener('click', async () => {
    const status = document.getElementById('settingsStatus');
    const btn = document.getElementById('saveBtn');
    const tk = (document.getElementById('ghToken').value.trim()) || localToken;
    if (!tk) {
      status.style.color = 'var(--red)';
      status.textContent = 'Paste a token first.';
      return;
    }
    btn.disabled = true;
    status.style.color = 'var(--ink-2)';
    status.textContent = 'Saving locally and encrypting vault for all 5 users…';
    try {
      localStorage.setItem('asa_github_token', tk);
      if (SESSION && SESSION.secrets) SESSION.secrets.githubToken = tk;
      try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(SESSION)); } catch {}

      const secrets = { githubToken: tk, anthropicKey: (SESSION.secrets && SESSION.secrets.anthropicKey) || null };
      const vault = await setupVaultAllUsers(secrets);
      await commitVault(vault, tk);

      status.style.color = 'var(--green)';
      status.textContent = '✓ Token saved & vault.json committed. Any user can now sign in from any device with just their password.';
      btn.disabled = false;
      setTimeout(() => navigate('settings'), 1200);
    } catch (e) {
      btn.disabled = false;
      status.style.color = 'var(--red)';
      status.textContent = 'Saved locally, but vault commit failed: ' + (e.message || e) + '. Check that the token has Contents: Read and write on this repo.';
    }
  });
  document.getElementById('clearBtn').addEventListener('click', () => {
    localStorage.removeItem('asa_github_token');
    if (SESSION && SESSION.secrets) SESSION.secrets.githubToken = null;
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(SESSION)); } catch {}
    navigate('settings');
  });
  return;
}

async function renderSettings_legacy(root) {
  const cur = SESSION.secrets || {};

  document.getElementById('saveBtn').addEventListener('click', async () => {
    const status = document.getElementById('settingsStatus');
    const btn = document.getElementById('saveBtn');
    const ghIn = document.getElementById('ghToken').value.trim();
    const anIn = document.getElementById('anthropicKey').value.trim();

    const newGh = ghIn || cur.githubToken || null;
    const newAn = anIn || cur.anthropicKey || null;
    if (!newGh) {
      status.style.color = 'var(--red)';
      status.textContent = 'A GitHub token is required to commit the vault to the repo.';
      return;
    }

    btn.disabled = true; btn.textContent = 'Saving…';
    status.style.color = 'var(--ink-dim)';
    status.textContent = 'Encrypting for all users…';

    try {
      const newSecrets = { githubToken: newGh, anthropicKey: newAn };
      const newVault = await setupVaultAllUsers(newSecrets);
      newVault.updatedAt = new Date().toISOString();
      status.textContent = 'Committing vault.json to repo…';
      await commitVault(newVault, newGh);

      SESSION.secrets = newSecrets;
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(SESSION));
      buildSidebar(SESSION); // refresh AI tab visibility

      status.style.color = 'var(--green)';
      status.textContent = '✓ Saved. All five users can now log in with just their password.';
      btn.disabled = false; btn.textContent = 'Save & commit to repo';
      // re-render settings so masked values update
      setTimeout(() => navigate('settings'), 800);
    } catch (e) {
      status.style.color = 'var(--red)';
      status.textContent = '✗ ' + (e.message || 'Save failed.');
      btn.disabled = false; btn.textContent = 'Save & commit to repo';
    }
  });

  document.getElementById('resetBtn').addEventListener('click', async () => {
    if (!confirm('Delete vault.json from the repo? Everyone will need to re-set up keys.')) return;
    if (!cur.githubToken) { alert('No GitHub token in this session — re-paste one in the field above first.'); return; }
    try {
      const r = await fetch(`https://api.github.com/repos/${REPO.owner}/${REPO.repo}/contents/admin/vault.json`, {
        headers: { 'Authorization': `Bearer ${cur.githubToken}`, 'Accept': 'application/vnd.github+json' },
      });
      if (!r.ok) throw new Error('vault.json not found in repo');
      const j = await r.json();
      const del = await fetch(`https://api.github.com/repos/${REPO.owner}/${REPO.repo}/contents/admin/vault.json`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${cur.githubToken}`, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'Reset vault', sha: j.sha, branch: 'main' }),
      });
      if (!del.ok) throw new Error('Delete failed');
      alert('Vault reset. Sign out and back in to re-create.');
    } catch (e) { alert(e.message); }
  });
}

/* ============================================================
 * VIEWS
 * ============================================================ */
function fmtMoney(n) { return '$' + (Number(n) || 0).toLocaleString('en-US'); }
function fmtNum(n) { return (Number(n) || 0).toLocaleString('en-US'); }
function safePct(curr, prev) {
  if (!prev || prev === 0) return curr ? '+∞' : '0.0';
  return (((curr - prev) / prev) * 100).toFixed(1);
}
function emptyRow(cols, msg) {
  return `<tr><td colspan="${cols}" style="text-align:center;color:var(--ink-dim);font-style:italic;padding:24px">${msg || 'No data yet — upload files to populate.'}</td></tr>`;
}
function fmtBytes(n) { if (n<1024) return n+' B'; if (n<1024*1024) return (n/1024).toFixed(1)+' KB'; return (n/1024/1024).toFixed(1)+' MB'; }
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function previewBanner() {
  return `<div class="prototype-banner">⚠ Charts use sample data — connect real CSVs by uploading them on the section pages. Files are committed to <code>${SESSION.repo.owner}/${SESSION.repo.repo}</code>.</div>`;
}

/* Customer reliability — what each customer FORECAST (told us) vs what they
 * ACTUALLY gave, YTD. From production.forecastByCustomer (FORECAST_VS_ACTUAL). */
function custReliabilityPanel(opts) {
  const fva = (MOCK.production && MOCK.production.forecastVsActual) || {};
  const months = fva.months || [];
  const bc = fva.byCustomer || {};
  const through = fva.actualThroughMonth || months.length;   // months with actuals (e.g. 6 = thru June)
  if (!months.length || !Object.keys(bc).length) return '';
  const elapsed = months.slice(0, through);                  // Jan..current
  const m3 = (m) => m.slice(0, 3);
  const col = (p) => p == null ? 'var(--ink-dim)' : p >= 95 ? '#16a34a' : p >= 60 ? '#b45309' : '#b91c1c';
  // Customer families: a parent "mothership" owns several booking names.
  // Pulse Performance owns Dance + Zenith (marching band) — roll them up under Pulse.
  const FAMILIES = { 'Pulse Performance': ['g2 performance', 'dance', 'apex'] };
  const parentOf = {}; Object.keys(FAMILIES).forEach(p => FAMILIES[p].forEach(m => parentOf[m] = p));
  const rows = Object.keys(bc).filter(c => c !== 'All').map(c => {
    const o = bc[c], f = o.forecastUnits || [], a = o.actualUnits || [];
    const cells = elapsed.map((_, i) => ({ f: f[i] || 0, a: a[i] || 0, pct: (f[i] || 0) > 0 ? Math.round((a[i] || 0) / f[i] * 100) : null }));
    const yF = cells.reduce((s, x) => s + x.f, 0), yA = cells.reduce((s, x) => s + x.a, 0);
    return { customer: c, cells, yF, yA, yPct: yF > 0 ? Math.round(yA / yF * 100) : null };
  }).filter(r => r.yF > 0 || r.yA > 0);
  if (!rows.length) return '';
  // Group family members under their parent (aggregate cells), keep others standalone.
  const aggCells = (members) => elapsed.map((_, i) => {
    const f = members.reduce((s, r) => s + r.cells[i].f, 0), a = members.reduce((s, r) => s + r.cells[i].a, 0);
    return { f, a, pct: f > 0 ? Math.round(a / f * 100) : null };
  });
  const groups = {};   // parent -> [member rows]
  const standalone = [];
  rows.forEach(r => { const p = parentOf[String(r.customer).toLowerCase()]; if (p) (groups[p] = groups[p] || []).push(r); else standalone.push(r); });
  const entries = standalone.map(r => ({ kind: 'single', row: r, sortF: r.yF }));
  Object.keys(groups).forEach(p => {
    const members = groups[p].sort((a, b) => b.yF - a.yF);
    const cells = aggCells(members);
    const yF = cells.reduce((s, x) => s + x.f, 0), yA = cells.reduce((s, x) => s + x.a, 0);
    entries.push({ kind: 'group', parent: p, members, cells, yF, yA, yPct: yF > 0 ? Math.round(yA / yF * 100) : null, sortF: yF });
  });
  entries.sort((a, b) => b.sortF - a.sortF);
  const allRows = rows;  // totals across every booking name
  const tot = elapsed.map((_, i) => ({ f: allRows.reduce((s, r) => s + r.cells[i].f, 0), a: allRows.reduce((s, r) => s + r.cells[i].a, 0) }));
  const tYF = allRows.reduce((s, r) => s + r.yF, 0), tYA = allRows.reduce((s, r) => s + r.yA, 0);
  const cellHtml = (x) => {
    if (!x.f && !x.a) return '<td style="text-align:right;color:var(--ink-dim)">·</td>';
    return `<td style="text-align:right;color:${col(x.pct)}"><div style="font-weight:700">${fmtNum(x.a)}</div><div style="font-size:10px;color:var(--ink-dim)">/${fmtNum(x.f)}${x.pct != null ? ' · ' + x.pct + '%' : ''}</div></td>`;
  };
  const dataRow = (label, cells, yF, yA, yPct, opts = {}) => `<tr${opts.bg ? ` style="background:${opts.bg}"` : ''}>
        <td style="${opts.indent ? 'padding-left:26px;' : ''}${opts.bold ? 'font-weight:800' : ''}">${opts.indent ? '<span style="color:var(--ink-dim)">↳ </span>' : ''}${opts.bold ? '<strong>' : ''}${escapeHtml(label)}${opts.bold ? '</strong>' : ''}${opts.tag || ''}</td>
        ${cells.map(cellHtml).join('')}
        <td style="text-align:right;background:#f8fafc">${fmtNum(yF)}</td>
        <td style="text-align:right;background:#f8fafc;font-weight:700">${fmtNum(yA)}</td>
        <td style="text-align:right;background:#f8fafc;font-weight:800;color:${col(yPct)}">${yPct == null ? '—' : yPct + '%'}</td></tr>`;
  return `
  <div class="panel" style="border-left:4px solid #0a3d62">
    <div class="panel-head"><h2>Customer reliability — forecast vs actual, by month</h2><span class="panel-meta">each cell: actual units / forecast · delivered % · ${m3(elapsed[0])}–${m3(elapsed[elapsed.length-1])} YTD</span></div>
    <div style="overflow-x:auto"><table style="min-width:720px">
      <thead><tr><th>Customer</th>${elapsed.map(m => `<th style="text-align:right">${m3(m)}</th>`).join('')}<th style="text-align:right;background:#eff6ff">YTD fcst</th><th style="text-align:right;background:#eff6ff">YTD act</th><th style="text-align:right;background:#eff6ff">YTD %</th></tr></thead>
      <tbody>${entries.map(e => {
        if (e.kind === 'single') return dataRow(e.row.customer, e.row.cells, e.row.yF, e.row.yA, e.row.yPct);
        const tag = ` <span style="font-size:10px;background:#eef2ff;color:#3730a3;padding:1px 7px;border-radius:8px;font-weight:600">family · ${e.members.length} brands</span>`;
        return dataRow(e.parent, e.cells, e.yF, e.yA, e.yPct, { bold: true, bg: '#fbfbfe', tag })
          + e.members.map(m => dataRow(m.customer, m.cells, m.yF, m.yA, m.yPct, { indent: true })).join('');
      }).join('')}
      <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td>${tot.map(x => { const p = x.f > 0 ? Math.round(x.a / x.f * 100) : null; return `<td style="text-align:right;color:${col(p)}">${p == null ? '·' : p + '%'}</td>`; }).join('')}<td style="text-align:right">${fmtNum(tYF)}</td><td style="text-align:right">${fmtNum(tYA)}</td><td style="text-align:right;color:${col(tYF > 0 ? Math.round(tYA / tYF * 100) : null)}">${tYF > 0 ? Math.round(tYA / tYF * 100) + '%' : '—'}</td></tr>
      </tbody></table></div>
    <p style="padding:8px 18px;font-size:11px;color:var(--ink-dim)">Each month cell = delivered % (units received ÷ what the customer forecast for that month); "·" = nothing forecast that month. <strong>Pulse Performance</strong> is the parent of <strong>Dance</strong> and <strong>Zenith</strong> (marching band) — the bold Pulse row is the family total, with each brand listed beneath. Green ≥95% · amber 60–94% · red &lt;60%. Source: FORECAST_VS_ACTUAL, actuals through ${m3(elapsed[elapsed.length-1])}.</p>
  </div>`;
}

/* Pipeline & forward outlook — open orders + rest-of-year forecast, whether
 * each customer's forecast is trending up/down vs their run-rate, how reliably
 * they deliver, and what it all means for production capacity. */
function pipelinePanel() {
  const fva = (MOCK.production && MOCK.production.forecastVsActual) || {};
  const months = fva.months || [], through = fva.actualThroughMonth || 6, bc = fva.byCustomer || {};
  if (!months.length || !Object.keys(bc).length) return '';
  const cap = ((MOCK.production && MOCK.production.capacityBenchmark) || {}).weekly || 12000;
  const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const ooMap = {}, ooUsd = {}; ((MOCK.production && MOCK.production.openOrdersByCustomer) || []).forEach(r => { const k = norm(r.customer); ooMap[k] = (ooMap[k] || 0) + (r.units || 0); ooUsd[k] = (ooUsd[k] || 0) + (r.usd || 0); });
  const pvs = (MOCK.production && MOCK.production.producedVsShipped) || {};
  const whNet = (pvs.totalProduced || 0) - (pvs.totalShipped || 0);  // produced but not shipped = warehouse accumulation
  const rem = Math.max(1, months.length - through);
  const rows = Object.keys(bc).filter(c => c !== 'All').map(c => {
    const f = bc[c].forecastUnits || [], a = bc[c].actualUnits || [];
    const elapsedF = f.slice(0, through).reduce((s, x) => s + (x || 0), 0);
    const fwdF = f.slice(through).reduce((s, x) => s + (x || 0), 0);
    const em = elapsedF / Math.max(1, through), fm = fwdF / rem;
    const trend = elapsedF === 0 ? (fwdF > 0 ? 'new' : 'none') : (fm < em * 0.9 ? 'down' : fm > em * 1.1 ? 'up' : 'flat');
    const deliv = elapsedF > 0 ? Math.round(a.slice(0, through).reduce((s, x) => s + (x || 0), 0) / elapsedF * 100) : null;
    return { customer: c, open: ooMap[norm(c)] || 0, openUsd: ooUsd[norm(c)] || 0, fwdF, em, fm, trend, deliv };
  }).filter(r => r.open > 0 || r.fwdF > 0 || r.deliv != null).sort((a, b) => (b.open + b.fwdF) - (a.open + a.fwdF));
  if (!rows.length) return '';
  const totOpen = rows.reduce((s, r) => s + r.open, 0), totOpenUsd = rows.reduce((s, r) => s + r.openUsd, 0), totFwd = rows.reduce((s, r) => s + r.fwdF, 0);
  const trendChip = (t) => t === 'up' ? '<span style="color:#16a34a;font-weight:700">▲ up</span>' : t === 'down' ? '<span style="color:#b91c1c;font-weight:700">▼ down</span>' : t === 'new' ? '<span style="color:#0a3d62;font-weight:700">new</span>' : '<span style="color:var(--ink-dim)">flat</span>';
  const signal = (r) => {
    if (r.trend === 'down' && r.deliv != null && r.deliv < 80) return '<span class="tag tag-bad">cut forecast & behind — call them</span>';
    if (r.trend === 'up' && (r.deliv == null || r.deliv >= 90)) return '<span class="tag tag-good">ramping — ready capacity</span>';
    if (r.deliv != null && r.deliv < 60) return '<span class="tag tag-warn">under-delivering</span>';
    return '<span style="color:var(--ink-dim)">—</span>';
  };
  return `<div class="panel" style="border-left:4px solid #0a3d62">
    <div class="panel-head"><h2>Pipeline &amp; forward outlook</h2><span class="panel-meta">open orders + rest-of-year forecast vs how customers actually deliver — and what it means for production</span></div>
    <div class="kpi-grid" style="margin:0 0 4px">
      <div class="kpi"><div class="kpi-label">Open orders (pipeline)</div><div class="kpi-value">${fmtNum(totOpen)}</div><div class="kpi-delta flat">~${(totOpen/cap).toFixed(1)} wks @ ${fmtNum(cap)}/wk</div></div>
      <div class="kpi"><div class="kpi-label">Forecast — rest of year</div><div class="kpi-value">${fmtNum(totFwd)}</div><div class="kpi-delta flat">~${(totFwd/cap).toFixed(1)} wks of work</div></div>
      <div class="kpi" style="cursor:pointer;border-left:3px solid #b45309" onclick="navigate('invAccum')"><div class="kpi-label">Produced, not shipped</div><div class="kpi-value" style="color:${whNet>0?'#b45309':whNet<0?'#16a34a':'inherit'}">${whNet>=0?'+':''}${fmtNum(whNet)}</div><div class="kpi-delta flat">accumulated in warehouse →</div></div>
      <div class="kpi"><div class="kpi-label">Weekly capacity</div><div class="kpi-value">${fmtNum(cap)}</div><div class="kpi-delta flat">units/wk · ${totFwd>cap*Math.max(1,rem*4.3)?'forecast > capacity':'within capacity'}</div></div>
    </div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>Customer</th><th style="text-align:right">Open orders</th><th style="text-align:right">Open $</th><th style="text-align:right">Fwd forecast</th><th style="text-align:right">Run-rate /mo</th><th style="text-align:center">Forecast</th><th style="text-align:right">Delivered YTD</th><th>What it means</th></tr></thead>
      <tbody>${rows.map(r => `<tr>
        <td><strong>${escapeHtml(r.customer)}</strong></td>
        <td style="text-align:right;font-weight:700;color:#b45309">${fmtNum(r.open)}</td>
        <td style="text-align:right">${fmtMoney(Math.round(r.openUsd))}</td>
        <td style="text-align:right">${fmtNum(r.fwdF)}</td>
        <td style="text-align:right;color:var(--ink-dim)">${fmtNum(Math.round(r.em))} → ${fmtNum(Math.round(r.fm))}</td>
        <td style="text-align:center">${trendChip(r.trend)}</td>
        <td style="text-align:right;font-weight:700;color:${r.deliv == null ? 'var(--ink-dim)' : r.deliv >= 95 ? '#16a34a' : r.deliv >= 60 ? '#b45309' : '#b91c1c'}">${r.deliv == null ? '—' : r.deliv + '%'}</td>
        <td>${signal(r)}</td></tr>`).join('')}
      <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td style="text-align:right">${fmtNum(totOpen)}</td><td style="text-align:right">${fmtMoney(Math.round(totOpenUsd))}</td><td style="text-align:right">${fmtNum(totFwd)}</td><td></td><td></td><td></td><td></td></tr>
      </tbody></table></div>
    <p style="padding:8px 18px;font-size:11px;color:var(--ink-dim)">Fwd forecast = units the customer says are coming the rest of the year (Jul–Dec). "Run-rate /mo" = their avg forecast per month, elapsed → forward (a drop means they're pulling back). "Delivered YTD" = actual ÷ forecast so far. A customer who <strong>cut their forecast and is behind</strong> (e.g. Granite) is a call to make; ones <strong>ramping up</strong> need capacity reserved. Capacity ${fmtNum(cap)} units/wk.</p>
  </div>`;
}

/* Sales pipeline — 2026 outlook by momentum/confidence (from the Sales Tracker
 * Pipeline Overview). What's in the book and how solid it is. */
function salesPipelinePanel() {
  const p = (MOCK.sales && MOCK.sales.pipeline) || {};
  const rows = p.byCustomer || [];
  if (!rows.length) return '';
  const momColor = (m) => /active|growing/i.test(m) ? '#16a34a' : /advancing/i.test(m) ? '#b45309' : /developing/i.test(m) ? '#d97706' : '#64748b';
  return `<div class="panel" style="border-left:4px solid #2bb673">
    <div class="panel-head"><h2>Sales pipeline — 2026 outlook by momentum</h2><span class="panel-meta">what's in the book + how solid · ${fmtNum(p.totalUnits)} units / ${fmtMoney(p.totalRevenue)} projected (not booked)</span></div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>Customer</th><th>Momentum</th><th>Status</th><th style="text-align:right">2026 units</th><th style="text-align:right">2026 revenue</th><th>Product notes</th></tr></thead>
      <tbody>${rows.map(x => `<tr>
        <td><strong>${escapeHtml(x.customer)}</strong></td>
        <td style="white-space:nowrap;color:${momColor(x.momentum)};font-weight:700">${escapeHtml(x.momentum || '—')}</td>
        <td style="font-size:12px">${escapeHtml(x.status || '')}</td>
        <td style="text-align:right;font-weight:700">${fmtNum(x.units2026)}</td>
        <td style="text-align:right">${x.revenue2026 > 0 ? fmtMoney(x.revenue2026) : '<span style="color:var(--ink-dim)">TBD</span>'}</td>
        <td style="font-size:12px;color:var(--ink-dim)">${escapeHtml((x.notes || '').slice(0, 46))}</td></tr>`).join('')}
      <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td></td><td></td><td style="text-align:right">${fmtNum(p.totalUnits)}</td><td style="text-align:right">${fmtMoney(p.totalRevenue)}</td><td></td></tr>
      </tbody></table></div>
    <p style="padding:8px 18px;font-size:11px;color:var(--ink-dim)">${escapeHtml(p.note || '')}</p>
  </div>`;
}

/* NW snapshot for the Overview — the key prepaid account at a glance.
 * Full detail lives in the NW tab; this is the owner's quick read. */
function uaSnapshotPanel() {
  const ua = (MOCK.production && MOCK.production.ua) || null;
  if (!ua || !ua.advance) return '';
  const adv = ua.advance || {}, sc = ua.scorecard || {}, pp = ua.productionPlan || {}, inv = ua.inventory || {}, aging = ua.pastDueAging || {};
  const owed = adv.owedUnits || 0, delivered = adv.deliveredYtdUnits || 0, committed = owed + delivered;
  const dPct = committed > 0 ? Math.round(delivered / committed * 100) : 0;
  const past = aging.total || 0;
  const cwUa = (MOCK.shipping.currentWeek || {}).ua || {}, lwUa = (MOCK.shipping.lastWeek || {}).ua || {};
  const wkUa = (cwUa.unitsShipped || 0) > 0 || (cwUa.unitsPlanned || 0) > 0 ? cwUa : lwUa;
  const wkLabel = wkUa === cwUa ? 'this week' : 'last week';
  const statColor = past > 1000 ? '#fca5a5' : past > 0 ? '#fde68a' : '#86efac';
  const statText = past > 0 ? `${fmtNum(past)} units past required date — recovery in production` : 'On schedule — nothing past due';
  const cell = (label, val, sub) => `<div style="background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:12px 14px">
    <div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:rgba(255,255,255,.55)">${label}</div>
    <div style="font-size:21px;font-weight:800;color:#fff;margin-top:2px">${val}</div>
    <div style="font-size:10.5px;color:rgba(255,255,255,.55)">${sub}</div></div>`;
  return `
  <div class="panel" style="background:linear-gradient(135deg,#14142b 0%,#2a2a5a 100%);color:#fff;padding:20px 24px;cursor:pointer" onclick="navigate('ua')">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <div>
        <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;opacity:.65">Key account · prepaid</div>
        <div style="font-size:20px;font-weight:800">Northwind (Coreline) <span style="font-size:12px;font-weight:600;color:${statColor}">● ${statText}</span></div>
      </div>
      <span style="font-size:12px;color:rgba(255,255,255,.6)">full NW detail →</span>
    </div>
    <div style="margin-top:14px">
      <div style="display:flex;justify-content:space-between;font-size:11.5px;opacity:.8;margin-bottom:5px"><span>Delivered ${fmtNum(delivered)} units</span><span>${fmtNum(owed)} still owed</span></div>
      <div style="height:11px;background:rgba(255,255,255,.14);border-radius:6px;overflow:hidden"><div style="height:100%;width:${dPct}%;background:linear-gradient(90deg,#22c55e,#86efac)"></div></div>
      <div style="font-size:10.5px;opacity:.6;margin-top:4px">${dPct}% of the ${fmtNum(committed)}-unit prepaid program delivered</div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:10px;margin-top:14px">
      ${cell('Owed (prepaid)', fmtNum(owed), fmtMoney(Math.round(adv.owedUsd || 0)))}
      ${cell('In production', (pp.totalInProductionUnits || 0) > 0 ? fmtNum(pp.totalInProductionUnits) : '—', (pp.totalInProductionUnits || 0) > 0 ? 'heading to shipping' : 'not in latest CAPACITY export')}
      ${cell('Shipped ' + wkLabel, fmtNum(wkUa.unitsShipped || 0), 'of ' + fmtNum(wkUa.unitsPlanned || 0) + ' planned')}
      ${cell('Fill rate', sc.fillRatePct != null ? sc.fillRatePct + '%' : '—', 'shipped vs planned YTD')}
      ${cell('Raw materials left ($)', fmtMoney(inv.onHandCost || 0), fmtNum(inv.onHandUnits || 0) + ' on hand')}
    </div>
  </div>`;
}

/* What's on the production lines — placeholder until the line-status report is
 * uploaded; auto-fills from production.productionLines once it lands. */
function productionLinesPanel() {
  const raw = (MOCK.production && MOCK.production.productionLines);
  const rows = Array.isArray(raw) ? raw : (raw && Array.isArray(raw.lines) ? raw.lines : []);
  if (!rows.length) {
    return `<div class="panel" style="border:1px dashed #cfd8e0;background:#fafbfc">
      <div class="panel-head"><h2>On the production lines</h2><span class="panel-meta">live line status · awaiting data upload</span></div>
      <div style="padding:26px 22px;text-align:center;color:var(--ink-dim);font-size:13px;line-height:1.7">
        📋 <strong>Reserved for production-line data.</strong><br>
        Upload a report of what each line is currently running — line, customer, product, units, status — via <a href="#" onclick="navigate('upload');return false;">Upload Data</a>, and this panel fills in automatically.
      </div></div>`;
  }
  const f = (o, ...ks) => { for (const k of ks) { if (o[k] != null && o[k] !== '') return o[k]; } return ''; };
  const asof = (raw && raw.asOf) ? ' · as of ' + escapeHtml(raw.asOf) : '';
  return `<div class="panel">
    <div class="panel-head"><h2>On the production lines</h2><span class="panel-meta">what each line is running${asof}</span></div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>Line</th><th>Customer</th><th>Product</th><th style="text-align:right">Units</th><th>Status</th></tr></thead>
      <tbody>${rows.map(r => `<tr>
        <td><strong>${escapeHtml(f(r, 'line', 'lineName', 'module', 'area'))}</strong></td>
        <td>${escapeHtml(f(r, 'customer', 'client'))}</td>
        <td>${escapeHtml(f(r, 'product', 'program', 'item'))}</td>
        <td style="text-align:right">${fmtNum(f(r, 'units', 'qty', 'quantity') || 0)}</td>
        <td>${escapeHtml(f(r, 'status', 'state') || '—')}</td></tr>`).join('')}</tbody></table></div>
  </div>`;
}

/* ============================================================
 * OWNER BRIEFING — the state of the business in plain English, computed live
 * from the data. The first thing the owner reads. Every line links to detail.
 * ============================================================ */
function ownerBriefing() {
  const ES = (typeof LANG !== 'undefined' && LANG === 'es');
  const T = (en, es) => ES ? es : en;
  const L = [];
  const money = (n) => '$' + Math.round(n).toLocaleString('en-US');
  // --- Cash / A/R ---
  const inv = (MOCK.sales.arOpenInvoicesSource || []).filter(x => (x.open || 0) > 0);
  const arOpen = inv.reduce((s, x) => s + x.open, 0);
  const od = inv.filter(x => (x.daysPast || 0) > 0);
  const odSum = od.reduce((s, x) => s + x.open, 0);
  const due7 = inv.filter(x => (x.daysPast || 0) <= 0 && (x.daysPast || 0) >= -7).reduce((s, x) => s + x.open, 0);
  if (arOpen > 0) {
    const byC = {}; od.forEach(x => byC[x.customer] = (byC[x.customer] || 0) + x.open);
    const top = Object.entries(byC).sort((a, b) => b[1] - a[1])[0];
    L.push({ dot: odSum > arOpen * .4 ? 'red' : odSum > 0 ? 'amber' : 'green', view: 'collections',
      html: T(
        `<strong>${money(arOpen)} is owed to us.</strong> ${odSum > 0 ? `${money(odSum)} is overdue${top ? ` — <strong>${escapeHtml(top[0])}</strong> is ${money(top[1])} of it; call them` : ''}.` : 'Nothing overdue.'} ${due7 > 0 ? money(due7) + ' should land in the next 7 days.' : ''}`,
        `<strong>${money(arOpen)} nos deben.</strong> ${odSum > 0 ? `${money(odSum)} está vencido${top ? ` — <strong>${escapeHtml(top[0])}</strong> es ${money(top[1])} de eso; llámalos` : ''}.` : 'Nada vencido.'} ${due7 > 0 ? money(due7) + ' debería entrar en los próximos 7 días.' : ''}`) });
  }
  // --- This week ---
  const cw = MOCK.shipping.currentWeek || {}, lw = MOCK.shipping.lastWeek || {};
  const started = (cw.unitsShipped || 0) > 0 || (cw.unitsPlanned || 0) > 0;
  const wk = started ? cw : lw;
  const pct = (wk.unitsPlanned || 0) > 0 ? Math.round((wk.unitsShipped || 0) / wk.unitsPlanned * 100) : null;
  L.push({ dot: pct == null ? 'navy' : pct >= 95 ? 'green' : pct >= 80 ? 'amber' : 'red', view: 'shipping',
    html: started
      ? T(`<strong>This week we've shipped ${fmtNum(wk.unitsShipped || 0)} of ${fmtNum(wk.unitsPlanned || 0)} planned units</strong>${pct != null ? ` (${pct}%)` : ''}${(wk.usdShipped||0)>0 ? ` — ${money(wk.usdShipped)} out the door` : ''}.`,
          `<strong>Esta semana hemos enviado ${fmtNum(wk.unitsShipped || 0)} de ${fmtNum(wk.unitsPlanned || 0)} unidades planificadas</strong>${pct != null ? ` (${pct}%)` : ''}${(wk.usdShipped||0)>0 ? ` — ${money(wk.usdShipped)} despachadas` : ''}.`)
      : T(`<strong>The week is just starting.</strong> Last week we shipped ${fmtNum(lw.unitsShipped || 0)} units${(lw.unitsPlanned || 0) > 0 ? ` against ${fmtNum(lw.unitsPlanned)} planned (${Math.round((lw.unitsShipped || 0) / lw.unitsPlanned * 100)}%)` : ''}${(lw.usdShipped||0)>0 ? ` — ${money(lw.usdShipped)} out the door` : ''}.`,
          `<strong>La semana apenas comienza.</strong> La semana pasada enviamos ${fmtNum(lw.unitsShipped || 0)} unidades${(lw.unitsPlanned || 0) > 0 ? ` frente a ${fmtNum(lw.unitsPlanned)} planificadas (${Math.round((lw.unitsShipped || 0) / lw.unitsPlanned * 100)}%)` : ''}${(lw.usdShipped||0)>0 ? ` — ${money(lw.usdShipped)} despachadas` : ''}.`) });
  // --- Warehouse accumulation ---
  const pvs = MOCK.production.producedVsShipped || {};
  const net = (pvs.totalProduced || 0) - (pvs.totalShipped || 0);
  if (pvs.totalProduced) L.push({ dot: net > 5000 ? 'amber' : 'green', view: 'invAccum',
    html: net > 0
      ? T(`<strong>${fmtNum(net)} units are sitting in the warehouse</strong> — produced but not yet shipped. Every one of them is cash waiting to be collected.`,
          `<strong>${fmtNum(net)} unidades están en el almacén</strong> — producidas pero aún no enviadas. Cada una es efectivo esperando ser cobrado.`)
      : T(`<strong>The warehouse is clearing</strong> — we're shipping more than we produce (net ${fmtNum(net)}).`,
          `<strong>El almacén se está despejando</strong> — estamos enviando más de lo que producimos (neto ${fmtNum(net)}).`) });
  // --- Order book vs capacity ---
  const oo = (MOCK.production.openOrdersByCustomer || []).reduce((s, r) => s + (r.units || 0), 0);
  const cap = ((MOCK.production.capacityBenchmark || {}).weekly) || 12000;
  if (oo > 0) {
    const wks = oo / cap;
    L.push({ dot: wks >= 4 ? 'green' : wks >= 2 ? 'amber' : 'red', view: 'productionFlow',
      html: T(`<strong>The order book holds ${fmtNum(oo)} units</strong> — about ${wks.toFixed(1)} weeks of work at ${fmtNum(cap)}/wk capacity${wks < 2 ? ' — the book is getting thin; we need orders' : ''}.`,
              `<strong>El libro de órdenes tiene ${fmtNum(oo)} unidades</strong> — cerca de ${wks.toFixed(1)} semanas de trabajo a capacidad de ${fmtNum(cap)}/sem${wks < 2 ? ' — el libro se está adelgazando; necesitamos órdenes' : ''}.`) });
  }
  // --- NW (Coreline) ---
  const ua = MOCK.production.ua || {};
  if (ua.advance) {
    const owedU = ua.advance.owedUnits || 0, inProd = (ua.productionPlan || {}).totalInProductionUnits || 0;
    const uaPast = (ua.pastDueAging || {}).total || 0;
    const fill = (ua.scorecard || {}).fillRatePct;
    L.push({ dot: uaPast > 1000 ? 'red' : uaPast > 0 ? 'amber' : 'green', view: 'ua',
      html: T(`<strong>NW (Coreline): we still owe ${fmtNum(owedU)} prepaid units</strong>${inProd > 0 ? ` — ${fmtNum(inProd)} are in production now` : ''}${fill != null ? ` · fill rate ${fill}%` : ''}. ${uaPast > 0 ? `<strong>${fmtNum(uaPast)} units are past their required date.</strong>` : 'Nothing past due — the program is on schedule.'}`,
              `<strong>NW (Coreline): aún debemos ${fmtNum(owedU)} unidades prepagadas</strong>${inProd > 0 ? ` — ${fmtNum(inProd)} están en producción ahora` : ''}${fill != null ? ` · cumplimiento ${fill}%` : ''}. ${uaPast > 0 ? `<strong>${fmtNum(uaPast)} unidades están pasadas de su fecha.</strong>` : 'Nada vencido — el programa va en tiempo.'}`) });
  }
  // --- Pipeline risk ---
  const fva = MOCK.production.forecastVsActual || {};
  const bc = fva.byCustomer || {}; const thr = fva.actualThroughMonth || 6; const rem = Math.max(1, 12 - thr);
  const risks = [];
  Object.keys(bc).filter(c => c !== 'All').forEach(c => {
    const f = bc[c].forecastUnits || [], a = bc[c].actualUnits || [];
    const eF = f.slice(0, thr).reduce((s, x) => s + (x || 0), 0), fF = f.slice(thr).reduce((s, x) => s + (x || 0), 0);
    if (eF < 1000) return;
    const deliv = Math.round(a.slice(0, thr).reduce((s, x) => s + (x || 0), 0) / eF * 100);
    if ((fF / rem) < (eF / thr) * 0.9 && deliv < 80) risks.push({ c, deliv });
  });
  if (risks.length) L.push({ dot: 'red', view: 'forecastVsActual',
    html: T(`<strong>${risks.map(r => escapeHtml(r.c)).join(', ')} ${risks.length > 1 ? 'have' : 'has'} cut the forward forecast AND ${risks.length > 1 ? 'are' : 'is'} behind on what was promised</strong> (${risks.map(r => r.deliv + '%').join(', ')} delivered) — worth a direct conversation.`,
            `<strong>${risks.map(r => escapeHtml(r.c)).join(', ')} ${risks.length > 1 ? 'han' : 'ha'} recortado el pronóstico futuro Y ${risks.length > 1 ? 'están' : 'está'} atrasado(s) en lo prometido</strong> (${risks.map(r => r.deliv + '%').join(', ')} entregado) — vale una conversación directa.`) });
  // --- Late production ---
  const ws = MOCK.production.wipSummary || {};
  if ((ws.lateProgramCount || 0) > 0) L.push({ dot: (ws.lateValue || 0) > 50000 ? 'red' : 'amber', view: 'capacityWip',
    html: T(`<strong>${ws.lateProgramCount} programs are past their required date</strong> (${fmtNum(ws.lateUnits || 0)} units · ${money(ws.lateValue || 0)} at risk). Oldest: ${escapeHtml(ws.oldestProgram || '')}.`,
            `<strong>${ws.lateProgramCount} programas están pasados de su fecha</strong> (${fmtNum(ws.lateUnits || 0)} unidades · ${money(ws.lateValue || 0)} en riesgo). Más viejo: ${escapeHtml(ws.oldestProgram || '')}.`) });
  // --- Bills ---
  const apPast = (MOCK.finance.pastDueExpenses || []).reduce((s, x) => s + (x.amount || 0), 0);
  if (apPast > 0) L.push({ dot: 'amber', view: 'expenses',
    html: T(`<strong>We owe suppliers ${money(apPast)} past due.</strong> Biggest categories: ink &amp; paper, shipping, rent, fabric — see Expenses for what to negotiate or cut.`,
            `<strong>Debemos a proveedores ${money(apPast)} vencido.</strong> Categorías más grandes: tinta y papel, envío, renta, tela — ve Gastos para qué negociar o recortar.`) });
  if (!L.length) return '';
  const dotColor = { red: '#f87171', amber: '#fbbf24', green: '#4ade80', navy: '#93c5fd' };
  const dateStr = new Date().toLocaleDateString(ES ? 'es-DO' : 'en-US', { weekday: 'long', month: 'long', day: 'numeric' });
  return `
  <div class="panel" style="background:linear-gradient(135deg,#0d1b2a 0%,#1c2e4a 100%);color:#e8eef6;padding:24px 28px;margin-bottom:18px">
    <div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px">
      <div style="font-size:11px;letter-spacing:2.5px;text-transform:uppercase;color:#7fd1a8;font-weight:700">${T('The state of the business','El estado del negocio')}</div>
      <div style="font-size:12px;color:#8aa0b8">${dateStr} · ${T('live from the latest uploads','en vivo desde las últimas cargas')}</div>
    </div>
    <div style="margin-top:14px;display:flex;flex-direction:column;gap:11px">
      ${L.map(l => `<div onclick="navigate('${l.view}')" style="cursor:pointer;display:flex;gap:12px;align-items:flex-start;padding:10px 14px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);border-radius:10px" onmouseover="this.style.background='rgba(255,255,255,.1)'" onmouseout="this.style.background='rgba(255,255,255,.05)'">
        <span style="margin-top:5px;width:9px;height:9px;border-radius:50%;background:${dotColor[l.dot]};flex-shrink:0;box-shadow:0 0 8px ${dotColor[l.dot]}"></span>
        <span style="font-size:15px;line-height:1.6;color:#dce6f2">${l.html}</span>
        <span style="margin-left:auto;color:#5f7a96;font-size:14px;flex-shrink:0">→</span>
      </div>`).join('')}
    </div>
  </div>`;
}

function secHead(emoji, title, sub) {
  return `<div style="display:flex;align-items:baseline;gap:10px;margin:26px 2px 10px;border-bottom:2px solid var(--line);padding-bottom:7px">
    <span style="font-size:16px">${emoji}</span>
    <span style="font-size:13px;font-weight:800;letter-spacing:1.6px;text-transform:uppercase;color:#14142b">${title}</span>
    ${sub ? `<span style="font-size:11.5px;color:var(--ink-dim)">${sub}</span>` : ''}
  </div>`;
}

function renderOverview(root) {
  const totalReceivables = (MOCK.sales.receivableSummary||[]).reduce((a,b)=>a+(b.open||0),0);
  const overdueAr = (MOCK.sales.arOpenInvoicesSource||[]).filter(x=>(x.daysPast||0)>0).reduce((s,x)=>s+(x.open||0),0);
  const totalPastDue = (MOCK.finance.pastDueExpenses||[]).reduce((a,b)=>a+(b.amount||0),0);
  const pastDueCount = (MOCK.finance.pastDueExpenses||[]).length;
  const wip = MOCK.production.wip || [];
  const shippedByCust = MOCK.finance.shippedByCustomer || [];
  const today = new Date();   // real today — late-day math must not go stale
  // Warehouse accumulation = produced (Bihorario) − shipped (SHIPPINGREPORT)
  const _pvs = MOCK.production.producedVsShipped || {};
  const accProduced = _pvs.totalProduced || 0, accShipped = _pvs.totalShipped || 0;
  const accNet = accProduced - accShipped;

  // Late orders summary (from WIP — programs with reqDate in the past)
  const lateOrders = wip.map(w => {
    let delay = null;
    if (w.reqDate && w.reqDate !== '—') {
      const d = new Date(w.reqDate);
      if (!isNaN(d)) delay = Math.round((today - d) / 86400000);
    }
    return {...w, delay};
  }).filter(w => w.delay !== null && w.delay > 0).sort((a,b)=>b.delay-a.delay);
  const lateUnits = lateOrders.reduce((s,w)=>s+(w.promised||0),0);
  const lateUSD = lateOrders.reduce((s,w)=>s+(w.usd||0),0);

  // Top customers by sales volume (YTD revenue from finance.shippedByCustomer)
  const topByRev = shippedByCust.slice().sort((a,b)=>(b.revenue||0)-(a.revenue||0)).slice(0,8);
  const topByUnits = shippedByCust.slice().sort((a,b)=>(b.shipped||0)-(a.shipped||0)).slice(0,8);

  // Weekly production performance by customer — use latest week from FvA byCustomer or shipping byCustomer (this week)
  const wkBC = MOCK.shipping.byCustomer || [];
  const totWkPlan = wkBC.reduce((s,r)=>s+(r.unitsPlanned||0),0);
  const totWkAct = wkBC.reduce((s,r)=>s+(r.unitsShipped||0),0);
  const totWkPlanD = wkBC.reduce((s,r)=>s+(r.usdPlanned||0),0);
  const totWkActD = wkBC.reduce((s,r)=>s+(r.usdShipped||0),0);
  const totWkPct = totWkPlan>0 ? Math.round(totWkAct/totWkPlan*100) : null;
  const totWkPctD = totWkPlanD>0 ? Math.round(totWkActD/totWkPlanD*100) : null;
  const fmtP = (p) => p == null ? '<span style="color:var(--ink-dim)">—</span>' : p >= 95 ? `<span class="tag tag-good">${p}%</span>` : p >= 80 ? `<span class="tag tag-warn">${p}%</span>` : `<span class="tag tag-bad">${p}%</span>`;

  // This-week % to plan: prefer the current week; if it hasn't started yet (no
  // plan or shipments — e.g. Monday morning), fall back to the last COMPLETED
  // week so the KPI is never blank.
  const _cw = MOCK.shipping.currentWeek || {}, _lw = MOCK.shipping.lastWeek || {};
  let wkAct = _cw.unitsShipped || 0, wkPlan = _cw.unitsPlanned || 0, wkScope = 'this week', _wkUa = _cw.ua || {};
  if (!wkPlan && !wkAct) { wkAct = _lw.unitsShipped || 0; wkPlan = _lw.unitsPlanned || 0; wkScope = 'last full wk'; _wkUa = _lw.ua || {}; }
  const wkPct = wkPlan > 0 ? Math.round(wkAct / wkPlan * 100) : null;
  const wkUaShip = _wkUa.unitsShipped || 0, wkUaPlan = _wkUa.unitsPlanned || 0;
  const wkUaPct = wkAct > 0 ? Math.round(wkUaShip / wkAct * 100) : 0;  // NW share of the week's shipped units
  // YTD revenue = shipped YTD US$ from SHIPPINGREPORT (authoritative per AGENT_RULES).
  const ytdRevUsd = (MOCK.production.flow && MOCK.production.flow.shippedYTD && MOCK.production.flow.shippedYTD.usd) || 0;
  const ytdRevUnits = (MOCK.production.flow && MOCK.production.flow.shippedYTD && MOCK.production.flow.shippedYTD.units) || 0;

  // Daily tracking: programs sorted by delay then earliest req
  const dailyOrders = wip.slice().sort((a,b) => {
    const aD = a.reqDate && a.reqDate!=='—' ? (today - new Date(a.reqDate))/86400000 : -9999;
    const bD = b.reqDate && b.reqDate!=='—' ? (today - new Date(b.reqDate))/86400000 : -9999;
    return bD - aD;
  });

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Admin Overview</p>
        <h1>Today at a glance</h1>
        <p>The state of the business, computed live from the latest uploads — every line links to the detail.</p>
      </div>
    </div>

    ${ownerBriefing()}

    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Owed to us</div><div class="kpi-value">${fmtMoney(totalReceivables)}</div><div class="kpi-delta flat">${MOCK.sales.receivableSummary.length} customers</div></div>
      <div class="kpi" style="cursor:pointer;border-left:3px solid #b91c1c" onclick="navigate('collections')"><div class="kpi-label">Overdue — call now</div><div class="kpi-value" style="color:#b91c1c">${fmtMoney(overdueAr)}</div><div class="kpi-delta flat">past due · who to chase →</div></div>
      <div class="kpi"><div class="kpi-label">This week vs plan</div><div class="kpi-value" style="color:${wkPct==null?'inherit':wkPct>=95?'#16a34a':wkPct>=80?'#b45309':'#b91c1c'}">${wkPct!=null?wkPct+'%':'—'}</div><div class="kpi-delta flat">${fmtNum(wkAct)} / ${fmtNum(wkPlan)} units · ${wkScope}</div></div>
      <div class="kpi" style="border-left:3px solid #1c1c3a"><div class="kpi-label">↳ of which NW</div><div class="kpi-value" style="color:#1c1c3a">${wkUaPct}%</div><div class="kpi-delta flat">${fmtNum(wkUaShip)} / ${fmtNum(wkUaPlan)} units · NW (Coreline)</div></div>
      <div class="kpi"><div class="kpi-label">Revenue this year</div><div class="kpi-value">${fmtMoney(ytdRevUsd)}</div><div class="kpi-delta flat">${fmtNum(ytdRevUnits)} units shipped YTD</div></div>
      <div class="kpi" style="cursor:pointer" onclick="navigate('invAccum')"><div class="kpi-label">Sitting in warehouse</div><div class="kpi-value" style="color:${accNet>0?'#b45309':accNet<0?'#16a34a':'inherit'}">${accNet>=0?'+':''}${fmtNum(accNet)}</div><div class="kpi-delta flat">warehouse accumulation · units →</div></div>
    </div>

    ${secHead('💰','Money in','revenue pace · is business up or down')}

    ${(() => {
      // HOW WE'RE DOING — BY MONTH: actual shipped vs plan, with YTD attainment
      // and the forward forecast. The real month-by-month performance view.
      const mp = MOCK.finance && MOCK.finance.monthlyPerformance;
      if (!mp || !Array.isArray(mp.months) || !mp.months.length) return '';
      const done = mp.months.filter(m => m.status === 'actual' || m.status === 'current');
      const maxV = Math.max(1, ...mp.months.map(m => Math.max(m.shippedUsd || 0, m.plannedUsd || 0, m.forecastUsd || 0)));
      const attColor = (p) => p == null ? 'var(--ink-dim)' : p >= 95 ? '#16a34a' : p >= 80 ? '#b45309' : '#b91c1c';
      const bar = (v, color) => `<div style="height:8px;border-radius:2px;background:${color};width:${Math.round((v / maxV) * 100)}%;min-width:${v > 0 ? '2px' : '0'}"></div>`;
      return `<div class="panel">
        <div class="panel-head"><h2>How we're doing — by month</h2><span class="panel-meta">shipped (actual money in) vs plan · ${mp.source ? 'SHIPPINGREPORT' : ''} · later months = forecast</span></div>
        <div class="kpi-grid" style="margin:0">
          <div class="kpi"><div class="kpi-label">YTD shipped</div><div class="kpi-value">${fmtMoney(mp.ytdShippedUsd || 0)}</div><div class="kpi-delta flat">money in through ${mp.months[(mp.currentMonth||1)-1] ? mp.months[(mp.currentMonth||1)-1].label : ''}</div></div>
          <div class="kpi"><div class="kpi-label">YTD vs plan</div><div class="kpi-value" style="color:${attColor(mp.ytdAttainmentPct)}">${mp.ytdAttainmentPct != null ? mp.ytdAttainmentPct + '%' : '—'}</div><div class="kpi-delta flat">${fmtMoney(mp.ytdShippedUsd||0)} / ${fmtMoney(mp.ytdPlannedUsd||0)} planned</div></div>
          <div class="kpi"><div class="kpi-label">Full-year outlook</div><div class="kpi-value">${fmtMoney(mp.months.reduce((s,m)=>s+((m.status==='forecast')?(m.forecastUsd||0):(m.shippedUsd||0)),0))}</div><div class="kpi-delta flat">actual to date + forecast</div></div>
        </div>
        <div style="overflow-x:auto;padding:4px 18px 8px"><table>
          <thead><tr><th>Month</th><th style="text-align:right">Shipped (actual)</th><th style="text-align:right">Plan</th><th style="width:34%">vs plan</th><th style="text-align:right">Attainment</th></tr></thead>
          <tbody>${mp.months.map(m => {
            const isFc = m.status === 'forecast';
            const shownShip = isFc ? (m.forecastUsd || 0) : (m.shippedUsd || 0);
            return `<tr${m.status==='current'?' style="background:#eff6ff"':''}>
              <td><strong>${escapeHtml(m.label)}</strong>${m.status==='current'?' <span style="font-size:10px;background:#0a3d62;color:#fff;padding:1px 6px;border-radius:8px">in progress</span>':isFc?' <span style="font-size:10px;color:#b45309">forecast</span>':''}</td>
              <td style="text-align:right;${isFc?'color:#b45309':'font-weight:600'}">${fmtMoney(shownShip)}</td>
              <td style="text-align:right;color:var(--ink-dim)">${isFc?'—':fmtMoney(m.plannedUsd||0)}</td>
              <td>${isFc ? `<div style="display:flex;align-items:center;gap:6px">${bar(m.forecastUsd||0,'#fcd9b6')}</div>` : `<div style="display:flex;flex-direction:column;gap:2px">${bar(m.shippedUsd||0,'#0a3d62')}${bar(m.plannedUsd||0,'#cbd5e1')}</div>`}</td>
              <td style="text-align:right;font-weight:700;color:${isFc?'var(--ink-dim)':attColor(m.attainmentPct)}">${isFc?'—':(m.attainmentPct!=null?m.attainmentPct+'%':'—')}</td></tr>`;
          }).join('')}</tbody>
        </table></div>
        <p style="padding:4px 18px 12px;font-size:11px;color:var(--ink-dim)">Dark bar = shipped (actual money in, from SHIPPINGREPORT); grey bar = plan that month. ${escapeHtml(mp.note||'')}</p>
      </div>`;
    })()}

    ${(() => {
      // Revenue pace — is business up or down? Numbers only, no charts.
      const wr = MOCK.shipping.weeklyRevenue || {}; const all = wr.weeks || [];
      if (all.length < 3) return '';
      // "Last full week" must be a COMPLETED week — the week containing today is
      // flagged partial by the builder (belt + suspenders: also exclude this Monday on).
      const _monNow = (() => { const t = new Date(); t.setDate(t.getDate() - ((t.getDay() + 6) % 7)); return t.toISOString().slice(0, 10); })();
      const done = all.filter(w => !w.partial && w.week < _monNow);
      const inProg = all.find(w => w.partial || w.week >= _monNow);
      const avg = Math.round(wr.avgUsd || 0);
      const last = done[done.length - 1] || {};
      const vsAvg = avg > 0 ? Math.round(((last.usd || 0) - avg) / avg * 100) : 0;
      const best = done.reduce((m, w) => (w.usd || 0) > (m.usd || 0) ? w : m, done[0] || {});
      const total = Math.round(all.reduce((s, w) => s + (w.usd || 0), 0));
      const wkLbl = (iso) => new Date(iso + 'T00:00:00').toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      const recent = done.slice(-3);
      return `<div class="panel" style="cursor:pointer" onclick="navigate('asaStock')">
        <div class="panel-head"><h2>Revenue pace — $ shipped per week</h2><span class="panel-meta">week-by-week detail in $STA →</span></div>
        <div class="kpi-grid" style="margin:0">
          <div class="kpi"><div class="kpi-label">Last full week</div><div class="kpi-value">${fmtMoney(Math.round(last.usd || 0))}</div><div class="kpi-delta flat">wk of ${wkLbl(last.week)}</div></div>
          <div class="kpi"><div class="kpi-label">vs our average</div><div class="kpi-value" style="color:${vsAvg >= 0 ? '#16a34a' : '#b91c1c'}">${vsAvg >= 0 ? '+' : ''}${vsAvg}%</div><div class="kpi-delta flat">average ${fmtMoney(avg)}/wk</div></div>
          <div class="kpi"><div class="kpi-label">Best week this year</div><div class="kpi-value">${fmtMoney(Math.round(best.usd || 0))}</div><div class="kpi-delta flat">wk of ${wkLbl(best.week)}</div></div>
          <div class="kpi"><div class="kpi-label">Shipped this year</div><div class="kpi-value">${fmtMoney(total)}</div><div class="kpi-delta flat">${all.length} weeks</div></div>
        </div>
        <p style="padding:6px 18px 4px;font-size:13px;color:var(--ink-dim)">Recent weeks: ${recent.map(w => `<strong style="color:#14142b">${wkLbl(w.week)}</strong> ${fmtMoney(Math.round(w.usd || 0))}`).join(' &nbsp;·&nbsp; ')}</p>
        ${(() => {
          const ar2 = (MOCK.sales.arOpenInvoicesSource || []).filter(x => (x.open || 0) > 0);
          if (!ar2.length) return '';
          const d7 = Math.round(ar2.filter(x => (x.daysPast || 0) <= 0 && (x.daysPast || 0) >= -7).reduce((s, x) => s + x.open, 0));
          const d30 = Math.round(ar2.filter(x => (x.daysPast || 0) < -7 && (x.daysPast || 0) >= -30).reduce((s, x) => s + x.open, 0));
          const odd = Math.round(ar2.filter(x => (x.daysPast || 0) > 0).reduce((s, x) => s + x.open, 0));
          const discNote = (MOCK.finance.discounts||[]).map(x => `<strong style="color:#b45309">${escapeHtml(x.customer)} pays net of ${x.pct}%</strong> — its money in is shown discounted`).join(' · ');
          return `<p style="padding:0 18px 12px;font-size:13px;color:var(--ink-dim)">Cash landing: <strong style="color:#16a34a">${fmtMoney(d7)}</strong> due in 7 days &nbsp;·&nbsp; <strong style="color:#14142b">${fmtMoney(d30)}</strong> due in 8–30 days &nbsp;·&nbsp; <strong style="color:#b91c1c">${fmtMoney(odd)} overdue</strong> — collect it${discNote ? '<br>' + discNote : ''}</p>`;
        })()}
      </div>`;
    })()}

    ${secHead('📦','Pipeline','orders on the books · what’s coming · who actually delivers')}

    ${pipelinePanel()}

    ${salesPipelinePanel()}

    ${custReliabilityPanel()}

    ${secHead('🏗️','Inventory building up','produced but not shipped — cash waiting in the warehouse')}

    ${(() => {
      const pvs = MOCK.production.producedVsShipped || {};
      const prodU = pvs.totalProduced || 0, shipU = pvs.totalShipped || 0, net = prodU - shipU;
      if (!prodU) return '';
      const pile = (pvs.byProduct || []).filter(r => (r.gap || 0) > 0).sort((a, b) => b.gap - a.gap);
      const pileSum = pile.reduce((s, r) => s + r.gap, 0);
      return `<div class="panel" style="cursor:pointer" onclick="navigate('invAccum')">
        <div class="panel-head"><h2>Produced but not shipped</h2><span class="panel-meta">cash sitting in the warehouse · full breakdown →</span></div>
        <div class="kpi-grid" style="margin:0">
          <div class="kpi"><div class="kpi-label">In the warehouse</div><div class="kpi-value" style="color:${net > 0 ? '#b45309' : '#16a34a'}">${net >= 0 ? '+' : ''}${fmtNum(net)}</div><div class="kpi-delta flat">units, produced − shipped</div></div>
          <div class="kpi"><div class="kpi-label">Produced this year</div><div class="kpi-value">${fmtNum(prodU)}</div><div class="kpi-delta flat">units sewn</div></div>
          <div class="kpi"><div class="kpi-label">Shipped this year</div><div class="kpi-value">${fmtNum(shipU)}</div><div class="kpi-delta flat">units out the door</div></div>
          <div class="kpi"><div class="kpi-label">Piling up</div><div class="kpi-value" style="color:#b45309">${fmtNum(pileSum)}</div><div class="kpi-delta flat">${pile.length} products building</div></div>
        </div>
        ${pile.length ? `<p style="padding:6px 18px 12px;font-size:13px;color:var(--ink-dim)">Biggest piles: ${pile.slice(0, 3).map(r => `<strong style="color:#14142b">${escapeHtml(r.product)}</strong> ${fmtNum(r.gap)}`).join(' &nbsp;·&nbsp; ')}</p>` : ''}
      </div>`;
    })()}

    ${secHead('🧵','Raw materials on hand','fabric, trims & supplies we hold — by customer, in dollars')}

    ${(() => {
      const pm = MOCK.production && MOCK.production.polypm;
      if (!pm || !Array.isArray(pm.byCustomer) || !pm.byCustomer.length) return '';
      const rows = pm.byCustomer.filter(r => (r.cost || 0) > 0);
      const total = pm.totalOnHandCost || rows.reduce((s, r) => s + (r.cost || 0), 0);
      const flags = pm.dataQualityFlags || [];
      return `<div class="panel">
        <div class="panel-head"><h2>Raw materials we're holding — by customer ($)</h2><span class="panel-meta">${fmtMoney(total)} on hand · who paid: <strong style="color:#0a3d62">STA ${fmtMoney(pm.asaOwnedCost||0)}</strong> · customer ${fmtMoney(pm.customerOwnedCost||0)}</span></div>
        <div class="kpi-grid" style="margin:0">
          <div class="kpi"><div class="kpi-label">Materials on hand ($)</div><div class="kpi-value">${fmtMoney(total)}</div><div class="kpi-delta flat">value sitting in the warehouse now</div></div>
          <div class="kpi" style="border-left:3px solid #0a3d62"><div class="kpi-label">STA paid for</div><div class="kpi-value">${fmtMoney(pm.asaOwnedCost||0)}</div><div class="kpi-delta flat">our capital · trims, supplies, Falcon + $150k Tsunami fabric</div></div>
          <div class="kpi"><div class="kpi-label">Customer paid for</div><div class="kpi-value">${fmtMoney(pm.customerOwnedCost||0)}</div><div class="kpi-delta flat">their fabric (incl. prepaid NW)</div></div>
          <div class="kpi"><div class="kpi-label">% used up</div><div class="kpi-value">${pm.totalStartedWith?Math.round((pm.totalAllocated/pm.totalStartedWith)*100):0}%</div><div class="kpi-delta flat">${fmtNum(pm.totalAllocated||0)} of ${fmtNum(pm.totalStartedWith||0)} started · allocated to orders</div></div>
        </div>
        <div style="overflow-x:auto"><table>
          <thead><tr><th>Customer</th><th style="text-align:right">$ on hand</th><th style="text-align:right">Who paid (STA / cust)</th><th>What it is</th><th style="text-align:right">Started → % used</th></tr></thead>
          <tbody>${rows.map(r => `<tr>
            <td><strong>${escapeHtml(r.customer)}</strong></td>
            <td style="text-align:right;font-weight:700;color:#0a3d62">${fmtMoney(r.cost || 0)}</td>
            <td style="text-align:right;font-size:12px">${fmtMoney(r.asaCost||0)} <span style="color:var(--ink-dim)">/ ${fmtMoney(r.customerCost||0)}</span></td>
            <td style="font-size:12px">${(r.byCategory || []).slice(0, 3).map(c => `${escapeHtml(c.category)} <strong>${fmtMoney(c.cost)}</strong>`).join(' &nbsp;·&nbsp; ') || escapeHtml(r.whatItIs || '')}</td>
            <td style="text-align:right;font-size:12px">${fmtNum(r.startedWith||0)} → <strong style="color:${(r.consumedPct||0)>=70?'#b45309':'#14142b'}">${r.consumedPct||0}%</strong></td></tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td style="text-align:right">${fmtMoney(total)}</td><td style="text-align:right;font-size:12px">${fmtMoney(pm.asaOwnedCost||0)} / ${fmtMoney(pm.customerOwnedCost||0)}</td><td></td><td style="text-align:right">${fmtNum(pm.totalStartedWith||0)} → ${pm.totalStartedWith?Math.round((pm.totalAllocated/pm.totalStartedWith)*100):0}%</td></tr>
          </tbody></table></div>
        <p style="padding:8px 18px 4px;font-size:11px;color:var(--ink-dim)"><strong>On hand</strong> = units/yards physically in the warehouse now. <strong>Started → % used</strong> = on hand + allocated, and what share has been allocated to production orders. <strong>Who paid:</strong> ${escapeHtml(pm.ownershipNote||'')}</p>
        ${flags.length ? `<p style="padding:0 18px 12px;font-size:11px;color:#b45309">⚠ ${flags.length} material cost${flags.length>1?'s were':' was'} corrected down for a bad cost cell (biggest: ${escapeHtml(flags[0].customer)} ${escapeHtml(flags[0].material)} ${fmtMoney(flags[0].statedCost)}→${fmtMoney(flags[0].correctedCost)}). This is why "National Sports" is now ~${fmtMoney((rows.find(r=>/official/i.test(r.customer))||{}).cost||0)}, not ~$337k.</p>` : ''}
      </div>`;
    })()}

    ${secHead('💵','Who owes us','open A/R by customer · who to call')}

    <!-- What each customer owes us — open A/R by customer -->
    ${(() => {
      const ar = (MOCK.sales.receivableSummary || []).slice().sort((a,b)=>(b.open||0)-(a.open||0));
      if (!ar.length) return '';
      const tag = (s) => s==='good' ? '<span class="tag tag-good">good</span>' : s==='warn' ? '<span class="tag tag-warn">watch</span>' : '<span class="tag tag-bad">overdue</span>';
      return `
      <div class="panel">
        <div class="panel-head"><h2>What each customer owes us</h2><span class="panel-meta">open A/R · ${fmtMoney(totalReceivables)} across ${ar.length} customers · <a href="#" onclick="navigate('collections');return false;">when it lands →</a></span></div>
        <table>
          <thead><tr><th>Customer</th><th style="text-align:right">Open A/R</th><th style="text-align:right">Current</th><th style="text-align:right">Past due (31+)</th><th>Status</th></tr></thead>
          <tbody>${ar.map(r => { const pd = (r.dpd60||0)+(r.dpd90||0);
            const disc = (MOCK.finance.discounts||[]).find(x => String(r.customer||'').toLowerCase().startsWith(String(x.customer||'').toLowerCase()));
            return `<tr>
            <td><strong>${escapeHtml(r.customer)}</strong>${disc ? ` <span class="tag tag-warn">-${disc.pct}%</span>` : ''}</td>
            <td style="text-align:right"><strong>${fmtMoney(r.open||0)}</strong>${disc ? `<div style="font-size:11px;color:#b45309">≈ ${fmtMoney((r.open||0)*(1-disc.pct/100))} expected net of ${disc.pct}%</div>` : ''}</td>
            <td style="text-align:right">${fmtMoney(r.current||0)}</td>
            <td style="text-align:right;color:${pd>0?'#b91c1c':'var(--ink-dim)'}">${fmtMoney(pd)}</td>
            <td>${tag(r.status)}</td></tr>`; }).join('')}
          <tr style="background:#f8fafc;font-weight:700"><td>TOTAL</td><td style="text-align:right">${fmtMoney(totalReceivables)}</td><td></td><td></td><td></td></tr>
          </tbody>
        </table>
      </div>`;
    })()}

    ${secHead('⭐','NW analytics','the prepaid program at a glance · click for full detail')}

    ${uaSnapshotPanel()}

    ${secHead('🚚','This week on the floor','shipped vs plan by customer · what still has to go out')}

    ${(() => {
      // Production by customer — FRESH sources: this/last week (fix_current_week)
      // + open orders (the old remainingByCustomer / aiCoaching paths were stale → zeros).
      const cw = MOCK.shipping.currentWeek || {}, lw = MOCK.shipping.lastWeek || {};
      const oo = MOCK.production.openOrdersByCustomer || [];
      const norm = (s) => String(s||'').toLowerCase().replace(/[^a-z0-9]/g,'');
      const map = {};
      const get = (c) => (map[norm(c)] = map[norm(c)] || { customer: c, planThis: 0, shipThis: 0, shipLast: 0, open: 0 });
      (cw.byCustomer||[]).forEach(r => { const g = get(r.customer); g.planThis += r.unitsPlanned||0; g.shipThis += r.unitsShipped||0; });
      (lw.byCustomer||[]).forEach(r => { const g = get(r.customer); g.shipLast += r.unitsShipped||0; });
      oo.forEach(r => { const g = get(r.customer); g.open += r.units||0; });
      const rows = Object.values(map).filter(g => g.planThis||g.shipThis||g.shipLast||g.open).sort((a,b)=>b.open-a.open);
      if (!rows.length) return '';
      const tot = rows.reduce((a,g)=>({planThis:a.planThis+g.planThis, shipThis:a.shipThis+g.shipThis, shipLast:a.shipLast+g.shipLast, open:a.open+g.open}), {planThis:0,shipThis:0,shipLast:0,open:0});
      return `
      <div class="panel">
        <div class="panel-head"><h2>Production by customer</h2><span class="panel-meta">this week (Mon ${escapeHtml((cw.weekStart||'').slice(5))} → today) vs plan, last week's shipped, and open order units still to ship</span></div>
        <table>
          <thead><tr><th>Customer</th><th>Planned this wk</th><th>Shipped this wk</th><th>Shipped last wk</th><th>Open to ship</th><th>% this wk</th></tr></thead>
          <tbody>${rows.map(g => {
            const p = g.planThis > 0 ? Math.round((g.shipThis/g.planThis)*100) : null;
            return `<tr>
              <td><strong>${escapeHtml(g.customer)}</strong></td>
              <td>${fmtNum(g.planThis)}</td>
              <td><strong>${fmtNum(g.shipThis)}</strong></td>
              <td style="color:var(--ink-dim)">${fmtNum(g.shipLast)}</td>
              <td><strong style="color:${g.open>0?'#b45309':'#16a34a'}">${fmtNum(g.open)}</strong></td>
              <td>${fmtP(p)}</td>
            </tr>`;
          }).join('')}
          <tr style="background:#f8fafc;font-weight:700">
            <td>TOTAL</td>
            <td>${fmtNum(tot.planThis)}</td>
            <td>${fmtNum(tot.shipThis)}</td>
            <td style="color:var(--ink-dim)">${fmtNum(tot.shipLast)}</td>
            <td style="color:${tot.open>0?'#b45309':'#16a34a'}">${fmtNum(tot.open)}</td>
            <td>${fmtP(tot.planThis>0?Math.round(tot.shipThis/tot.planThis*100):null)}</td>
          </tr>
          </tbody>
        </table>
      </div>`;
    })()}

    ${secHead('🏭','Production & warehouse','what’s on the lines · who drives the revenue')}

    ${productionLinesPanel()}

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h2>Top customers by revenue (YTD 2026)</h2><span class="panel-meta">SHIPPINGREPORT actuals</span></div>
        <table>
          <thead><tr><th>#</th><th>Customer</th><th>Units shipped</th><th>Revenue</th></tr></thead>
          <tbody>${topByRev.length === 0 ? emptyRow(4) : topByRev.map((r,i)=>`<tr>
            <td style="color:var(--ink-dim);font-weight:700">#${i+1}</td>
            <td><strong>${escapeHtml(r.customer||'')}</strong></td>
            <td>${fmtNum(r.shipped||0)}</td>
            <td><strong>${fmtMoney(r.revenue||0)}</strong></td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Top customers by volume (units YTD)</h2><span class="panel-meta">SHIPPINGREPORT actuals</span></div>
        <table>
          <thead><tr><th>#</th><th>Customer</th><th>Units</th><th>Revenue</th></tr></thead>
          <tbody>${topByUnits.length === 0 ? emptyRow(4) : topByUnits.map((r,i)=>`<tr>
            <td style="color:var(--ink-dim);font-weight:700">#${i+1}</td>
            <td><strong>${escapeHtml(r.customer||'')}</strong></td>
            <td><strong>${fmtNum(r.shipped||0)}</strong></td>
            <td>${fmtMoney(r.revenue||0)}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
    </div>


    ${(() => {
      // Daily tracking — grouped by customer; within each group sort by most-overdue first
      const byCust = {};
      dailyOrders.forEach(w => { (byCust[w.customer||'Unknown'] = byCust[w.customer||'Unknown'] || []).push(w); });
      // Sort groups: customers with any late program first, then by total units
      const groups = Object.entries(byCust).map(([c, rows]) => {
        rows.sort((a,b) => {
          const aD = a.reqDate && a.reqDate!=='—' ? (today - new Date(a.reqDate))/86400000 : -9999;
          const bD = b.reqDate && b.reqDate!=='—' ? (today - new Date(b.reqDate))/86400000 : -9999;
          return bD - aD;
        });
        const units = rows.reduce((s,r)=>s+(r.promised||0),0);
        const lateCount = rows.filter(r => {
          if (!r.reqDate || r.reqDate==='—') return false;
          const d = new Date(r.reqDate); if (isNaN(d)) return false;
          return (today - d) / 86400000 > 0;
        }).length;
        return { customer:c, rows, units, lateCount };
      }).sort((a,b) => (b.lateCount - a.lateCount) || (b.units - a.units));
      return `
      <div class="panel">
        <div class="panel-head"><h2>Daily tracking — all open programs (grouped by customer)</h2><span class="panel-meta">${dailyOrders.length} program${dailyOrders.length===1?'':'s'} across ${groups.length} customer${groups.length===1?'':'s'} · groups ranked by late count then volume</span></div>
        <div style="overflow-x:auto;max-height:680px;overflow-y:auto">
          <table>
            <thead><tr><th>Customer / Program</th><th>Units</th><th>Original ship date</th><th>Current status</th><th>Delay / Remain</th></tr></thead>
            <tbody>${groups.length === 0 ? emptyRow(5) : groups.map(g => `
              <tr style="background:#0a3d62">
                <td style="background:#0a3d62;padding:8px 12px"><span style="color:#fff;font-weight:700">${escapeHtml(g.customer)}</span> <span style="font-size:11px;color:#fff;opacity:.8;font-weight:500">(${g.rows.length} program${g.rows.length===1?'':'s'} · ${fmtNum(g.units)} units${g.lateCount?' · '+g.lateCount+' late':''})</span></td>
                <td style="background:#0a3d62;color:#fff;font-weight:700"><strong>${fmtNum(g.units)}</strong></td>
                <td style="background:#0a3d62"></td>
                <td style="background:#0a3d62"></td>
                <td style="background:#0a3d62"></td>
              </tr>
              ${g.rows.map(w => {
                let delay=null;
                if (w.reqDate && w.reqDate!=='—') {
                  const d=new Date(w.reqDate); if(!isNaN(d)) delay=Math.round((today-d)/86400000);
                }
                const delayCell = delay==null ? '<span style="color:var(--ink-dim)">—</span>' : delay>0 ? `<span class="tag tag-bad">${delay}d late</span>` : delay===0 ? `<span class="tag tag-warn">due today</span>` : `<span style="color:var(--ink-dim);font-size:12px">${-delay}d remain</span>`;
                return `<tr>
                  <td style="padding-left:28px"><span style="color:var(--ink-dim)">↳</span> ${escapeHtml(w.program||'')}</td>
                  <td>${fmtNum(w.promised||0)}</td>
                  <td style="font-size:11px">${escapeHtml(w.reqDate||'—')}</td>
                  <td><span class="tag tag-${w.status||'good'}">${w.status==='good'?'On track':w.status==='warn'?'Watch':'At risk'}</span></td>
                  <td>${delayCell}</td>
                </tr>`;
              }).join('')}
            `).join('')}</tbody>
          </table>
        </div>
      </div>`;
    })()}
  `;
}

function renderForecastVsActual(root) {
  const fva = (MOCK.production && MOCK.production.forecastVsActual) || {};
  const months = fva.months || [];
  const byCust = fva.byCustomer || {};
  const ytdByCust = fva.ytdByCustomer || {};
  const customers = Object.keys(byCust);
  if (customers.length === 0) {
    root.innerHTML = `<div class="page-head"><div><p class="eyebrow">Tracker</p><h1>Forecast vs Actual</h1><p>Awaiting FORECAST_VS_ACTUAL.xlsx and WIP.xlsx uploads.</p></div></div>`;
    return;
  }
  // Two independent selections: YTD card customer + matrix customer
  if (typeof window.__fvaYtdCust === 'undefined' || !byCust[window.__fvaYtdCust]) window.__fvaYtdCust = 'All';
  if (typeof window.__fvaMatCust === 'undefined' || !byCust[window.__fvaMatCust]) window.__fvaMatCust = 'All';
  const ytdCust = window.__fvaYtdCust;
  const matCust = window.__fvaMatCust;
  const ytd = ytdByCust[ytdCust] || {};
  const mat = byCust[matCust] || {};
  const tagFor = (p) => p == null ? '<span style="color:var(--ink-dim)">—</span>' : p >= 95 ? `<span class="tag tag-good">${p}%</span>` : p >= 80 ? `<span class="tag tag-warn">${p}%</span>` : `<span class="tag tag-bad">${p}%</span>`;
  const colorFor = (p) => p == null ? 'var(--ink-dim)' : p >= 95 ? '#16a34a' : p >= 80 ? '#b45309' : '#b91c1c';
  const custOpts = (selected) => customers.map(c => `<option value="${escapeHtml(c)}"${c===selected?' selected':''}>${escapeHtml(c)}</option>`).join('');

  const fU = mat.forecastUnits || [], aU = mat.actualUnits || [];
  const fD = mat.forecastUSD || [], aD = mat.actualUSD || [];
  const matRows = months.map((m, i) => {
    const pu = fU[i] ? Math.round((aU[i] / fU[i]) * 100) : null;
    const pd = fD[i] ? Math.round((aD[i] / fD[i]) * 100) : null;
    return { m, fU: fU[i] || 0, aU: aU[i] || 0, pu, fD: fD[i] || 0, aD: aD[i] || 0, pd };
  });
  const matTotF = matRows.reduce((s,r)=>s+r.fU,0);
  const matTotA = matRows.reduce((s,r)=>s+r.aU,0);
  const matTotFD = matRows.reduce((s,r)=>s+r.fD,0);
  const matTotAD = matRows.reduce((s,r)=>s+r.aD,0);
  const matPctU = matTotF ? Math.round(matTotA/matTotF*100) : null;
  const matPctD = matTotFD ? Math.round(matTotAD/matTotFD*100) : null;

  // 13-week weekly view (from SHIPPINGREPORT planned vs actual)
  const wk = (MOCK.shipping && MOCK.shipping.fvaWeekly13) || null;
  if (typeof window.__fvaWkCust === 'undefined') window.__fvaWkCust = 'All';
  const wkCustomers = wk && wk.byCustomer ? Object.keys(wk.byCustomer).sort((a,b)=>a==='All'?-1:b==='All'?1:a.localeCompare(b)) : [];
  if (wk && !wk.byCustomer[window.__fvaWkCust]) window.__fvaWkCust = 'All';
  const wkSel = wk ? wk.byCustomer[window.__fvaWkCust] : null;
  const wkLabels = wk ? wk.weeks : [];
  const wkFU = wkSel ? wkSel.forecastUnits : [];
  const wkAU = wkSel ? wkSel.actualUnits : [];
  const wkFD = wkSel ? wkSel.forecastUSD : [];
  const wkAD = wkSel ? wkSel.actualUSD : [];
  const wkAttU = wkLabels.map((_,i) => (wkFU[i]||0)>0 ? Math.round((wkAU[i]||0)/wkFU[i]*100) : null);
  const wkAttD = wkLabels.map((_,i) => (wkFD[i]||0)>0 ? Math.round((wkAD[i]||0)/wkFD[i]*100) : null);
  const wkTotFU = wkFU.reduce((s,x)=>s+(x||0),0);
  const wkTotAU = wkAU.reduce((s,x)=>s+(x||0),0);
  const wkTotFD = wkFD.reduce((s,x)=>s+(x||0),0);
  const wkTotAD = wkAD.reduce((s,x)=>s+(x||0),0);
  const wkTotPctU = wkTotFU ? Math.round(wkTotAU/wkTotFU*100) : null;
  const wkTotPctD = wkTotFD ? Math.round(wkTotAD/wkTotFD*100) : null;
  const wkCustOpts = wkCustomers.map(c => `<option value="${escapeHtml(c)}"${c===window.__fvaWkCust?' selected':''}>${escapeHtml(c)}</option>`).join('');

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Tracker</p>
        <h1>Forecast vs Actual</h1>
        <p style="font-size:14px;line-height:1.55">
          <strong>What this page is:</strong> at the start of the year your sales team built a weekly + monthly forecast for how many units (and US$) each customer would ship. Every week, the SHIPPINGREPORT records what actually shipped. This page is the scoreboard.
        </p>
        <p style="font-size:13px;line-height:1.55;color:var(--ink-dim);margin-top:6px">
          <strong style="color:#16a34a">Green ≥ 95%</strong> = you hit or beat the forecast that period · <strong style="color:#b45309">Amber 80-94%</strong> = soft · <strong style="color:#b91c1c">Red &lt; 80%</strong> = forecast missed. Use the customer dropdown to drill in.
        </p>
      </div>
    </div>

    ${custReliabilityPanel()}

    ${(() => {
      // YTD plain-English summary so the owner gets the story at a glance
      const ytd = ytdByCust['All'] || {};
      const u = ytd.actualUnits, f = ytd.forecastUnits;
      const $u = ytd.actualUSD, $f = ytd.forecastUSD;
      const pctU = f ? Math.round(u/f*100) : null;
      const pct$ = $f ? Math.round($u/$f*100) : null;
      const verdict = pctU == null ? 'Awaiting data.'
        : pctU >= 100 ? `Ahead of plan by ${(pctU-100)}%`
        : pctU >= 95  ? `On plan (-${(100-pctU)}%)`
        : pctU >= 80  ? `Behind plan by ${100-pctU}%`
        : `Significantly behind plan by ${100-pctU}%`;
      const color = pctU == null ? 'var(--ink-dim)' : pctU >= 95 ? '#16a34a' : pctU >= 80 ? '#b45309' : '#b91c1c';
      return `
      <div class="panel" style="background:linear-gradient(135deg,#0a3d62 0%,#1c5b8a 100%);color:#fff;padding:24px;margin-bottom:18px">
        <p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;margin:0 0 4px;opacity:.85">YTD Scoreboard · Total Business</p>
        <div style="display:flex;gap:32px;flex-wrap:wrap;margin-top:8px">
          <div><div style="font-size:11px;opacity:.7;text-transform:uppercase;letter-spacing:1px">Units forecast</div><div style="font-size:24px;font-weight:800">${fmtNum(f||0)}</div></div>
          <div><div style="font-size:11px;opacity:.7;text-transform:uppercase;letter-spacing:1px">Units actual</div><div style="font-size:24px;font-weight:800">${fmtNum(u||0)}</div></div>
          <div><div style="font-size:11px;opacity:.7;text-transform:uppercase;letter-spacing:1px">% attainment</div><div style="font-size:32px;font-weight:800;color:${pctU>=95?'#86efac':pctU>=80?'#fde68a':'#fca5a5'}">${pctU!=null?pctU+'%':'—'}</div></div>
          <div><div style="font-size:11px;opacity:.7;text-transform:uppercase;letter-spacing:1px">Verdict</div><div style="font-size:18px;font-weight:700;margin-top:4px">${escapeHtml(verdict)}</div></div>
        </div>
        <p style="font-size:13px;opacity:.85;margin:14px 0 0;line-height:1.5">
          Translation: through this point in the year, the plan said you would ship <strong>${fmtNum(f||0)}</strong> units worth <strong>${fmtMoney($f||0)}</strong>. You actually shipped <strong>${fmtNum(u||0)}</strong> units worth <strong>${fmtMoney($u||0)}</strong>. ${pctU != null && pctU < 95 ? `That's <strong>${fmtNum((f||0) - (u||0))}</strong> units (<strong>${fmtMoney(($f||0)-($u||0))}</strong>) behind the plan. The gap needs to close in the second half of the year, or the plan needs to be re-forecasted.` : pctU != null && pctU >= 100 ? 'You are ahead of plan — protect this with capacity discipline so the back half doesn\'t slip.' : ''}
        </p>
      </div>`;
    })()}

    ${wk ? `
    <div class="panel" style="border-top:4px solid #0a3d62">
      <div class="panel-head">
        <h2>13-week weekly — forecast vs actual</h2>
        <span class="panel-meta">
          <label style="display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--ink-dim)">Customer
            <select id="fvaWkSel" style="padding:6px 8px;border:1px solid var(--line);border-radius:6px">${wkCustOpts}</select>
          </label>
        </span>
      </div>
      <div class="grid-2" style="padding:0">
        <div style="padding:20px;text-align:center;border-right:1px solid var(--line)">
          <div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">13-wk Att — Units</div>
          <div style="font-size:48px;font-weight:800;color:${colorFor(wkTotPctU)};line-height:1.1;margin-top:6px">${wkTotPctU != null ? wkTotPctU + '%' : '—'}</div>
          <div style="font-size:12px;color:var(--ink-dim);margin-top:4px">${fmtNum(wkTotAU)} actual / ${fmtNum(wkTotFU)} planned</div>
        </div>
        <div style="padding:20px;text-align:center">
          <div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">13-wk Att — US$</div>
          <div style="font-size:48px;font-weight:800;color:${colorFor(wkTotPctD)};line-height:1.1;margin-top:6px">${wkTotPctD != null ? wkTotPctD + '%' : '—'}</div>
          <div style="font-size:12px;color:var(--ink-dim);margin-top:4px">${fmtMoney(wkTotAD)} actual / ${fmtMoney(wkTotFD)} planned</div>
        </div>
      </div>
      <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th rowspan="2">Week ending</th>
            <th colspan="3" style="text-align:center;border-bottom:1px solid var(--line)">Units</th>
            <th colspan="3" style="text-align:center;border-bottom:1px solid var(--line)">US$</th>
          </tr>
          <tr>
            <th>Planned</th><th>Actual</th><th>Att %</th>
            <th>Planned</th><th>Actual</th><th>Att %</th>
          </tr>
        </thead>
        <tbody>${wkLabels.map((lbl,i)=>{
          const dash = '<span style="color:var(--ink-dim)">—</span>';
          return `
          <tr>
            <td><strong>${escapeHtml(lbl)}</strong></td>
            <td>${fmtNum(wkFU[i]||0)}</td>
            <td>${wkAU[i]==null?dash:fmtNum(wkAU[i])}</td>
            <td>${tagFor(wkAttU[i])}</td>
            <td>${fmtMoney(wkFD[i]||0)}</td>
            <td>${wkAD[i]==null?dash:fmtMoney(wkAD[i])}</td>
            <td>${tagFor(wkAttD[i])}</td>
          </tr>`;
        }).join('')}
          <tr style="background:#f8fafc;font-weight:700">
            <td>Total (13 wk)</td>
            <td>${fmtNum(wkTotFU)}</td>
            <td>${fmtNum(wkTotAU)}</td>
            <td>${tagFor(wkTotPctU)}</td>
            <td>${fmtMoney(wkTotFD)}</td>
            <td>${fmtMoney(wkTotAD)}</td>
            <td>${tagFor(wkTotPctD)}</td>
          </tr>
        </tbody>
      </table>
      </div>
      <div class="chart-wrap tall"><canvas id="fvaWkChart"></canvas></div>
      <p style="font-size:11px;color:var(--ink-dim);margin:8px 0 0">Source: ${escapeHtml((wk.source||'').split('/').pop())}. ${escapeHtml(wk.note||'')}</p>
    </div>` : ''}

    <div class="panel">
      <div class="panel-head">
        <h2>YTD Forecast Attainment</h2>
        <span class="panel-meta">
          <label style="display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--ink-dim)">Customer
            <select id="fvaYtdSel" style="padding:6px 8px;border:1px solid var(--line);border-radius:6px">${custOpts(ytdCust)}</select>
          </label>
        </span>
      </div>
      <div class="grid-2" style="padding:0">
        <div style="padding:24px;text-align:center;border-right:1px solid var(--line)">
          <div style="font-size:12px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">% Forecast Att YTD — Units</div>
          <div style="font-size:64px;font-weight:800;color:${colorFor(ytd.attUnits)};line-height:1.1;margin-top:8px">${ytd.attUnits != null ? ytd.attUnits + '%' : '—'}</div>
          <div style="font-size:13px;color:var(--ink-dim);margin-top:6px">${fmtNum(ytd.actualUnits || 0)} actual / ${fmtNum(ytd.forecastUnits || 0)} forecast</div>
        </div>
        <div style="padding:24px;text-align:center">
          <div style="font-size:12px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">% Forecast Att YTD — US$</div>
          <div style="font-size:64px;font-weight:800;color:${colorFor(ytd.attUSD)};line-height:1.1;margin-top:8px">${ytd.attUSD != null ? ytd.attUSD + '%' : '—'}</div>
          <div style="font-size:13px;color:var(--ink-dim);margin-top:6px">${fmtMoney(ytd.actualUSD || 0)} actual / ${fmtMoney(ytd.forecastUSD || 0)} forecast</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <h2>Monthly forecast vs actual</h2>
        <span class="panel-meta">
          <label style="display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--ink-dim)">Customer
            <select id="fvaMatSel" style="padding:6px 8px;border:1px solid var(--line);border-radius:6px">${custOpts(matCust)}</select>
          </label>
        </span>
      </div>
      <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th rowspan="2">Month</th>
            <th colspan="3" style="text-align:center;border-bottom:1px solid var(--line)">Units</th>
            <th colspan="3" style="text-align:center;border-bottom:1px solid var(--line)">US$</th>
          </tr>
          <tr>
            <th>Forecast</th><th>Actual</th><th>Att %</th>
            <th>Forecast</th><th>Actual</th><th>Att %</th>
          </tr>
        </thead>
        <tbody>${matRows.map(r => `
          <tr>
            <td><strong>${escapeHtml(r.m)}</strong></td>
            <td>${fmtNum(r.fU)}</td>
            <td>${fmtNum(r.aU)}</td>
            <td>${tagFor(r.pu)}</td>
            <td>${fmtMoney(r.fD)}</td>
            <td>${fmtMoney(r.aD)}</td>
            <td>${tagFor(r.pd)}</td>
          </tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:700">
            <td>Total</td>
            <td>${fmtNum(matTotF)}</td>
            <td>${fmtNum(matTotA)}</td>
            <td>${tagFor(matPctU)}</td>
            <td>${fmtMoney(matTotFD)}</td>
            <td>${fmtMoney(matTotAD)}</td>
            <td>${tagFor(matPctD)}</td>
          </tr>
        </tbody>
      </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>Monthly forecast vs actual — chart</h2><span class="panel-meta">${escapeHtml(matCust)} · units</span></div>
      <div class="chart-wrap"><canvas id="fvaChart"></canvas></div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>% Attainment by month — line chart</h2><span class="panel-meta">${escapeHtml(matCust)} · SUM(Actual) / SUM(Forecast) × 100</span></div>
      <div class="chart-wrap tall"><canvas id="fvaAttLine"></canvas></div>
    </div>
  `;
  const ytdSel = document.getElementById('fvaYtdSel');
  if (ytdSel) ytdSel.addEventListener('change', e => { window.__fvaYtdCust = e.target.value; renderForecastVsActual(root); });
  const matSel = document.getElementById('fvaMatSel');
  if (matSel) matSel.addEventListener('change', e => { window.__fvaMatCust = e.target.value; renderForecastVsActual(root); });
  const wkSelEl = document.getElementById('fvaWkSel');
  if (wkSelEl) wkSelEl.addEventListener('change', e => { window.__fvaWkCust = e.target.value; renderForecastVsActual(root); });

  // 13-week weekly chart — bars (units) + line (% att US$)
  if (wk && document.getElementById('fvaWkChart')) {
    // Two paired bars per week — Planned vs Actual US$. No crazy % line.
    // The visual story is: are the dark bars (actual) keeping up with the
    // light bars (planned)? Gap = the dollars you missed (or won) that week.
    activeChart.push(new Chart(document.getElementById('fvaWkChart'), {
      type: 'bar',
      data: {
        labels: wkLabels,
        datasets: [
          { label:'Planned US$', data: wkFD, backgroundColor:'#cfe6f5', borderColor:'#0a3d62', borderWidth:1 },
          { label:'Actual US$',  data: wkAD, backgroundColor:'#0a3d62' },
        ]
      },
      options: {
        responsive:true, maintainAspectRatio:false,
        scales: {
          x: { title:{display:true,text:'Week ending'}, grid:{display:false}, ticks:{font:{size:10}} },
          y: { title:{display:true,text:'US$'}, ticks:{callback:(v)=>'$'+(v/1000).toFixed(0)+'k', font:{size:10}}, grid:{color:'rgba(0,0,0,.05)'}, beginAtZero:true },
        },
        plugins: {
          legend:{ position:'bottom', labels:{font:{size:11}} },
          tooltip:{ callbacks:{ label:(ctx) => `${ctx.dataset.label}: $${(ctx.parsed.y||0).toLocaleString()}` } }
        },
        animation:{ duration:250 }
      },
      plugins: [{
        id:'wkAttLabels',
        // Print the attainment % above each Actual bar — green/amber/red coded.
        afterDatasetsDraw(chart) {
          const ctx = chart.ctx;
          const ds = chart.getDatasetMeta(1).data; // actual bars
          ctx.save();
          ctx.font='700 10px Inter, system-ui, sans-serif';
          ctx.textAlign='center';
          ds.forEach((bar,i)=>{
            const v = wkAttD[i];
            if (v == null) return;
            ctx.fillStyle = v >= 95 ? '#16a34a' : v >= 80 ? '#b45309' : '#b91c1c';
            ctx.fillText(v+'%', bar.x, bar.y - 6);
          });
          ctx.restore();
        }
      }]
    }));
  }
  // Monthly chart: show only months where either forecast OR actual has data >0,
  // and limit to recent window — current month ±3. Future months with zero actual still show forecast bar.
  const _today = new Date();  // real today
  const curMo = _today.getMonth(); // 0-indexed
  const winStart = Math.max(0, curMo - 3);
  const winEnd = Math.min(11, curMo + 3);
  const visIdx = [];
  for (let i = winStart; i <= winEnd; i++) visIdx.push(i);
  const chartLabels = visIdx.map(i => months[i]);
  const chartForecast = visIdx.map(i => matRows[i].fU);
  // Actual: null (blank bar) for any month that hasn't happened yet (month index > current month)
  // OR if actual is 0 for past month, still show as 0 (real signal)
  const chartActual = visIdx.map(i => i > curMo ? null : matRows[i].aU);
  activeChart.push(new Chart(document.getElementById('fvaChart'), {
    type: 'bar',
    data: { labels: chartLabels, datasets: [
      { label: 'Forecast', data: chartForecast, backgroundColor: '#cfe6f5' },
      { label: 'Actual', data: chartActual, backgroundColor: '#0a3d62' },
    ]},
    options: chartOpts(true),
    plugins: [{
      id: 'fvaBarLabels',
      afterDatasetsDraw(chart) {
        const ctx = chart.ctx;
        ctx.save();
        ctx.font = '600 10px Inter, system-ui, sans-serif';
        ctx.textAlign = 'center';
        chart.data.datasets.forEach((ds, dsi) => {
          const meta = chart.getDatasetMeta(dsi);
          meta.data.forEach((bar, i) => {
            const v = ds.data[i];
            if (v == null || v === 0) return;
            const label = v >= 1000 ? '$'+(v/1000).toFixed(0)+'k' : '$'+Math.round(v);
            ctx.fillStyle = dsi === 0 ? '#0a3d62' : '#fff';
            ctx.fillText(label, bar.x, bar.y + (dsi === 0 ? -4 : 14));
          });
        });
        ctx.restore();
      }
    }]
  }));

  // % Attainment line chart — limit to past months only (future months have no actual)
  const attData = visIdx.map(i => {
    if (i > curMo) return null; // future months: skip
    return matRows[i].fU > 0 ? Math.round((matRows[i].aU / matRows[i].fU) * 100) : null;
  });
  if (document.getElementById('fvaAttLine')) {
    activeChart.push(new Chart(document.getElementById('fvaAttLine'), {
      type: 'line',
      data: {
        labels: chartLabels,
        datasets: [{
          label: '% Attainment (Actual / Forecast)',
          data: attData,
          borderColor: '#2bb673',
          backgroundColor: 'rgba(43,182,115,.12)',
          fill: true,
          tension: 0.25,
          pointRadius: 5,
          pointBackgroundColor: '#2bb673',
          spanGaps: true,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { title:{display:true,text:'Month'}, ticks:{font:{size:11}}, grid:{display:false} },
          y: { title:{display:true,text:'% Attainment'}, ticks:{font:{size:11}, callback:(v)=>v+'%'}, grid:{color:'rgba(0,0,0,.05)'}, beginAtZero:true }
        },
        plugins: { legend: { display: false } },
        animation: { duration: 250 }
      },
      plugins: [{
        id: 'attlabels',
        afterDatasetsDraw(chart) {
          const {ctx} = chart;
          const ds = chart.getDatasetMeta(0).data;
          ctx.save();
          ctx.font = '600 11px Inter, system-ui, sans-serif';
          ctx.textAlign = 'center';
          ds.forEach((pt, i) => {
            const v = attData[i];
            if (v != null) {
              ctx.fillStyle = v >= 95 ? '#16a34a' : v >= 80 ? '#b45309' : '#b91c1c';
              ctx.fillText(v + '%', pt.x, pt.y - 10);
            }
          });
          ctx.restore();
        }
      }]
    }));
  }
}

function renderShipping(root) {
  const cw = MOCK.shipping.currentWeek || {};
  const lw = MOCK.shipping.lastWeek || {};
  const bc = MOCK.shipping.byCustomer || [];
  const pct = (a, b) => (b && b > 0) ? Math.round((a / b) * 100) : null;
  const attU = cw.attainmentUnits != null ? cw.attainmentUnits : pct(cw.unitsShipped, cw.unitsPlanned);
  const attD = cw.attainmentUSD != null ? cw.attainmentUSD : pct(cw.usdShipped, cw.usdPlanned);
  const attULast = pct(lw.unitsShipped, lw.unitsPlanned);
  const attDLast = pct(lw.usdShipped, lw.usdPlanned);
  const fmtD = (s) => { if(!s) return '—'; const d=new Date(s+'T00:00:00'); return d.toLocaleDateString('en-US',{month:'short',day:'numeric'}); };
  const cwEmpty = !(cw.unitsShipped > 0);  // week just started — nothing shipped yet
  const weekLabel = cw.weekStart
    ? `Mon ${fmtD(cw.weekStart)} → today (this week so far)${cwEmpty ? ' · nothing shipped yet — last week shown →' : ''}`
    : 'Awaiting current-week shipping report';
  const lastLabel = lw.weekStart ? `Mon ${fmtD(lw.weekStart)} → Sun ${fmtD(lw.weekEnd)} (full week)` : '—';
  const attTag = (p) => p == null ? '<span style="color:var(--ink-dim)">—</span>' : p >= 95 ? `<span class="tag tag-good">${p}%</span>` : p >= 80 ? `<span class="tag tag-warn">${p}%</span>` : `<span class="tag tag-bad">${p}%</span>`;
  const attColor = (p) => p == null ? 'var(--ink-dim)' : p >= 95 ? '#16a34a' : p >= 80 ? '#b45309' : '#b91c1c';

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Shipping & Logistics</p>
        <h1>This week vs last week</h1>
        <p>${escapeHtml(weekLabel)} — actuals against plan, side-by-side with the prior week.</p>
      </div>
      ${SESSION.role !== 'admin' ? `<button class="btn btn-ghost btn-sm" onclick="navigate('upload')">+ Upload Data</button>` : ''}
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h2>This week</h2><span class="panel-meta">${escapeHtml(weekLabel)}</span></div>
        <div style="padding:18px 22px">
          <div class="kpi-grid">
            <div class="kpi"><div class="kpi-label">Units shipped</div><div class="kpi-value">${fmtNum(cw.unitsShipped || 0)}</div><div class="kpi-delta flat">vs ${fmtNum(cw.unitsPlanned || 0)} planned</div></div>
            <div class="kpi"><div class="kpi-label">US$ shipped</div><div class="kpi-value">${fmtMoney(cw.usdShipped || 0)}</div><div class="kpi-delta flat">vs ${fmtMoney(cw.usdPlanned || 0)} planned</div></div>
            <div class="kpi"><div class="kpi-label">% attainment (units)</div><div class="kpi-value" style="color:${attColor(attU)}">${attU != null ? attU + '%' : '—'}</div><div class="kpi-delta flat">${fmtNum(cw.unitsShipped||0)} / ${fmtNum(cw.unitsPlanned||0)}</div></div>
            <div class="kpi"><div class="kpi-label">% attainment ($)</div><div class="kpi-value" style="color:${attColor(attD)}">${attD != null ? attD + '%' : '—'}</div><div class="kpi-delta flat">${fmtMoney(cw.usdShipped||0)} / ${fmtMoney(cw.usdPlanned||0)}</div></div>
          </div>
        </div>
      </div>
      <div class="panel" style="opacity:.85">
        <div class="panel-head"><h2>Last week</h2><span class="panel-meta">${escapeHtml(lastLabel)}</span></div>
        <div style="padding:18px 22px">
          <div class="kpi-grid">
            <div class="kpi"><div class="kpi-label">Units shipped</div><div class="kpi-value">${fmtNum(lw.unitsShipped || 0)}</div><div class="kpi-delta flat">vs ${fmtNum(lw.unitsPlanned || 0)} planned</div></div>
            <div class="kpi"><div class="kpi-label">US$ shipped</div><div class="kpi-value">${fmtMoney(lw.usdShipped || 0)}</div><div class="kpi-delta flat">vs ${fmtMoney(lw.usdPlanned || 0)} planned</div></div>
            <div class="kpi"><div class="kpi-label">% attainment (units)</div><div class="kpi-value" style="color:${attColor(attULast)}">${attULast != null ? attULast + '%' : '—'}</div><div class="kpi-delta flat">${fmtNum(lw.unitsShipped||0)} / ${fmtNum(lw.unitsPlanned||0)}</div></div>
            <div class="kpi"><div class="kpi-label">% attainment ($)</div><div class="kpi-value" style="color:${attColor(attDLast)}">${attDLast != null ? attDLast + '%' : '—'}</div><div class="kpi-delta flat">${fmtMoney(lw.usdShipped||0)} / ${fmtMoney(lw.usdPlanned||0)}</div></div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head" style="justify-content:space-between">
        <h2>Remaining to ship — by customer</h2>
        <span class="panel-meta">
          <span style="display:inline-flex;gap:6px">
            <button class="btn btn-sm" data-scope="week"  id="remTabWeek"  style="font-size:11px">This week</button>
            <button class="btn btn-sm btn-ghost" data-scope="month" id="remTabMonth" style="font-size:11px">This month</button>
            <button class="btn btn-sm btn-ghost" data-scope="year"  id="remTabYear"  style="font-size:11px">YTD</button>
          </span>
        </span>
      </div>
      <div id="remBody" style="padding:0"></div>
    </div>

    ${(() => {
      const dbc = MOCK.shipping.dailyByCustomer;
      if (!dbc || !Array.isArray(dbc.rows) || dbc.rows.length === 0) return '<div></div>';
      const days = dbc.days || [];
      const labels = dbc.dayLabels || days;
      return `
      <div class="panel">
        <div class="panel-head"><h2>Daily shipping this week — by customer × day</h2><span class="panel-meta">${escapeHtml(dbc.weekStart)} → ${escapeHtml(dbc.weekEnd)} · ${fmtNum(dbc.weekUnits||0)} units / ${fmtMoney(dbc.weekUsd||0)} · planned ${fmtNum(dbc.weekPlannedUnits||0)} / ${fmtMoney(dbc.weekPlannedUsd||0)}</span></div>
        <div style="overflow-x:auto">
          <table style="min-width:780px">
            <thead>
              <tr>
                <th rowspan="2">Customer</th>
                ${labels.map(l => `<th colspan="2" style="text-align:center;border-bottom:1px solid var(--line)">${escapeHtml(l)}</th>`).join('')}
                <th colspan="2" style="text-align:center;background:#f8fafc;border-bottom:1px solid var(--line)">Week total</th>
                <th colspan="2" style="text-align:center;background:#eff6ff;border-bottom:1px solid var(--line)">Planned</th>
              </tr>
              <tr>
                ${days.map(() => '<th style="text-align:right;font-size:10px">Units</th><th style="text-align:right;font-size:10px">$</th>').join('')}
                <th style="text-align:right;font-size:10px;background:#f8fafc">Units</th>
                <th style="text-align:right;font-size:10px;background:#f8fafc">$</th>
                <th style="text-align:right;font-size:10px;background:#eff6ff">Units</th>
                <th style="text-align:right;font-size:10px;background:#eff6ff">$</th>
              </tr>
            </thead>
            <tbody>${dbc.rows.map(r => `
              <tr>
                <td><strong>${escapeHtml(r.customer)}</strong></td>
                ${days.map(d_ => {
                  const c = r.days[d_] || {units:0,usd:0};
                  return `<td style="text-align:right;color:${c.units>0?'#0a3d62':'var(--ink-dim)'}">${c.units>0?fmtNum(c.units):'—'}</td>
                  <td style="text-align:right;color:${c.usd>0?'#0a3d62':'var(--ink-dim)'};font-size:11px">${c.usd>0?fmtMoney(c.usd):'—'}</td>`;
                }).join('')}
                <td style="text-align:right;background:#f8fafc"><strong>${fmtNum(r.weekUnits)}</strong></td>
                <td style="text-align:right;background:#f8fafc"><strong>${fmtMoney(r.weekUsd)}</strong></td>
                <td style="text-align:right;background:#eff6ff;color:var(--ink-dim)">${fmtNum(r.plannedUnits||0)}</td>
                <td style="text-align:right;background:#eff6ff;color:var(--ink-dim)">${fmtMoney(r.plannedUsd||0)}</td>
              </tr>`).join('')}
              <tr style="background:#0a3d62;color:#fff;font-weight:700">
                <td style="color:#fff">Day total</td>
                ${days.map(d_ => {
                  const t = (dbc.dayTotals||{})[d_] || {units:0,usd:0};
                  return `<td style="text-align:right;color:#fff"><strong>${fmtNum(t.units)}</strong></td>
                  <td style="text-align:right;color:#fff;font-size:11px"><strong>${fmtMoney(t.usd)}</strong></td>`;
                }).join('')}
                <td style="text-align:right;color:#fff"><strong>${fmtNum(dbc.weekUnits||0)}</strong></td>
                <td style="text-align:right;color:#fff"><strong>${fmtMoney(dbc.weekUsd||0)}</strong></td>
                <td style="text-align:right;color:#fff"><strong>${fmtNum(dbc.weekPlannedUnits||0)}</strong></td>
                <td style="text-align:right;color:#fff"><strong>${fmtMoney(dbc.weekPlannedUsd||0)}</strong></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>`;
    })()}

    <div style="display:none">
      <table>
        <thead><tr><th>Customer</th><th>Units shipped</th><th>Units planned</th><th>% Units</th><th>US$ shipped</th><th>US$ planned</th><th>% US$</th></tr></thead>
        <tbody>${bc.length === 0
          ? `<tr><td colspan="7" style="text-align:center;color:var(--ink-dim);padding:24px">Upload the latest shipping report to populate this matrix.</td></tr>`
          : bc.map(r => {
              const pu = pct(r.unitsShipped, r.unitsPlanned);
              const pd = pct(r.usdShipped, r.usdPlanned);
              return `<tr>
                <td><strong>${escapeHtml(r.customer)}</strong></td>
                <td>${fmtNum(r.unitsShipped || 0)}</td>
                <td>${fmtNum(r.unitsPlanned || 0)}</td>
                <td>${attTag(pu)}</td>
                <td>${fmtMoney(r.usdShipped || 0)}</td>
                <td>${fmtMoney(r.usdPlanned || 0)}</td>
                <td>${attTag(pd)}</td>
              </tr>`;
            }).join('')
        }</tbody>
      </table>
    </div>

    <div class="panel">
      <div class="panel-head">
        <h2>Shipped units — by week ending</h2>
        <span class="panel-meta">
          <label style="display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--ink-dim)">Window
            <select id="shipWinSel" style="padding:6px 8px;border:1px solid var(--line);border-radius:6px">
              <option value="4">Last 4 weeks</option>
              <option value="13" selected>Last 13 weeks</option>
              <option value="26">Last 26 weeks</option>
              <option value="52">YTD / All</option>
            </select>
          </label>
        </span>
      </div>
      <div class="chart-wrap tall"><canvas id="shipYtdLine"></canvas></div>
      <p style="font-size:11px;color:var(--ink-dim);margin:8px 0 0">Rightmost point is the current/most recent week. Window scrolls back from there.</p>
    </div>
  `;

  // Window selector
  const winEl = document.getElementById('shipWinSel');
  if (winEl) winEl.addEventListener('change', () => {
    if (window.__shipChart) {
      const n = parseInt(winEl.value, 10);
      const ytdAll = MOCK.shipping.ytdWeekly;
      const lbls = ytdAll.labels || [];
      const data = ytdAll.units || [];
      const sliced = lbls.length > n ? lbls.slice(-n) : lbls;
      const sd = data.length > n ? data.slice(-n) : data;
      window.__shipChart.data.labels = sliced;
      window.__shipChart.data.datasets[0].data = sd;
      window.__shipChart.__sliced = sd;
      window.__shipChart.update();
    }
  });

  const ytd = MOCK.shipping.ytdWeekly;
  if (ytd && ytd.labels && ytd.labels.length && document.getElementById('shipYtdLine')) {
    activeChart.push(new Chart(document.getElementById('shipYtdLine'), {
      type: 'line',
      data: {
        labels: (ytd.labels||[]).slice(-13),
        datasets: [{
          label: 'Units shipped',
          data: (ytd.units||[]).slice(-13),
          borderColor: '#0a3d62',
          backgroundColor: 'rgba(10,61,98,.12)',
          fill: true,
          tension: 0.25,
          pointRadius: 4,
          pointBackgroundColor: '#0a3d62',
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { title:{display:true,text:'Week ending'}, ticks:{font:{size:11}}, grid:{display:false} },
          y: { title:{display:true,text:'Units'}, ticks:{font:{size:11}}, grid:{color:'rgba(0,0,0,.05)'} }
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { title: (items) => 'Week ending ' + items[0].label } }
        },
        animation: { duration: 250 }
      },
      plugins: [{
        id: 'pointlabels',
        afterDatasetsDraw(chart) {
          const {ctx} = chart;
          const ds = chart.getDatasetMeta(0).data;
          const data = (chart.__sliced || chart.data.datasets[0].data);
          ctx.save();
          ctx.font = '600 10px Inter, system-ui, sans-serif';
          ctx.fillStyle = '#0a3d62';
          ctx.textAlign = 'center';
          ds.forEach((pt, i) => {
            const v = data[i];
            if (v != null) ctx.fillText(v.toLocaleString(), pt.x, pt.y - 8);
          });
          ctx.restore();
        }
      }]
    }));
    window.__shipChart = activeChart[activeChart.length-1] || null;
  }

  // -------- Remaining-to-ship by-customer panel (Week / Month / YTD) --------
  const rem = MOCK.shipping.remainingByCustomer || null;
  const remBody = document.getElementById('remBody');
  function paintRem(scope) {
    if (!remBody) return;
    if (!rem || !Array.isArray(rem.byCustomer) || rem.byCustomer.length === 0) {
      remBody.innerHTML = `<div style="padding:24px;text-align:center;color:var(--ink-dim)">No remaining-to-ship data yet — awaits next loop pass.</div>`;
      return;
    }
    const totals = (rem.totals || {})[scope] || {planned:0,shipped:0,remaining:0};
    const labelMap = {week:'this week', month:'this month', year:'year-to-date'};
    const rows = [...rem.byCustomer].sort((a,b) => (b[scope].remaining||0) - (a[scope].remaining||0));
    remBody.innerHTML = `
      <div style="padding:14px 22px;display:flex;gap:18px;flex-wrap:wrap;border-bottom:1px solid var(--line);background:#f8fafc">
        <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Planned (${labelMap[scope]})</div><div style="font-size:22px;font-weight:800">${fmtNum(totals.planned||0)}</div></div>
        <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Shipped</div><div style="font-size:22px;font-weight:800;color:#16a34a">${fmtNum(totals.shipped||0)}</div></div>
        <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Remaining</div><div style="font-size:22px;font-weight:800;color:${(totals.remaining||0)>0?'#b91c1c':'#16a34a'}">${fmtNum(totals.remaining||0)}</div></div>
      </div>
      <table>
        <thead><tr><th>Customer</th><th>Planned</th><th>Shipped</th><th>Remaining</th><th>% complete</th></tr></thead>
        <tbody>${rows.map(r => {
          const s = r[scope] || {};
          const p = (s.planned > 0) ? Math.round((s.shipped / s.planned) * 100) : null;
          const remColor = (s.remaining||0) > 0 ? '#b91c1c' : '#16a34a';
          return `<tr>
            <td><strong>${escapeHtml(r.customer)}</strong></td>
            <td>${fmtNum(s.planned||0)}</td>
            <td>${fmtNum(s.shipped||0)}</td>
            <td><strong style="color:${remColor}">${fmtNum(s.remaining||0)}</strong></td>
            <td>${attTag(p)}</td>
          </tr>`;
        }).join('')}</tbody>
      </table>
    `;
  }
  paintRem('week');
  ['Week','Month','Year'].forEach(s => {
    const el = document.getElementById('remTab'+s);
    if (!el) return;
    el.addEventListener('click', () => {
      ['Week','Month','Year'].forEach(x => {
        const e = document.getElementById('remTab'+x);
        if (e) e.className = (x === s) ? 'btn btn-sm' : 'btn btn-sm btn-ghost';
      });
      paintRem(s.toLowerCase());
    });
  });
}

function renderEmployees(root) {
  const emp = MOCK.employees || {supervisors:[],employees:[],dailyPlan:{emails:[]},incidents:[],warnings:[],scoreboard:[],drGrounds:[],stats:{}};
  const stats = emp.stats || {};
  const directoryLoaded = (emp.employees||[]).length > 0;
  const dp = emp.dailyPlan || {};
  const emails = dp.emails || [];
  const dr = emp.drGrounds || [];
  const incidents = emp.incidents || [];
  const warnings = emp.warnings || [];
  const score = emp.scoreboard || [];
  const org = emp.orgChart || null;

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Employees · HR</p>
        <h1>Workforce & supervisor command</h1>
        <p>Per-supervisor daily plans, end-of-day reports, employee scoreboard, and DR-compliant incident documentation. Plant target: ~500 employees / 15 supervisors.</p>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Employees on file</div><div class="kpi-value">${stats.loaded||0}<span style="font-size:14px;color:var(--ink-dim)"> / ${stats.totalEmployees||500}</span></div><div class="kpi-delta flat">${directoryLoaded?'':'directory pending upload'}</div></div>
      <div class="kpi"><div class="kpi-label">Supervisors</div><div class="kpi-value">${(emp.supervisors||[]).length}<span style="font-size:14px;color:var(--ink-dim)"> / ${stats.totalSupervisors||15}</span></div><div class="kpi-delta flat">${emails.length} active work areas</div></div>
      <div class="kpi"><div class="kpi-label">Open incidents (90d)</div><div class="kpi-value" style="color:${incidents.length?'#b45309':'inherit'}">${incidents.length}</div><div class="kpi-delta flat">${warnings.length} written warnings on file</div></div>
      <div class="kpi"><div class="kpi-label">Today's plan</div><div class="kpi-value">${emails.length}<span style="font-size:14px;color:var(--ink-dim)"> areas</span></div><div class="kpi-delta flat">${emails.reduce((s,e)=>s+e.lateCount,0)} late programs to triage</div></div>
    </div>

    <!-- OPERATION NOTES — type what's going on; saves privately for the AI only -->
    <div class="panel" style="margin-bottom:18px;border-left:5px solid #2bb673">
      <div class="panel-head">
        <h2>📝 Operation notes — tell the AI what's going on</h2>
        <span class="panel-meta">private · saved straight to the AI, not shown on the portal</span>
      </div>
      <div style="padding:16px 18px">
        <textarea id="opsNoteText" rows="4" placeholder="Type anything happening in the operation — a line is down, a customer order is rushed, a supervisor is out, a quality issue, a win. Whatever you'd tell a manager walking the floor. The AI reads these to understand what's really going on behind the numbers."
          style="width:100%;background:var(--paper-2);border:1px solid var(--line);border-radius:10px;padding:12px 14px;font-size:14px;line-height:1.5;resize:vertical;font-family:inherit"></textarea>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-top:10px;gap:12px;flex-wrap:wrap">
          <span id="opsNoteStatus" style="font-size:12px;color:var(--ink-dim)">🔒 Your note is sent privately to the AI. It is not displayed anywhere on the portal.</span>
          <button id="opsNoteSave" class="btn btn-primary">💾 Send to the AI</button>
        </div>
      </div>
    </div>

    ${org ? `
    <div class="panel" style="margin-bottom:18px">
      <div class="panel-head">
        <h2>🗺 Plant organization map</h2>
        <span class="panel-meta">👆 click any person to add a note about them · ${escapeHtml(org.meta&&org.meta.location||'')} · Rev ${escapeHtml(org.meta&&org.meta.revision_date||'')}</span>
      </div>
      <!-- TOOLBAR: search + filters + legend -->
      <div style="padding:14px 18px;background:#fff;border-bottom:1px solid var(--line);display:flex;gap:14px;flex-wrap:wrap;align-items:center;justify-content:space-between">
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;flex:1;min-width:280px">
          <div style="position:relative">
            <input id="orgSearch" type="search" placeholder="🔍 Search name or role…" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-size:13px;width:240px" />
          </div>
          <div id="orgFilters" style="display:flex;gap:6px;flex-wrap:wrap">
            <button data-filter="all" class="org-chip org-chip-active">All (${(org.managers||[]).length + (org.supervisors||[]).length + (org.staff||[]).length + 1})</button>
            <button data-filter="open" class="org-chip">Open positions</button>
            <button data-filter="incidents" class="org-chip">Has incidents</button>
            <button data-filter="top" class="org-chip">Top performers</button>
            <button data-filter="attention" class="org-chip">Needs attention</button>
          </div>
        </div>
        <div style="display:flex;gap:14px;font-size:11px;color:var(--ink-dim);align-items:center">
          <span style="display:flex;align-items:center;gap:5px"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#16a34a"></span>≥85 strong</span>
          <span style="display:flex;align-items:center;gap:5px"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#b45309"></span>65-84 ok</span>
          <span style="display:flex;align-items:center;gap:5px"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#b91c1c"></span>&lt;65 watch</span>
          <button id="orgCollapseAll" class="btn btn-ghost btn-sm" style="font-size:11px">Collapse all</button>
        </div>
      </div>
      <style>
        .org-chip{background:#f4f6f8;border:1px solid var(--line);color:var(--ink-2);padding:5px 11px;border-radius:14px;font-size:11px;font-weight:600;cursor:pointer;transition:all .15s}
        .org-chip:hover{background:#e5e9ee}
        .org-chip-active{background:#0a3d62;color:#fff;border-color:#0a3d62}
        .org-col{position:relative;padding:8px 6px 6px;border-radius:10px;transition:opacity .2s}
        .org-col.dimmed{opacity:.25}
        .org-card.dimmed{opacity:.2;pointer-events:none}
        .org-card.match{box-shadow:0 0 0 3px #facc15,0 4px 12px rgba(250,204,21,.4) !important;transform:scale(1.04)}
        .org-card:hover{transform:translateY(-1px);box-shadow:0 6px 14px rgba(0,0,0,.12) !important}
        .org-reports{display:flex;flex-direction:column;gap:7px;margin-top:10px;position:relative;padding-left:18px}
        .org-reports::before{content:"";position:absolute;left:8px;top:-2px;bottom:6px;width:2px;background:var(--line);border-radius:1px}
        .org-reports > .org-card::before{content:"";position:absolute;left:-10px;top:50%;width:10px;height:2px;background:var(--line)}
        .org-col.collapsed .org-reports{display:none}
        .org-col-toggle{position:absolute;top:6px;right:6px;background:rgba(255,255,255,.18);color:#fff;border:none;width:20px;height:20px;border-radius:50%;cursor:pointer;font-size:12px;line-height:1;display:flex;align-items:center;justify-content:center}
        .org-col-toggle:hover{background:rgba(255,255,255,.32)}
      </style>
      <div style="padding:22px 18px;background:#f8fafc;overflow-x:auto">
        <div id="orgMapRoot"></div>
        <p style="font-size:10px;color:var(--ink-dim);margin:18px 0 0;text-align:center;font-style:italic">Click any person for details and history · hover for quick score · ${(org.managers||[]).length} departments · ${(org.supervisors||[]).filter(s=>s.status==='OPEN').length} open positions · prepared by ${escapeHtml(org.meta&&org.meta.prepared_by||'')}</p>
      </div>
    </div>

    <!-- ORG DETAIL DRAWER -->
    <div id="orgDetailDrawer" style="display:none;position:fixed;top:0;right:0;width:420px;max-width:100%;height:100vh;background:#fff;box-shadow:-10px 0 40px rgba(0,0,0,.25);z-index:8800;overflow-y:auto;transform:translateX(100%);transition:transform .25s ease">
      <div id="orgDetailHeader" style="background:linear-gradient(135deg,#0a3d62,#1c5b8a);color:#fff;padding:22px 24px;position:sticky;top:0;z-index:1">
        <button onclick="window.__asaCloseOrgDetail()" style="position:absolute;top:14px;right:14px;background:rgba(255,255,255,.18);color:#fff;border:none;width:28px;height:28px;border-radius:50%;cursor:pointer;font-size:16px">×</button>
        <p id="orgDetailKicker" style="font-size:10px;letter-spacing:2px;text-transform:uppercase;margin:0 0 4px;opacity:.8">Employee</p>
        <h2 id="orgDetailName" style="margin:0;color:#fff;font-size:22px">—</h2>
        <p id="orgDetailRole" style="margin:4px 0 0;font-size:13px;opacity:.85">—</p>
        <p id="orgDetailReports" style="margin:6px 0 0;font-size:11px;opacity:.7"></p>
      </div>
      <div style="padding:20px 24px">
        <div id="orgDetailScore" style="display:flex;align-items:center;gap:14px;background:#f8fafc;padding:14px 16px;border-radius:10px;margin-bottom:16px"></div>
        <div id="orgDetailHighlights" style="margin-bottom:16px"></div>
        <div id="orgDetailIncidents" style="margin-bottom:16px"></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;border-top:1px solid var(--line);padding-top:16px;margin-top:8px">
          <button id="orgDetailFlagBtn" class="btn btn-ghost btn-sm" style="color:#b91c1c;border-color:#b91c1c">⚖ Flag for HR review</button>
          <button onclick="window.__asaCloseOrgDetail()" class="btn btn-ghost btn-sm">Close</button>
        </div>
      </div>
    </div>
    <!-- HR Termination flag modal -->
    <div id="hrFlagModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9000;align-items:center;justify-content:center;padding:20px">
      <div style="background:#fff;border-radius:14px;max-width:640px;width:100%;max-height:90vh;overflow:auto;box-shadow:0 30px 80px rgba(0,0,0,.35)">
        <div style="background:linear-gradient(135deg,#7a1f1f,#b91c1c);color:#fff;padding:18px 24px">
          <p style="font-size:10px;letter-spacing:2px;text-transform:uppercase;margin:0 0 4px;opacity:.85">HR Termination Request</p>
          <h2 style="margin:0;color:#fff;font-size:20px" id="hrFlagName">—</h2>
          <p id="hrFlagRole" style="margin:4px 0 0;font-size:13px;opacity:.85">—</p>
        </div>
        <div style="padding:20px 24px">
          <div id="hrFlagEvidence" style="background:#fff8eb;border-left:3px solid #b45309;padding:12px 14px;border-radius:6px;font-size:13px;color:#1a1a1a;margin-bottom:14px;line-height:1.5"></div>
          <label style="display:block;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--ink-2);font-weight:700;margin-bottom:6px">Reason for termination request</label>
          <select id="hrFlagReason" style="width:100%;background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:14px;margin-bottom:12px">
            <option value="">— select DR Article 88 ground —</option>
            <option value="88-1">88-1 — Dishonesty / theft — single fireable</option>
            <option value="88-2">88-2 — Acts of violence — single fireable</option>
            <option value="88-3">88-3 — Intentional property damage — single fireable</option>
            <option value="88-9">88-9 — Unjustified absence (2+ in 30d)</option>
            <option value="88-11">88-11 — Leaving without authorization (repeated)</option>
            <option value="88-12">88-12 — Insubordination (3 warnings)</option>
            <option value="88-13">88-13 — Negligence harming production</option>
            <option value="88-14">88-14 — Intoxication / drugs — single fireable</option>
            <option value="88-15">88-15 — Repeated tardiness (3 warnings in 90d)</option>
          </select>
          <label style="display:block;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--ink-2);font-weight:700;margin-bottom:6px">Summary for HR file</label>
          <textarea id="hrFlagNotes" rows="4" placeholder="Why this employee should be terminated — specific dates, witnesses, prior warnings. The AI agent will read this + their incidents on file and assemble the formal Article 88 documentation package on the next loop pass." style="width:100%;background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:13px;resize:vertical;margin-bottom:14px"></textarea>
          <div style="background:#fff3f3;border-left:3px solid #b91c1c;padding:10px 12px;border-radius:4px;font-size:11px;color:#1a1a1a;line-height:1.5;margin-bottom:14px">
            <strong style="color:#b91c1c">⚖ DR Labor Law Notice:</strong> Filing this request flags the employee for the AI to assemble Article 88 documentation. The agent will only generate a complete package if there are <strong>existing documented incidents on file</strong> that support the cited ground. If the threshold isn't met, the agent will produce a documentation-gap report instead — outlining what's missing — rather than fabricate evidence. Final termination decisions remain with HR + counsel.
          </div>
          <div style="display:flex;gap:10px;justify-content:flex-end">
            <button class="btn btn-ghost btn-sm" onclick="document.getElementById('hrFlagModal').style.display='none'">Cancel</button>
            <button id="hrFlagSubmit" class="btn btn-primary btn-sm" style="background:#b91c1c">Submit termination request</button>
          </div>
          <p id="hrFlagStatus" style="font-size:12px;color:var(--ink-dim);margin:10px 0 0"></p>
        </div>
      </div>
    </div>
    <!-- Hover popover -->
    <div id="orgPopover" style="display:none;position:fixed;z-index:8500;background:#0a3d62;color:#fff;padding:12px 14px;border-radius:8px;font-size:12px;line-height:1.5;max-width:280px;box-shadow:0 12px 30px rgba(0,0,0,.4);pointer-events:none"></div>
    <!-- Employee detail modal -->
    <div id="empDetailModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9000;align-items:center;justify-content:center;padding:20px">
      <div style="background:#fff;border-radius:14px;max-width:680px;width:100%;max-height:90vh;overflow:auto;box-shadow:0 30px 80px rgba(0,0,0,.35)">
        <div id="empDetailBody"></div>
      </div>
    </div>` : ''}

    ${!directoryLoaded ? `
      <div class="panel" style="border-left:4px solid #b45309;background:#fff8eb">
        <div class="panel-head"><h2 style="color:#b45309">📋 Directory upload pending</h2><span class="panel-meta">drops in uploads/employees/</span></div>
        <div style="padding:18px 22px;font-size:14px;line-height:1.6">
          <p style="margin:0 0 10px">Send a CSV or XLSX with these columns to populate the 500-employee scoreboard:</p>
          <pre style="background:#fff;border:1px solid var(--line);border-radius:6px;padding:12px;font-size:11px;margin:0 0 10px;overflow:auto">employee_id, name, position, supervisor_id, module_or_area, hire_date, status, dr_cedula (optional)</pre>
          <p style="margin:0 0 10px">And a second file (or second sheet) for supervisors:</p>
          <pre style="background:#fff;border:1px solid var(--line);border-radius:6px;padding:12px;font-size:11px;margin:0 0 10px;overflow:auto">supervisor_id, name, area, email, phone (optional)</pre>
          <p style="margin:0;color:#b45309"><strong>Notes:</strong> employee_id and supervisor_id must match. Drop in <code>uploads/employees/</code> and the next cron pass will ingest. Until then, the Daily Plan below works using customer-as-area buckets.</p>
        </div>
      </div>
    ` : ''}

    <!-- DAILY PLAN — EMAIL DRAFTS -->
    <div class="panel">
      <div class="panel-head"><h2>📧 Today's supervisor emails — draft from WIP</h2><span class="panel-meta">${dp.date||'—'} · ${dp.summary||''}</span></div>
      ${emails.length === 0 ? `<p style="padding:18px 22px;color:var(--ink-dim)">No active work areas right now.</p>` : `
        <div style="padding:0 4px 12px">
          ${emails.map((e,i) => `
            <div style="padding:18px 22px;border-bottom:1px solid var(--line)">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:14px;margin-bottom:12px;flex-wrap:wrap">
                <div>
                  <h3 style="margin:0 0 4px;color:#0a3d62">${escapeHtml(e.area)}</h3>
                  <div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">${e.lateCount} late · ${e.weekCount} this week · ${fmtMoney(e.lateUsd)} late value</div>
                </div>
                <div style="display:flex;gap:6px">
                  <button class="btn btn-ghost btn-sm" onclick="window.__asaCopyEmail && window.__asaCopyEmail(${i})">📋 Copy</button>
                  <button class="btn btn-primary btn-sm" onclick="window.__asaMailEmail && window.__asaMailEmail(${i})">✉ Open in mail</button>
                </div>
              </div>
              <pre id="emailBody${i}" style="background:#f8fafc;border:1px solid var(--line);border-radius:6px;padding:14px;font-size:12px;font-family:'SF Mono',Menlo,monospace;white-space:pre-wrap;line-height:1.55;margin:0;max-height:280px;overflow:auto">${escapeHtml(e.subject)}\n\n${escapeHtml(e.body)}</pre>
            </div>
          `).join('')}
        </div>
      `}
    </div>

    <!-- DAILY REPORT INTAKE FORM -->
    <div class="panel" style="margin-top:18px;border-top:4px solid #16a34a">
      <div class="panel-head"><h2>📥 Submit daily report (supervisors)</h2><span class="panel-meta">paste reply from email / WhatsApp / notes</span></div>
      <div style="padding:18px 22px;font-size:13px">
        <p style="margin:0 0 12px;color:var(--ink-dim)">Supervisor fills this at end of shift. Choose your area + date, paste the report text. The portal parses it into highlights + incidents and updates the scoreboard within 15 minutes.</p>
        <form id="dailyReportForm" onsubmit="return false" style="display:grid;gap:12px">
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
            <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-2);font-weight:700">
              Area / Module
              <select id="drArea" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:14px">
                ${(MOCK.employees && MOCK.employees.supervisors || []).length === 0
                  ? `<option value="">(supervisor directory not loaded — type below)</option>`
                  : (MOCK.employees.supervisors||[]).map(s => `<option value="${escapeHtml(s.supervisor_id)}">${escapeHtml(s.name)} — ${escapeHtml(s.area)}</option>`).join('')
                }
                ${(MOCK.employees && MOCK.employees.dailyPlan && MOCK.employees.dailyPlan.emails || []).map(e => `<option value="area:${escapeHtml(e.area)}">${escapeHtml(e.area)} (interim)</option>`).join('')}
              </select>
            </label>
            <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-2);font-weight:700">
              Date
              <input id="drDate" type="date" value="2026-05-20" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:14px" />
            </label>
            <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-2);font-weight:700">
              Supervisor name (if not in list)
              <input id="drSupName" type="text" placeholder="your name" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:14px" />
            </label>
          </div>
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-2);font-weight:700">
            Completed today (programs + units shipped/produced)
            <textarea id="drCompleted" rows="3" placeholder="e.g. Tsunami BB Jersey Basic — 120 units / Bellforge BB Pant — 80 units / shipped to Granite 200 units" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:13px;resize:vertical"></textarea>
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-2);font-weight:700">
            Programs delayed today (program + reason)
            <textarea id="drDelays" rows="2" placeholder="e.g. Granite BB Pant — fabric did not arrive / Bellforge volleyball jersey — print machine down 2hr" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:13px;resize:vertical"></textarea>
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-2);font-weight:700">
            👍 Employee highlights (name — what they did well)
            <textarea id="drHighlights" rows="3" placeholder="e.g. Maria Perez — picked up extra shift covering Module 2 / Juan Diaz — caught defect in 3rd inspection, saved 40 units" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:13px;resize:vertical"></textarea>
          </label>
          <label style="display:flex;flex-direction:column;gap:4px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-2);font-weight:700">
            ⚠ Incidents (name — what happened — time — witnesses)
            <textarea id="drIncidents" rows="4" placeholder="e.g. Pedro Gomez — arrived 45min late without calling, third time this month — 7:45am — witnesses: Ana Cruz, Luis Mejia / Carmen Lopez — argued with supervisor and walked off floor — 11am — witnesses: M. Rodriguez" style="background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:13px;resize:vertical"></textarea>
          </label>
          <div style="background:#fff8eb;border-left:3px solid #b45309;padding:10px 14px;border-radius:4px;font-size:12px;color:#1a1a1a;line-height:1.5">
            <strong style="color:#b45309">⚖ DR labor-law note:</strong> Incidents must describe real events truthfully. Each becomes part of an employee's permanent record and may be cited in the DR labor courts if the company later terminates for cause under Article 88. Include names of witnesses present — uncorroborated incidents have limited legal weight.
          </div>
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <button id="drSubmitBtn" class="btn btn-primary">Submit report</button>
            <span id="drStatus" style="font-size:12px;color:var(--ink-dim)"></span>
          </div>
        </form>
      </div>
    </div>

    <!-- EMPLOYEE SCOREBOARD -->
    <div class="panel" style="margin-top:18px">
      <div class="panel-head"><h2>Employee scoreboard</h2><span class="panel-meta">${score.length} rated · ${emp.supervisors?.length||0} supervisors reporting</span></div>
      ${score.length === 0 ? `
        <p style="padding:18px 22px;color:var(--ink-dim);font-size:14px">Scoreboard activates once supervisors submit end-of-day reports (highlights + incidents). Each employee is rated 0-100:<br/>
        <strong>Start: 70 (neutral).</strong> +5 per highlight from supervisor. −10 per documented incident. −20 per written warning. −40 per Article 88 major-cause incident. Updates daily.</p>
      ` : `
        <div style="overflow-x:auto;max-height:560px;overflow-y:auto">
        <table>
          <thead><tr><th>Rank</th><th>Employee</th><th>Position</th><th>Supervisor</th><th>Score</th><th>Highlights (90d)</th><th>Incidents</th><th>Warnings</th><th>Status</th></tr></thead>
          <tbody>${score.map((s,i)=>`<tr>
            <td><strong>#${i+1}</strong></td>
            <td><strong>${escapeHtml(s.name)}</strong></td>
            <td style="font-size:12px;color:var(--ink-dim)">${escapeHtml(s.position||'')}</td>
            <td style="font-size:12px">${escapeHtml(s.supervisor||'')}</td>
            <td style="font-weight:700;color:${s.score>=80?'#16a34a':s.score>=60?'#b45309':'#b91c1c'}">${s.score}</td>
            <td>${s.highlights||0}</td>
            <td>${s.incidents>0?`<span class="tag tag-warn">${s.incidents}</span>`:'0'}</td>
            <td>${s.warnings>0?`<span class="tag tag-bad">${s.warnings}</span>`:'0'}</td>
            <td>${s.terminationReady?`<button class="btn btn-ghost btn-sm" style="color:#b91c1c;border-color:#b91c1c" onclick="window.__asaTermPkg && window.__asaTermPkg('${escapeHtml(s.employee_id)}')">📄 Termination doc</button>`:`<span class="tag tag-good">Active</span>`}</td>
          </tr>`).join('')}</tbody>
        </table>
        </div>
      `}
    </div>

    <!-- DR LABOR LAW REFERENCE -->
    <div class="panel" style="margin-top:18px">
      <div class="panel-head"><h2>DR Labor Law — Article 88 just-cause grounds</h2><span class="panel-meta">DR Labor Code · required to terminate without severance</span></div>
      <div style="padding:14px 22px;font-size:13px;line-height:1.6">
        <p style="margin:0 0 12px;background:#fff8eb;border-left:3px solid #b45309;padding:10px 14px;border-radius:4px"><strong>⚖ How DR labor courts work:</strong> Termination without severance requires one of the 19 grounds in Article 88, documented contemporaneously, with witness corroboration where applicable. Employer must notify the DR Ministry of Labor within 48 hours of dismissal. Falsified records or "tailored" documentation = the company loses the case + pays severance + damages.</p>
        <p style="margin:0 0 10px"><strong>Article 88 grounds tracked by this system:</strong> <span style="font-weight:400;color:var(--ink-dim)">(shown in English for review · stored and filed in Spanish for legal validity)</span></p>
        <div style="overflow-x:auto"><table>
          <thead><tr><th>Code</th><th>Ground (cause)</th><th>Severity</th><th>Single-incident fireable?</th><th>Threshold if not</th></tr></thead>
          <tbody>${dr.map(g=>{
            const en = (typeof ART88_EN !== 'undefined' && ART88_EN[g.code]) || g.ground;
            return `<tr>
            <td><strong>Art. ${escapeHtml(g.code)}</strong></td>
            <td><div style="font-weight:600">${escapeHtml(en)}</div><div style="font-size:11px;color:var(--ink-dim);font-style:italic;margin-top:2px">${escapeHtml(g.ground)}</div></td>
            <td><span class="tag tag-${g.severity==='high'?'bad':g.severity==='medium'?'warn':'good'}">${escapeHtml(g.severity)}</span></td>
            <td>${g.singleIncidentFireable?'<span style="color:#b91c1c;font-weight:700">YES — 1 incident sufficient</span>':'<span style="color:var(--ink-dim)">No</span>'}</td>
            <td style="font-size:12px;color:var(--ink-dim)">${escapeHtml(g.threshold||'—')}</td>
          </tr>`;}).join('')}</tbody>
        </table></div>
        <p style="margin:14px 0 0;font-size:12px;color:var(--ink-dim)">Source: Dominican Republic Labor Code, Article 88. The table above is shown in English for managerial review; the underlying Spanish text (in italics) is what the AI uses when generating the formal Carta de Despido + Comunicación al Ministerio de Trabajo so the paperwork is filed in the proper legal language. The system maps each incident to a specific ground and tracks the threshold (e.g., 3 warnings within 90 days for tardiness) before flagging an employee as "termination-eligible." Documentation is designed to be admissible in DR labor courts — meaning <em>actual, contemporaneous, witnessed</em> records of real events. The system <strong>will not</strong> exaggerate severity or fabricate detail.</p>
      </div>
    </div>

    <!-- INCIDENT LOG -->
    <div class="panel" style="margin-top:18px">
      <div class="panel-head"><h2>Recent incidents — 90 day window</h2><span class="panel-meta">${incidents.length} incident${incidents.length===1?'':'s'} on file</span></div>
      ${incidents.length === 0 ? `<p style="padding:18px 22px;color:var(--ink-dim)">No incidents logged yet. When supervisors submit daily reports with the "incident" field, they land here with the employee tagged, the date, witnesses, and Article 88 mapping.</p>` : `
        <div style="overflow-x:auto;max-height:480px;overflow-y:auto"><table>
          <thead><tr><th>Date</th><th>Employee</th><th>Type</th><th>Art. 88</th><th>Description</th><th>Witnesses</th><th>Supervisor</th><th>Status</th></tr></thead>
          <tbody>${incidents.map(i=>`<tr>
            <td style="font-size:11px">${escapeHtml(i.date)}</td>
            <td><strong>${escapeHtml(i.employee_name||i.employee_id)}</strong></td>
            <td><span class="tag tag-${i.severity==='high'?'bad':i.severity==='medium'?'warn':'info'}">${escapeHtml(i.type)}</span></td>
            <td style="font-size:11px">${escapeHtml(i.dr_ground||'—')}</td>
            <td style="font-size:12px;max-width:380px">${escapeHtml(i.description||'')}</td>
            <td style="font-size:11px">${(i.witnesses||[]).join(', ')||'—'}</td>
            <td style="font-size:12px">${escapeHtml(i.supervisor||'')}</td>
            <td>${i.written_warning?'<span class="tag tag-warn">Written</span>':'<span class="tag tag-info">Logged</span>'}</td>
          </tr>`).join('')}</tbody>
        </table></div>
      `}
    </div>

    <div class="panel" style="background:#f8fafc;margin-top:14px">
      <div class="panel-head"><h2>How this section works</h2></div>
      <div style="padding:14px 22px;font-size:12px;line-height:1.6">
        <p style="margin:0 0 8px"><strong>1. Daily plan generator</strong> — Each morning the system reads WIP + late orders + this-week shipping plan, groups work by supervisor area, and drafts an email per supervisor. Copy/paste or open in your mail client.</p>
        <p style="margin:0 0 8px"><strong>2. Daily report intake</strong> — Supervisor replies (or pastes report into a form, coming next) with: completed work, highlights (employee did well), incidents (employee did poorly). System parses and updates scores + incident log.</p>
        <p style="margin:0 0 8px"><strong>3. Employee scoring</strong> — Each employee starts at 70 (neutral). +5 per highlight. −10 per documented incident. −20 per written warning. −40 per Article 88 major-cause event. Score drives the ranked scoreboard.</p>
        <p style="margin:0 0 8px"><strong>4. Termination eligibility</strong> — Triggered ONLY when an employee's incident record meets DR Article 88 threshold (e.g., single major-cause incident with witness, OR 3 written warnings within 90 days for the same minor-cause ground). The system will not flag termination based on score alone.</p>
        <p style="margin:0"><strong>5. Termination paperwork</strong> — When eligible, the system generates the formal Spanish-language paperwork (Carta de Despido + Comunicación al Ministerio de Trabajo, which must be filed within 48 hours) plus an English incident summary with attached witness statements. Each cites the specific Article 88 ground. Print and route per instructions in each document.</p>
      </div>
    </div>
  `;

  // Email actions
  window.__asaCopyEmail = (i) => {
    const el = document.getElementById('emailBody'+i);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(()=>showToast('Email copied to clipboard','success')).catch(()=>showToast('Copy failed','error'));
  };
  window.__asaMailEmail = (i) => {
    const e = ((MOCK.employees && MOCK.employees.dailyPlan && MOCK.employees.dailyPlan.emails) || [])[i];
    if (!e) return;
    const subj = encodeURIComponent(e.subject);
    const body = encodeURIComponent(e.body);
    window.open(`mailto:?subject=${subj}&body=${body}`,'_blank');
  };
  window.__asaTermPkg = (eid) => {
    showToast('Termination package generator activates when an employee meets Article 88 threshold. Currently no scored employees.','info');
  };

  // =============================================================
  // INTERACTIVE ORG MAP — hover for score, click for HR action
  // =============================================================
  (function buildOrgMap() {
    const root = document.getElementById('orgMapRoot');
    if (!root || !org) return;
    const pop = document.getElementById('orgPopover');
    const allPeople = [
      {...org.plantManager},
      ...(org.staff||[]),
      ...(org.managers||[]).map(m => ({...m, type:'manager'})),
      ...(org.supervisors||[])
    ];
    // Index incidents + highlights by employee_id AND by name (case-insensitive substring)
    const incidentsByPerson = {};
    const highlightsByPerson = {};
    (emp.incidents||[]).forEach(i => {
      const k = (i.employee_id||i.employee_name||'').toLowerCase();
      if (!k) return;
      (incidentsByPerson[k] = incidentsByPerson[k] || []).push(i);
    });
    (emp.highlights||[]).forEach(h => {
      const k = (h.employee_id||h.employee_name||'').toLowerCase();
      if (!k) return;
      (highlightsByPerson[k] = highlightsByPerson[k] || []).push(h);
    });
    const statsFor = (p) => {
      const k1 = (p.supervisor_id||'').toLowerCase();
      const k2 = (p.name||'').toLowerCase();
      const inc = (incidentsByPerson[k1]||[]).concat(incidentsByPerson[k2]||[]);
      const hi  = (highlightsByPerson[k1]||[]).concat(highlightsByPerson[k2]||[]);
      const score = Math.max(0, Math.min(100, 75 + (hi.length*5) - (inc.length*8)));
      return { incidents: inc.length, highlights: hi.length, score, _inc: inc, _hi: hi };
    };

    // Department color palette — each manager column gets a tint for visual identity
    const DEPT_COLORS = [
      {tint:'#fef3c7', accent:'#b45309'}, // amber
      {tint:'#dbeafe', accent:'#1e40af'}, // blue
      {tint:'#dcfce7', accent:'#15803d'}, // green
      {tint:'#fce7f3', accent:'#9d174d'}, // pink
      {tint:'#e0e7ff', accent:'#4338ca'}, // indigo
      {tint:'#fed7aa', accent:'#9a3412'}, // orange
      {tint:'#cffafe', accent:'#0e7490'}, // cyan
      {tint:'#f3e8ff', accent:'#6b21a8'}, // purple
      {tint:'#fee2e2', accent:'#991b1b'}, // red
    ];

    // Build HTML
    let html = '';
    // Top: Plant Manager
    html += `<div style="display:flex;justify-content:center;margin-bottom:14px">${cardHTML(org.plantManager, 'plant_manager', statsFor(org.plantManager))}</div>`;
    // Connecting line down to staff/managers row
    html += `<div style="display:flex;justify-content:center;margin-bottom:0"><div style="width:2px;height:18px;background:var(--line)"></div></div>`;
    // Staff (executive assistants etc.)
    if ((org.staff||[]).length) {
      html += `<div style="display:flex;justify-content:center;margin-bottom:14px;gap:10px;flex-wrap:wrap">`;
      (org.staff||[]).forEach(s => { html += cardHTML(s, 'staff', statsFor(s)); });
      html += `</div>`;
    }
    // 9 manager columns, each with its supervisors + ALL employees nested under
    const allEmps = emp.employees || [];
    html += `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;align-items:flex-start">`;
    (org.managers||[]).forEach((m, idx) => {
      const reports = (org.supervisors||[]).filter(s => s.manager_id === m.supervisor_id);
      const empsHere = allEmps.filter(e => e.supervisor_id === m.supervisor_id);
      // Group employees by department within this manager
      const byDept = {};
      empsHere.forEach(e => { (byDept[e.department||'—'] = byDept[e.department||'—'] || []).push(e); });
      const dept = DEPT_COLORS[idx % DEPT_COLORS.length];
      html += `<div class="org-col" data-col-idx="${idx}" style="background:${dept.tint};border-top:3px solid ${dept.accent}">`;
      html += cardHTML(m, 'manager', statsFor(m), dept);
      if (reports.length) {
        html += `<div class="org-reports">`;
        reports.forEach(r => { html += cardHTML(r, r.type==='supervisor_group'?'supervisor_group':'coordinator', statsFor(r), dept); });
        html += `</div>`;
      }
      // Show count + expandable employee list
      if (empsHere.length) {
        html += `<div style="margin-top:8px;padding:8px 10px;background:rgba(255,255,255,.5);border-radius:6px;font-size:11px">
          <div style="display:flex;justify-content:space-between;align-items:center;cursor:pointer" onclick="(function(t){var el=t.nextElementSibling;el.style.display=el.style.display==='none'?'block':'none';t.querySelector('.toggle').textContent=el.style.display==='none'?'▸':'▾';})(this)">
            <strong>${empsHere.length} employees</strong>
            <span class="toggle" style="color:${dept.accent}">▸</span>
          </div>
          <div style="display:none;margin-top:8px;max-height:340px;overflow-y:auto">
            ${Object.entries(byDept).sort((a,b)=>b[1].length-a[1].length).map(([deptName,list]) => `
              <div style="margin-bottom:8px">
                <div style="font-size:9px;letter-spacing:1px;text-transform:uppercase;color:${dept.accent};font-weight:700;margin-bottom:3px">${escapeHtml(deptName)} (${list.length})</div>
                ${list.map(e => empCardHTML(e, dept)).join('')}
              </div>`).join('')}
          </div>
        </div>`;
      }
      html += `</div>`;
    });
    html += `</div>`;
    root.innerHTML = html;

    function cardHTML(p, type, st, dept) {
      const isOpen = p.status === 'OPEN';
      const scoreColor = st.score >= 85 ? '#16a34a' : st.score >= 65 ? '#b45309' : '#b91c1c';
      const accent = dept ? dept.accent : '#0a3d62';
      const sizes = {
        plant_manager: {bg:'linear-gradient(135deg,#0a3d62,#1c5b8a)', color:'#fff', size:'17px', sub:'11px', pad:'14px 22px', minw:'260px', shadow:'0 4px 14px rgba(10,61,98,.25)'},
        manager:       {bg:accent, color:'#fff', size:'13px', sub:'10px', pad:'10px 12px', minw:'auto', shadow:'0 2px 6px rgba(0,0,0,.1)'},
        coordinator:   {bg:'#fff', color:'#0a3d62', size:'12px', sub:'10px', pad:'8px 10px', minw:'auto', shadow:'0 1px 3px rgba(0,0,0,.06)'},
        supervisor:    {bg:'#fff', color:'#0a3d62', size:'12px', sub:'10px', pad:'8px 10px', minw:'auto', shadow:'0 1px 3px rgba(0,0,0,.06)'},
        supervisor_group:{bg:'#fff', color:'#0a3d62', size:'11px', sub:'10px', pad:'7px 10px', minw:'auto', shadow:'0 1px 3px rgba(0,0,0,.06)'},
        staff:         {bg:'#fff', color:'#0a3d62', size:'12px', sub:'10px', pad:'8px 16px', minw:'200px', shadow:'0 2px 6px rgba(0,0,0,.08)'},
      };
      const s = sizes[type] || sizes.coordinator;
      const border = isOpen ? 'border:2px dashed #b91c1c;background:#fff3f3' : (type==='plant_manager'||type==='manager') ? '' : 'border:1px solid var(--line)';
      const title = type==='plant_manager' ? `<p style="font-size:9px;letter-spacing:2px;text-transform:uppercase;margin:0 0 4px;opacity:.7">Plant Manager</p>` : '';
      const titleLine = p.title_en || p.title_es || '';
      const collapseBtn = (type==='manager') ? `<button class="org-col-toggle" onclick="event.stopPropagation();window.__asaToggleCol(this)" title="Collapse / expand team">−</button>` : '';
      const searchHay = ((p.name||'')+' '+titleLine+' '+(p.area||'')).toLowerCase();
      const data = encodeURIComponent(JSON.stringify({...p, _stats: {incidents: st.incidents, highlights: st.highlights, score: st.score, _inc: st._inc, _hi: st._hi}}));
      return `<div class="org-card" data-person="${data}" data-search="${escapeHtml(searchHay)}" data-open="${isOpen?'1':'0'}" data-incidents="${st.incidents}" data-score="${st.score}"
          style="background:${s.bg};color:${s.color};padding:${s.pad};border-radius:8px;text-align:center;${s.minw!=='auto'?'min-width:'+s.minw+';':''}box-shadow:${s.shadow};cursor:${isOpen?'default':'pointer'};${border};position:relative;transition:transform .12s ease,box-shadow .12s ease"
          ${isOpen ? '' : `onmouseenter="window.__asaShowOrgPop(event,this)" onmouseleave="window.__asaHideOrgPop()" onmousemove="window.__asaMoveOrgPop(event)" onclick="window.__asaOpenOrgDetail(this)"`}>
        ${title}
        ${collapseBtn}
        <div style="font-size:${s.size};font-weight:700;line-height:1.2;color:${isOpen?'#b91c1c':s.color}">${escapeHtml(p.name||'')}${isOpen?' (OPEN)':''}</div>
        ${titleLine ? `<div style="font-size:${s.sub};opacity:.85;margin-top:3px;font-style:italic;line-height:1.3;color:${type==='manager'||type==='plant_manager'?'rgba(255,255,255,.85)':'var(--ink-dim)'}">${escapeHtml(titleLine)}</div>` : ''}
        ${!isOpen ? `<div style="position:absolute;top:4px;${type==='manager'?'left':'right'}:6px;background:${scoreColor};color:#fff;font-size:9px;font-weight:700;padding:1px 6px;border-radius:8px">${st.score}</div>` : ''}
        ${(!isOpen && (st.incidents>0 || st.highlights>0)) ? `<div style="position:absolute;bottom:-6px;right:6px;display:flex;gap:3px">${st.incidents>0?`<span style="background:#b91c1c;color:#fff;font-size:9px;padding:1px 5px;border-radius:8px">⚠ ${st.incidents}</span>`:''}${st.highlights>0?`<span style="background:#16a34a;color:#fff;font-size:9px;padding:1px 5px;border-radius:8px">👍 ${st.highlights}</span>`:''}</div>`:''}
      </div>`;
    }

    function empCardHTML(e, dept) {
      // Score per employee based on highlights/incidents on file
      const st = statsFor({supervisor_id: e.employee_id, name: e.name});
      const scoreColor = st.score >= 85 ? '#16a34a' : st.score >= 65 ? '#b45309' : '#b91c1c';
      const noteCount = (e.notes || []).length;
      const data = encodeURIComponent(JSON.stringify({...e, _stats: st}));
      return `<div class="emp-card" data-emp="${data}"
          onclick="window.__asaOpenEmpDetail(this)"
          onmouseenter="window.__asaShowEmpPop(event,this)" onmouseleave="window.__asaHideOrgPop()" onmousemove="window.__asaMoveOrgPop(event)"
          style="background:#fff;border:1px solid var(--line);border-left:3px solid ${dept.accent};border-radius:4px;padding:5px 8px;margin-bottom:3px;font-size:11px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;gap:6px">
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;line-height:1.1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(e.name)}</div>
          <div style="font-size:9px;color:var(--ink-dim);line-height:1.2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(e.puesto||'')}</div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:2px">
          <span style="background:${scoreColor};color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:8px;line-height:1.2">${st.score}</span>
          ${noteCount>0 ? `<span style="background:#0a3d62;color:#fff;font-size:8px;padding:1px 4px;border-radius:6px;line-height:1.2">📝${noteCount}</span>` : ''}
        </div>
      </div>`;
    }

    // ===== Interactivity: search, filter chips, collapse, drawer =====
    const searchInput = document.getElementById('orgSearch');
    const filterButtons = document.querySelectorAll('#orgFilters .org-chip');
    const allCards = () => root.querySelectorAll('.org-card');
    let activeFilter = 'all';
    let activeQuery = '';

    function applyFilter() {
      const q = activeQuery.toLowerCase().trim();
      allCards().forEach(card => {
        card.classList.remove('match','dimmed');
        const hay = card.dataset.search || '';
        const isOpen = card.dataset.open === '1';
        const inc = parseInt(card.dataset.incidents||'0', 10);
        const score = parseInt(card.dataset.score||'0', 10);
        let pass = true;
        if (activeFilter === 'open') pass = isOpen;
        else if (activeFilter === 'incidents') pass = inc > 0;
        else if (activeFilter === 'top') pass = score >= 85 && !isOpen;
        else if (activeFilter === 'attention') pass = (score < 65 || inc > 0) && !isOpen;
        if (q) {
          if (hay.includes(q)) { card.classList.add('match'); }
          else { pass = false; }
        }
        if (!pass) card.classList.add('dimmed');
      });
    }

    if (searchInput) searchInput.addEventListener('input', (e) => { activeQuery = e.target.value; applyFilter(); });
    filterButtons.forEach(btn => btn.addEventListener('click', () => {
      filterButtons.forEach(b => b.classList.remove('org-chip-active'));
      btn.classList.add('org-chip-active');
      activeFilter = btn.dataset.filter;
      applyFilter();
    }));

    window.__asaToggleCol = (btn) => {
      const col = btn.closest('.org-col');
      if (!col) return;
      const collapsed = col.classList.toggle('collapsed');
      btn.textContent = collapsed ? '+' : '−';
    };

    const collapseAllBtn = document.getElementById('orgCollapseAll');
    if (collapseAllBtn) collapseAllBtn.addEventListener('click', () => {
      const cols = root.querySelectorAll('.org-col');
      const anyOpen = Array.from(cols).some(c => !c.classList.contains('collapsed'));
      cols.forEach(c => {
        c.classList.toggle('collapsed', anyOpen);
        const t = c.querySelector('.org-col-toggle');
        if (t) t.textContent = anyOpen ? '+' : '−';
      });
      collapseAllBtn.textContent = anyOpen ? 'Expand all' : 'Collapse all';
    });

    // ===== Detail drawer =====
    const drawer = document.getElementById('orgDetailDrawer');
    window.__asaCloseOrgDetail = () => {
      if (!drawer) return;
      drawer.style.transform = 'translateX(100%)';
      setTimeout(() => { drawer.style.display = 'none'; }, 250);
    };
    window.__asaOpenOrgDetail = (el) => {
      const p = JSON.parse(decodeURIComponent(el.dataset.person||'%7B%7D'));
      const st = p._stats || {};
      window.__asaCurrentFlag = p;
      pop.style.display = 'none';
      // Count direct reports if this person is a manager
      const directReports = (org.supervisors||[]).filter(s => s.manager_id === p.supervisor_id);
      document.getElementById('orgDetailKicker').textContent =
        directReports.length ? `Department head · ${directReports.length} direct reports` :
        (p.area || 'Employee');
      document.getElementById('orgDetailName').textContent = p.name || '—';
      document.getElementById('orgDetailRole').textContent = (p.title_en || p.title_es || '') + (p.area ? ' · '+p.area : '');
      document.getElementById('orgDetailReports').textContent = p.supervisor_id ? ('ID: ' + p.supervisor_id) : '';
      const scoreColor = st.score >= 85 ? '#16a34a' : st.score >= 65 ? '#b45309' : '#b91c1c';
      document.getElementById('orgDetailScore').innerHTML = `
        <div style="font-size:42px;font-weight:800;color:${scoreColor};line-height:1">${st.score||'—'}</div>
        <div style="flex:1">
          <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--ink-dim);font-weight:700;margin-bottom:4px">Performance score</div>
          <div style="font-size:12px;color:var(--ink-2);line-height:1.5">${st.highlights||0} highlight${st.highlights===1?'':'s'} · ${st.incidents||0} incident${st.incidents===1?'':'s'}<br/>Base 75 +5/highlight −8/incident</div>
        </div>`;
      const hi = (st._hi||[]);
      const inc = (st._inc||[]);
      document.getElementById('orgDetailHighlights').innerHTML = `
        <h3 style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--ink-2);font-weight:700;margin:0 0 8px">👍 Recent highlights (${hi.length})</h3>
        ${hi.length === 0 ? `<p style="font-size:12px;color:var(--ink-dim);margin:0">None on file. Highlights appear when a supervisor cites this person positively in a daily report.</p>` :
          hi.slice(0,6).map(h => `<div style="background:#dcfce7;border-left:3px solid #16a34a;padding:8px 10px;border-radius:4px;font-size:12px;margin-bottom:6px;line-height:1.4"><strong>${escapeHtml(h.date||'')}</strong> · ${escapeHtml(h.note||h.description||'highlight')}</div>`).join('')}`;
      document.getElementById('orgDetailIncidents').innerHTML = `
        <h3 style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--ink-2);font-weight:700;margin:0 0 8px">⚠ Incidents on file (${inc.length})</h3>
        ${inc.length === 0 ? `<p style="font-size:12px;color:var(--ink-dim);margin:0">None on file. Clean record.</p>` :
          inc.slice(0,8).map(i => `<div style="background:#fff8eb;border-left:3px solid #b45309;padding:8px 10px;border-radius:4px;font-size:12px;margin-bottom:6px;line-height:1.4"><strong>${escapeHtml(i.date||'')}</strong> · ${escapeHtml(i.type||'incident')} ${i.article_88?`<span style="background:#b91c1c;color:#fff;font-size:10px;padding:1px 5px;border-radius:6px;margin-left:4px">Art ${escapeHtml(i.article_88)}</span>`:''}<br/><span style="color:var(--ink-dim)">${escapeHtml(i.description||i.note||'')}</span></div>`).join('')}`;
      const flagBtn = document.getElementById('orgDetailFlagBtn');
      if (flagBtn) flagBtn.onclick = () => { window.__asaCloseOrgDetail(); setTimeout(() => window.__asaOpenHRFlag(el), 280); };
      drawer.style.display = 'block';
      requestAnimationFrame(() => { drawer.style.transform = 'translateX(0)'; });
    };

    window.__asaShowOrgPop = (ev, el) => {
      const p = JSON.parse(decodeURIComponent(el.dataset.person||'%7B%7D'));
      const st = p._stats || {};
      const scoreColor = st.score >= 85 ? '#86efac' : st.score >= 65 ? '#fcd34d' : '#fca5a5';
      pop.innerHTML = `
        <div style="font-weight:800;font-size:14px;margin-bottom:2px">${escapeHtml(p.name||'')}</div>
        <div style="font-size:11px;opacity:.85;margin-bottom:8px;font-style:italic">${escapeHtml(p.title_en||p.title_es||'')}</div>
        <div style="display:flex;gap:10px;align-items:center;background:rgba(255,255,255,.1);padding:8px 10px;border-radius:6px;margin-bottom:8px">
          <div style="font-size:26px;font-weight:800;color:${scoreColor}">${st.score||'—'}</div>
          <div style="font-size:10px;line-height:1.4">
            <div>${st.highlights||0} highlight${st.highlights===1?'':'s'} 👍</div>
            <div>${st.incidents||0} incident${st.incidents===1?'':'s'} ⚠</div>
          </div>
        </div>
        <div style="font-size:10px;opacity:.7;line-height:1.5">
          <div><strong>Area:</strong> ${escapeHtml(p.area||p.title_en||'—')}</div>
          <div><strong>ID:</strong> ${escapeHtml(p.supervisor_id||'—')}</div>
        </div>
        <div style="font-size:10px;opacity:.7;margin-top:8px;text-align:center;border-top:1px solid rgba(255,255,255,.15);padding-top:6px">Click for HR actions</div>`;
      pop.style.display = 'block';
      window.__asaMoveOrgPop(ev);
    };
    window.__asaHideOrgPop = () => { pop.style.display = 'none'; };
    window.__asaMoveOrgPop = (ev) => {
      const x = ev.clientX + 14;
      const y = ev.clientY + 14;
      pop.style.left = Math.min(x, window.innerWidth - 300) + 'px';
      pop.style.top  = Math.min(y, window.innerHeight - 200) + 'px';
    };
    // Employee popover (lighter than supervisor popover)
    window.__asaShowEmpPop = (ev, el) => {
      const e = JSON.parse(decodeURIComponent(el.dataset.emp||'%7B%7D'));
      const st = e._stats || {};
      const scoreColor = st.score >= 85 ? '#86efac' : st.score >= 65 ? '#fcd34d' : '#fca5a5';
      pop.innerHTML = `
        <div style="font-weight:800;font-size:13px;margin-bottom:2px">${escapeHtml(e.name||'')}</div>
        <div style="font-size:10px;opacity:.85;margin-bottom:6px">${escapeHtml(e.puesto||'')} · ${escapeHtml(e.department||'')}</div>
        <div style="display:flex;gap:10px;align-items:center;background:rgba(255,255,255,.1);padding:6px 10px;border-radius:6px;margin-bottom:6px">
          <div style="font-size:22px;font-weight:800;color:${scoreColor}">${st.score||70}</div>
          <div style="font-size:10px;line-height:1.4">
            <div>${st.highlights||0} highlight${st.highlights===1?'':'s'} 👍</div>
            <div>${st.incidents||0} incident${st.incidents===1?'':'s'} ⚠</div>
            <div>${(e.notes||[]).length} admin note${(e.notes||[]).length===1?'':'s'} 📝</div>
          </div>
        </div>
        <div style="font-size:9px;opacity:.7">ID: ${escapeHtml(e.employee_id||'—')} · Code: ${escapeHtml(e.code||'')}</div>
        <div style="font-size:9px;opacity:.7;margin-top:6px;text-align:center;border-top:1px solid rgba(255,255,255,.15);padding-top:5px">Click to add note / view detail</div>`;
      pop.style.display = 'block';
      window.__asaMoveOrgPop(ev);
    };
    // Employee detail drawer (with notes)
    window.__asaOpenEmpDetail = (el) => {
      const e = JSON.parse(decodeURIComponent(el.dataset.emp||'%7B%7D'));
      window.__asaCurrentEmp = e;
      const st = e._stats || {};
      const scoreColor = st.score >= 85 ? '#16a34a' : st.score >= 65 ? '#b45309' : '#b91c1c';
      const modal = document.getElementById('empDetailModal');
      const body = document.getElementById('empDetailBody');
      body.innerHTML = `
        <div style="display:flex;gap:14px;align-items:center;padding:18px 22px;border-bottom:1px solid var(--line)">
          <div style="background:${scoreColor};color:#fff;font-size:24px;font-weight:800;padding:10px 16px;border-radius:10px;min-width:60px;text-align:center">${st.score||70}</div>
          <div style="flex:1">
            <h2 style="margin:0;font-size:20px">${escapeHtml(e.name||'')}</h2>
            <p style="margin:2px 0 0;color:var(--ink-dim);font-size:13px">${escapeHtml(e.puesto||'')}</p>
            <p style="margin:2px 0 0;font-size:11px;color:var(--ink-dim)"><strong>Dept:</strong> ${escapeHtml(e.department||'')} · <strong>ID:</strong> ${escapeHtml(e.employee_id||'')} · <strong>Code:</strong> ${escapeHtml(e.code||'')}</p>
          </div>
        </div>
        <div style="padding:18px 22px">
          <div style="display:flex;gap:14px;margin-bottom:18px">
            <div style="flex:1;background:#f0fdf4;padding:10px 12px;border-radius:6px;text-align:center">
              <div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-dim)">Highlights</div>
              <div style="font-size:22px;font-weight:800;color:#16a34a">${st.highlights||0}</div>
            </div>
            <div style="flex:1;background:#fff3f3;padding:10px 12px;border-radius:6px;text-align:center">
              <div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-dim)">Incidents</div>
              <div style="font-size:22px;font-weight:800;color:#b91c1c">${st.incidents||0}</div>
            </div>
            <div style="flex:1;background:#eff6ff;padding:10px 12px;border-radius:6px;text-align:center">
              <div style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-dim)">Admin notes</div>
              <div style="font-size:22px;font-weight:800;color:#0a3d62">${(e.notes||[]).length}</div>
            </div>
          </div>
          <h3 style="font-size:13px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-2);margin:0 0 10px">Admin Notes (chronological)</h3>
          <div id="empNotesList" style="max-height:240px;overflow-y:auto;background:#f8fafc;border:1px solid var(--line);border-radius:6px;padding:10px;margin-bottom:14px">
            ${(e.notes||[]).length === 0 ? `<p style="margin:0;color:var(--ink-dim);font-size:12px;text-align:center;padding:14px">No notes yet. Tap a quick log below or write one.</p>` :
              (e.notes||[]).slice().reverse().map(n => `
                <div style="background:#fff;border-left:3px solid #0a3d62;padding:8px 10px;border-radius:4px;margin-bottom:6px;font-size:12px">
                  <div style="font-size:9px;color:var(--ink-dim);margin-bottom:3px"><strong>${escapeHtml(n.author||'admin')}</strong> · ${escapeHtml(n.date||'')}</div>
                  <div>${escapeHtml(n.text||'')}</div>
                </div>`).join('')
            }
          </div>
          <div style="font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--ink-dim);margin-bottom:8px">Quick log — tap one, add detail, save</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
            ${[
              ['👍 Great work','#16a34a','Great work today — '],
              ['✅ Quality catch','#16a34a','Caught a quality issue — '],
              ['💪 Extra effort','#16a34a','Went above and beyond — '],
              ['⏰ Late','#b45309','Arrived late — time: __:__ — '],
              ['🚪 Left early','#b45309','Left early — time: __:__ — '],
              ['❌ Absent','#b91c1c','Absent without notice — '],
              ['🔧 Needs training','#0a3d62','Needs training on — '],
              ['⚠ Behavior issue','#b91c1c','Behavior issue — witnesses: — '],
            ].map(([label,color,tmpl]) => `<button type="button" class="emp-quick" data-tmpl="${escapeHtml(tmpl)}"
                style="background:#fff;border:1px solid ${color};color:${color};border-radius:14px;padding:5px 11px;font-size:12px;font-weight:600;cursor:pointer">${escapeHtml(label)}</button>`).join('')}
          </div>
          <textarea id="empNewNote" rows="3" placeholder="Tap a quick-log button above (then add the detail), or type a note from scratch. Timestamped and saved to this person's record for the AI to read." style="width:100%;background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:13px;resize:vertical;margin-bottom:10px"></textarea>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="btn btn-ghost btn-sm" onclick="document.getElementById('empDetailModal').style.display='none'">Close</button>
            <button id="empNoteSubmit" class="btn btn-primary btn-sm">💾 Save note</button>
          </div>
          <p id="empNoteStatus" style="font-size:11px;color:var(--ink-dim);margin:6px 0 0;text-align:right"></p>
        </div>`;
      modal.style.display = 'flex';
      pop.style.display = 'none';
      // Quick-log chips: prefill the note box with a starter phrase + focus, so a
      // floor manager can log a floor event in two taps.
      modal.querySelectorAll('.emp-quick').forEach(b => b.onclick = () => {
        const ta = document.getElementById('empNewNote');
        const tmpl = b.dataset.tmpl || '';
        ta.value = (ta.value.trim() ? ta.value.trim() + '\n' : '') + tmpl;
        ta.focus();
        ta.setSelectionRange(ta.value.length, ta.value.length);
      });
      document.getElementById('empNoteSubmit').onclick = async () => {
        const status = document.getElementById('empNoteStatus');
        const text = document.getElementById('empNewNote').value.trim();
        if (!text) { status.style.color='var(--red)'; status.textContent='Note text required.'; return; }
        const tok = localStorage.getItem('asa_github_token') || (typeof SHARED_GH_TOKEN !== 'undefined' ? SHARED_GH_TOKEN : null);
        if (!tok) { status.style.color='var(--red)'; status.textContent='No upload key.'; return; }
        status.style.color='var(--ink-dim)'; status.textContent='Saving…';
        const noteId = `note_${e.employee_id}_${Date.now()}`;
        const payload = {
          id: noteId,
          employee_id: e.employee_id,
          employee_name: e.name,
          author: SESSION.username || 'admin',
          date: new Date().toISOString(),
          text: text,
        };
        const path = `uploads/employees/notes/${noteId}.json`;
        try {
          const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${path}`, {
            method:'PUT', headers:{'Authorization':`Bearer ${tok}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'},
            body: JSON.stringify({ message:`Admin note · ${e.name}`, content: btoa(unescape(encodeURIComponent(JSON.stringify(payload,null,2)))), branch:'main' })
          });
          if (!r.ok) throw new Error('GitHub '+r.status);
          status.style.color='#16a34a'; status.textContent='✓ Saved — appears within 15 min after cron pass.';
          showToast(`Note saved on ${e.name}`,'success');
          document.getElementById('empNewNote').value='';
        } catch (err) {
          status.style.color='var(--red)'; status.textContent='✗ '+(err.message||'save failed');
        }
      };
    };
    window.__asaCurrentFlag = null;
    window.__asaOpenHRFlag = (el) => {
      const p = JSON.parse(decodeURIComponent(el.dataset.person||'%7B%7D'));
      window.__asaCurrentFlag = p;
      const st = p._stats || {};
      document.getElementById('hrFlagName').textContent = p.name || '—';
      document.getElementById('hrFlagRole').textContent = (p.title_en || p.title_es || '') + (p.area ? ' · '+p.area : '');
      const ev = document.getElementById('hrFlagEvidence');
      if (st.incidents > 0 || st.highlights > 0) {
        ev.innerHTML = `<strong>Evidence on file:</strong> ${st.incidents} documented incident${st.incidents===1?'':'s'} and ${st.highlights} positive highlight${st.highlights===1?'':'s'}. Current score: <strong>${st.score}</strong>. Agent will pull these into the Article 88 package.`;
      } else {
        ev.innerHTML = `<strong>⚠ No incidents on file yet for this person.</strong> If you submit, the agent will produce a <em>documentation-gap report</em> noting what evidence is needed before a termination meets DR Article 88 standards — it will not fabricate evidence.`;
      }
      document.getElementById('hrFlagReason').value = '';
      document.getElementById('hrFlagNotes').value = '';
      document.getElementById('hrFlagStatus').textContent = '';
      document.getElementById('hrFlagModal').style.display = 'flex';
      pop.style.display = 'none';
    };
    const submitBtn = document.getElementById('hrFlagSubmit');
    if (submitBtn) submitBtn.addEventListener('click', async () => {
      const status = document.getElementById('hrFlagStatus');
      const p = window.__asaCurrentFlag;
      if (!p) return;
      const reason = document.getElementById('hrFlagReason').value;
      const notes  = document.getElementById('hrFlagNotes').value.trim();
      if (!reason) { status.style.color='var(--red)'; status.textContent='Select an Article 88 ground.'; return; }
      if (!notes)  { status.style.color='var(--red)'; status.textContent='Add a summary for the HR file.'; return; }
      const tok = localStorage.getItem('asa_github_token') || (typeof SHARED_GH_TOKEN !== 'undefined' ? SHARED_GH_TOKEN : null);
      if (!tok) { status.style.color='var(--red)'; status.textContent='No upload key — unlock on the upload page first.'; return; }
      status.style.color='var(--ink-dim)'; status.textContent='Submitting…'; submitBtn.disabled = true;
      const requestId = `term_${(p.supervisor_id||p.name).replace(/[^a-zA-Z0-9_-]/g,'_')}_${Date.now()}`;
      const payload = {
        id: requestId,
        requested_at: new Date().toISOString(),
        requested_by: SESSION.username || 'unknown',
        person: { supervisor_id: p.supervisor_id, name: p.name, title_es: p.title_es, title_en: p.title_en, area: p.area },
        dr_ground: reason,
        summary: notes,
        status: 'pending_agent_review',
        ai_action: 'On the next loop pass, scripts/process_termination_requests.py will (1) look up all incidents in employees.incidents[] for this person, (2) validate they meet DR Article 88 threshold for the cited ground, (3a) if yes, generate the full Article 88 termination package (Carta de Desahucio + Comunicación al Ministerio de Trabajo + Liquidación checklist) into outputs/hr_packages/<requestId>/, OR (3b) if no, generate a documentation-gap report listing exactly what evidence is missing.'
      };
      const path = `uploads/employees/termination_requests/${requestId}.json`;
      try {
        const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${path}`, {
          method:'PUT',
          headers:{'Authorization':`Bearer ${tok}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'},
          body: JSON.stringify({ message:`HR termination request: ${p.name} (Art. ${reason})`, content: btoa(unescape(encodeURIComponent(JSON.stringify(payload,null,2)))), branch:'main' })
        });
        if (!r.ok) throw new Error('GitHub '+r.status);
        status.style.color='#16a34a'; status.textContent='✓ Submitted — agent will process on next loop pass (within 15 min).';
        showToast(`HR termination request flagged for ${p.name}. Agent will assemble docs on next pass.`,'info');
        setTimeout(()=>{ document.getElementById('hrFlagModal').style.display='none'; }, 2000);
      } catch (e) {
        status.style.color='var(--red)'; status.textContent='✗ '+(e.message||'submit failed');
      } finally { submitBtn.disabled=false; }
    });
  })();

  // Operation-notes submit — free-text floor log the AI ingests each pass.
  const opsSave = document.getElementById('opsNoteSave');
  if (opsSave) opsSave.addEventListener('click', async () => {
    const status = document.getElementById('opsNoteStatus');
    const text = (document.getElementById('opsNoteText').value || '').trim();
    if (!text) { status.style.color='var(--red)'; status.textContent='Type a note first.'; return; }
    const tok = localStorage.getItem('asa_github_token');
    if (!tok) { status.style.color='var(--red)'; status.textContent='Upload key locked — sign out and back in to unlock.'; return; }
    status.style.color='var(--ink-dim)'; status.textContent='Saving…';
    const id = `ops_${Date.now()}`;
    const payload = { id, author: SESSION.username || 'admin', date: new Date().toISOString(), text };
    const path = `uploads/employees/ops-notes/${id}.json`;
    try {
      const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${path}`, {
        method:'PUT', headers:{'Authorization':`Bearer ${tok}`,'Accept':'application/vnd.github+json','Content-Type':'application/json'},
        body: JSON.stringify({ message:`Operation note · ${SESSION.username||'admin'}`, content: btoa(unescape(encodeURIComponent(JSON.stringify(payload,null,2)))), branch:'main' })
      });
      if (!r.ok) throw new Error('GitHub '+r.status);
      status.style.color='#16a34a'; status.textContent='✓ Saved — the AI reads it on the next pass (~15 min).';
      showToast('Operation note saved for the AI','success');
      document.getElementById('opsNoteText').value='';
    } catch (err) {
      status.style.color='var(--red)'; status.textContent='✗ '+(err.message||'save failed');
    }
  });

  // Daily report submit — writes JSON file to uploads/employees/reports/ via GitHub PAT
  const drSubmit = document.getElementById('drSubmitBtn');
  if (drSubmit) drSubmit.addEventListener('click', async () => {
    const status = document.getElementById('drStatus');
    const area = document.getElementById('drArea').value;
    const date = document.getElementById('drDate').value;
    const supName = document.getElementById('drSupName').value.trim();
    const completed = document.getElementById('drCompleted').value.trim();
    const delays = document.getElementById('drDelays').value.trim();
    const highlights = document.getElementById('drHighlights').value.trim();
    const incidents = document.getElementById('drIncidents').value.trim();
    if (!area || !date) { status.style.color='var(--red)'; status.textContent='Pick an area and a date.'; return; }
    if (!completed && !delays && !highlights && !incidents) { status.style.color='var(--red)'; status.textContent='Fill at least one section before submitting.'; return; }
    const tok = localStorage.getItem('asa_github_token') || (typeof SHARED_GH_TOKEN !== 'undefined' ? SHARED_GH_TOKEN : null);
    if (!tok) { status.style.color='var(--red)'; status.textContent='No upload key — unlock token on the upload page first.'; return; }
    status.style.color='var(--ink-dim)'; status.textContent='Submitting…'; drSubmit.disabled = true;
    const reportId = `${date}_${area.replace(/[^a-zA-Z0-9_-]/g,'_')}_${Date.now()}`;
    const payload = {
      id: reportId,
      date, area, supervisor_id: area.startsWith('SUP-')?area:null, supervisor_name: supName,
      submitted_at: new Date().toISOString(),
      submitted_by: SESSION.username || 'unknown',
      completed, delays, highlights, incidents,
    };
    const path = `uploads/employees/reports/${reportId}.json`;
    try {
      const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${path}`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${tok}`, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: `Daily report ${date} · ${area} · ${supName}`, content: btoa(unescape(encodeURIComponent(JSON.stringify(payload,null,2)))), branch: 'main' })
      });
      if (!r.ok) throw new Error('GitHub ' + r.status);
      status.style.color='#16a34a'; status.textContent='✓ Submitted — scoreboard will update within 15 min.';
      showToast('Daily report submitted','success');
      ['drCompleted','drDelays','drHighlights','drIncidents'].forEach(id => document.getElementById(id).value = '');
    } catch (e) {
      status.style.color='var(--red)'; status.textContent='✗ ' + (e.message || 'submit failed');
    } finally { drSubmit.disabled = false; }
  });
}

function renderAICoaching(root) {
  const coach = (MOCK.production && MOCK.production.aiCoaching) || {observations:[],executiveSummary:'No coaching analysis yet — run the next loop pass.',briefing:'',priorityDecisions:[],themes:[]};
  const sevColor = (s) => s==='red'?'#b91c1c':s==='amber'?'#b45309':s==='green'?'#16a34a':'#1c5b8a';
  const sevBg = (s) => s==='red'?'#fff3f3':s==='amber'?'#fff8eb':s==='green'?'#f0fdf4':'#eff6ff';
  const sevIcon = (s) => s==='red'?'⛔':s==='amber'?'⚠️':s==='green'?'✓':'ℹ️';
  const sevLabel = (s) => s==='red'?'Action Required':s==='amber'?'Watch':s==='green'?'On Track':'Needs Data';
  const generated = coach.generated ? new Date(coach.generated).toLocaleString() : '—';

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">AI Coaching</p>
        <h1>Strategic operating brief</h1>
        <p>Synthesized from every uploaded file — receivables, payables, WIP, shipping, forecasts, inventory, capacity. Reads like a memo from a senior operating partner. Refreshed every loop pass · Generated ${escapeHtml(generated)}.</p>
      </div>
    </div>

    <!-- LEADER BRIEFING -->
    <div class="panel" style="background:linear-gradient(135deg,#0a3d62 0%,#1c5b8a 100%);color:#fff;padding:28px;margin-bottom:18px">
      <p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;margin:0 0 12px;opacity:.7">Briefing · The CEO Read</p>
      <p style="font-size:16px;line-height:1.7;margin:0 0 14px;font-weight:400">${escapeHtml(coach.briefing||coach.executiveSummary||'')}</p>
      <div style="background:rgba(255,255,255,.08);border-left:3px solid #cfe6f5;padding:12px 16px;border-radius:4px;font-size:13px;line-height:1.5;opacity:.9">
        <strong style="letter-spacing:1px;text-transform:uppercase;font-size:10px;opacity:.7">Snapshot</strong><br/>
        ${escapeHtml(coach.executiveSummary||'')}
      </div>
    </div>

    <!-- BIGGEST PROBLEM (THIS WEEK) -->
    ${(coach.thisWeek && coach.thisWeek.biggestProblem) ? `
    <div class="panel" style="background:#fff3f3;border-left:6px solid #b91c1c;padding:22px 26px;margin-bottom:18px">
      <p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;margin:0 0 6px;color:#b91c1c;font-weight:800">⛔ Biggest Problem This Week</p>
      <h2 style="margin:0 0 8px;color:#b91c1c;font-size:22px">${escapeHtml(coach.thisWeek.biggestProblem.area)}: ${escapeHtml(coach.thisWeek.biggestProblem.finding)}</h2>
      ${(coach.thisWeek.problems||[]).slice(1).map(p => `<p style="margin:6px 0 0;font-size:13px;color:#1a1a1a"><strong style="color:${p.severity==='red'?'#b91c1c':'#b45309'}">${p.severity==='red'?'⛔':'⚠️'} ${escapeHtml(p.area)}:</strong> ${escapeHtml(p.finding)}</p>`).join('')}
    </div>` : ''}

    <!-- THIS WEEK BY CUSTOMER -->
    ${(coach.thisWeek) ? `
    <div class="panel" style="margin-bottom:18px">
      <div class="panel-head"><h2>This week by customer — production, shipping, receivables</h2><span class="panel-meta">week ending ${escapeHtml(coach.thisWeek.weekEnding||'—')}</span></div>
      <div style="overflow-x:auto">
        <table style="min-width:900px">
          <thead><tr>
            <th>Customer</th>
            <th style="text-align:right">Shipped (units)</th>
            <th style="text-align:right">Planned</th>
            <th style="text-align:right">Remaining</th>
            <th style="text-align:right">% complete</th>
            <th style="text-align:right">A/R open</th>
            <th style="text-align:right">A/R past due</th>
            <th style="text-align:right">WIP late ($)</th>
          </tr></thead>
          <tbody>${(() => {
            const sh = coach.thisWeek.shipping || [];
            const rec = coach.thisWeek.receivables || [];
            const wip = coach.thisWeek.wip || [];
            // Union of customer names across the three
            const norm = (s) => String(s||'').toLowerCase().replace(/[^a-z0-9]/g,'').replace(/llc|inc|sportinggoodsco|sporting|goods|co|sportswear/g,'');
            const lookup = (arr, c) => arr.find(x => norm(x.customer) === norm(c));
            const allCusts = new Set();
            sh.forEach(x => allCusts.add(x.customer));
            rec.forEach(x => allCusts.add(x.customer));
            wip.forEach(x => allCusts.add(x.customer));
            const rows = [...allCusts].map(c => {
              const s = lookup(sh, c) || {};
              const r = lookup(rec, c) || {};
              const w = lookup(wip, c) || {};
              return { customer:c, s, r, w };
            }).sort((a,b) => (b.r.open||0) + (b.w.lateUsd||0) - ((a.r.open||0) + (a.w.lateUsd||0)));
            if (rows.length === 0) return `<tr><td colspan="8" style="text-align:center;color:var(--ink-dim);padding:24px">Awaiting next loop pass.</td></tr>`;
            return rows.map(({customer,s,r,w}) => {
              const pct = s.planned > 0 ? Math.round((s.units/s.planned)*100) : null;
              const pctTag = pct == null ? '—' : `<span class="tag tag-${pct>=95?'good':pct>=70?'warn':'bad'}">${pct}%</span>`;
              return `<tr>
                <td><strong>${escapeHtml(customer)}</strong></td>
                <td style="text-align:right">${fmtNum(s.units||0)}</td>
                <td style="text-align:right;color:var(--ink-dim)">${fmtNum(s.planned||0)}</td>
                <td style="text-align:right;color:${(s.remaining||0)>0?'#b91c1c':'inherit'};font-weight:${(s.remaining||0)>0?'700':'400'}">${fmtNum(s.remaining||0)}</td>
                <td style="text-align:right">${pctTag}</td>
                <td style="text-align:right">${fmtMoney(r.open||0)}</td>
                <td style="text-align:right;color:${(r.past||0)>0?'#b91c1c':'inherit'};font-weight:${(r.past||0)>0?'700':'400'}">${fmtMoney(r.past||0)}</td>
                <td style="text-align:right;color:${(w.lateUsd||0)>0?'#b91c1c':'inherit'};font-weight:${(w.lateUsd||0)>0?'700':'400'}">${fmtMoney(w.lateUsd||0)}</td>
              </tr>`;
            }).join('');
          })()}</tbody>
        </table>
      </div>
    </div>` : ''}

    <!-- PRIORITY DECISIONS -->
    ${(coach.priorityDecisions||[]).length ? `
    <div class="panel" style="margin-bottom:18px">
      <div class="panel-head"><h2>Priority decisions this week</h2><span class="panel-meta">${(coach.priorityDecisions||[]).length} decision${(coach.priorityDecisions||[]).length===1?'':'s'} needing CEO/owner attention</span></div>
      <div style="padding:0 4px 12px">
        ${(coach.priorityDecisions||[]).map((dc,i) => `
          <div style="padding:18px 22px;border-bottom:1px solid var(--line);display:grid;grid-template-columns:auto 1fr;gap:18px;align-items:start">
            <div style="font-size:28px;font-weight:800;color:#0a3d62;line-height:1;min-width:48px;text-align:center">
              ${i+1}
            </div>
            <div>
              <h3 style="margin:0 0 6px;font-size:16px;color:#0a3d62">${escapeHtml(dc.title||'')}</h3>
              <p style="margin:0 0 10px;font-size:13px;color:var(--ink);line-height:1.6"><strong style="color:var(--ink-dim);text-transform:uppercase;font-size:10px;letter-spacing:1px">Situation:</strong> ${escapeHtml(dc.rationale||'')}</p>
              <p style="margin:0;font-size:14px;line-height:1.6;font-weight:500;color:#0a3d62"><span style="color:var(--ink-dim);text-transform:uppercase;font-size:10px;letter-spacing:1px;font-weight:600">Decision needed → </span>${escapeHtml(dc.decision_needed||'')}</p>
            </div>
          </div>
        `).join('')}
      </div>
    </div>` : ''}

    <!-- STRATEGIC THEMES -->
    ${(coach.themes||[]).length ? `
    <div class="panel" style="margin-bottom:18px">
      <div class="panel-head"><h2>Strategic lenses</h2><span class="panel-meta">three views into the business this week</span></div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:0;padding:0">
        ${(coach.themes||[]).map((t,i) => `
          <div style="padding:22px;border-right:${i<(coach.themes||[]).length-1?'1px solid var(--line)':'none'};border-bottom:1px solid var(--line)">
            <p style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--ink-dim);margin:0 0 4px;font-weight:700">Theme ${i+1}</p>
            <h3 style="margin:0 0 10px;font-size:17px;color:#0a3d62">${escapeHtml(t.name||'')}</h3>
            <p style="font-size:13px;font-weight:600;color:#b45309;margin:0 0 14px;font-style:italic;border-left:3px solid #b45309;padding-left:10px">${escapeHtml(t.one_liner||'')}</p>
            ${(t.insights||[]).map(s => `<p style="font-size:13px;line-height:1.6;margin:0 0 12px;color:var(--ink)">${escapeHtml(s)}</p>`).join('')}
          </div>
        `).join('')}
      </div>
    </div>` : ''}

    <!-- DETAIL: OBSERVATIONS -->
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-head"><h2>Operational observations — detail</h2><span class="panel-meta">10 areas of the business · color-coded severity</span></div>
    </div>
    ${(coach.observations||[]).map(o => `
      <div class="panel" style="border-left:5px solid ${sevColor(o.severity)};background:${sevBg(o.severity)};margin-bottom:12px">
        <div class="panel-head" style="background:transparent;border-bottom:1px solid rgba(0,0,0,.06)">
          <h2 style="display:flex;align-items:center;gap:10px;font-size:16px"><span style="font-size:20px">${sevIcon(o.severity)}</span>${escapeHtml(o.topic)}</h2>
          <span class="panel-meta" style="color:${sevColor(o.severity)};font-weight:700;text-transform:uppercase;letter-spacing:1px;font-size:10px">${sevLabel(o.severity)}</span>
        </div>
        <div style="padding:14px 22px">
          <p style="margin:0 0 8px;font-size:13px;line-height:1.6;color:#1a1a1a"><strong>What's happening:</strong> ${escapeHtml(o.finding||'')}</p>
          <p style="margin:0;font-size:13px;line-height:1.6;color:#1a1a1a"><strong>Recommended action:</strong> ${escapeHtml(o.action||'')}</p>
        </div>
      </div>
    `).join('')}

    <div class="panel" style="background:#f8fafc">
      <div class="panel-head"><h2>How this brief is generated</h2></div>
      <div style="padding:14px 22px;font-size:12px;color:var(--ink);line-height:1.6">
        <p style="margin:0 0 8px">Every loop pass (15 min) this brief is regenerated from <code>admin/data.json</code> via <code>scripts/generate_ai_coaching.py</code>. It synthesizes A/R, A/P, WIP, shipping, forecasts, inventory, and capacity into a strategic memo, then ranks 3–5 priority decisions and writes detail across 3 strategic themes and 10 operational areas.</p>
        <p style="margin:0"><strong>Severity legend:</strong> <span style="color:#b91c1c;font-weight:700">⛔ red = act today</span> · <span style="color:#b45309;font-weight:700">⚠️ amber = watch this week</span> · <span style="color:#16a34a;font-weight:700">✓ green = on track</span> · <span style="color:#1c5b8a;font-weight:700">ℹ️ blue = need more data</span></p>
      </div>
    </div>
  `;
}

function renderExecutiveOps(root) {
  const bench = MOCK.production && MOCK.production.capacityBenchmark || {};
  const weekly = bench.weekly_data || [];
  const wkRange = weekly.slice(-13);
  const wip = MOCK.production.wip || [];
  const ytdByCust = (MOCK.finance && MOCK.finance.shippedByCustomer) || [];
  const fva = (MOCK.production && MOCK.production.forecastVsActual) || {};
  const byCust = fva.ytdByCustomer || {};
  const today = new Date();   // real today — late-day math must not go stale
  const target = bench.targetPct || 70;
  const cap = bench.weekly || 12000;
  const fmtP = (p) => p == null ? '<span style="color:var(--ink-dim)">—</span>' : p >= 95 ? `<span class="tag tag-good">${p}%</span>` : p >= 80 ? `<span class="tag tag-warn">${p}%</span>` : `<span class="tag tag-bad">${p}%</span>`;

  // Section 1: Weekly Production Performance — 13 weeks
  // Open balance per week = cumulative (Planned - Shipped) running total
  let runningOpen = 0;
  const prodRows = wkRange.map(w => {
    const planned = w.plannedUnits || 0;
    const shipped = w.units || 0;
    // Produced ≈ Shipped (no separate production log feed); flag this
    const produced = shipped;
    runningOpen += (planned - shipped);
    return {
      week: w.label,
      planned, produced, shipped,
      openBalance: Math.max(0, Math.round(runningOpen)),
      pct: planned > 0 ? Math.round(shipped/planned*100) : null
    };
  });

  // Section 2: By Customer YTD (Plan vs Actual)
  const custKeys = Object.keys(byCust).filter(k => k !== 'All' && byCust[k] && (byCust[k].forecastUnits || byCust[k].actualUnits)).sort((a,b)=> (byCust[b].forecastUnits||0)-(byCust[a].forecastUnits||0));
  const custRows = custKeys.map(c => {
    const v = byCust[c];
    const pct = v.forecastUnits > 0 ? Math.round(v.actualUnits/v.forecastUnits*100) : null;
    return { customer: c, plan: v.forecastUnits || 0, actual: v.actualUnits || 0, planUSD: v.forecastUSD || 0, actualUSD: v.actualUSD || 0, pct };
  });
  const custTotPlan = custRows.reduce((s,r)=>s+r.plan,0);
  const custTotAct = custRows.reduce((s,r)=>s+r.actual,0);
  const custTotPlanD = custRows.reduce((s,r)=>s+r.planUSD,0);
  const custTotActD = custRows.reduce((s,r)=>s+r.actualUSD,0);
  const custTotPct = custTotPlan ? Math.round(custTotAct/custTotPlan*100) : null;

  // Section 3: Capacity Utilization — Week / Capacity / Scheduled / Actual
  const capRows = wkRange.map(w => ({
    week: w.label,
    capacity: cap,
    scheduled: w.plannedUnits || 0,
    actual: w.units || 0,
    schedPct: cap ? Math.round((w.plannedUnits||0)/cap*100) : 0,
    actPct: cap ? Math.round((w.units||0)/cap*100) : 0,
  }));

  // Section 4: Delay Tracking — Program / Original Ship / Status / Delay
  const delays = wip.map(w => {
    let delay = null;
    if (w.reqDate && w.reqDate !== '—') {
      const reqD = new Date(w.reqDate);
      if (!isNaN(reqD)) delay = Math.round((today - reqD) / (1000*60*60*24));
    }
    return {
      customer: w.customer || '',
      program: w.program || '',
      promised: w.promised || 0,
      reqDate: w.reqDate,
      delay,
      status: w.status || 'good',
    };
  }).sort((a,b) => (b.delay||-9999) - (a.delay||-9999));
  const latePrograms = delays.filter(d => d.delay !== null && d.delay > 0);
  const lateTotalUnits = latePrograms.reduce((s,d)=>s+d.promised,0);

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">On-Time Delivery</p>
        <h1>On-time delivery & production performance</h1>
        <p>On-time delivery performance by customer, weekly production, plan vs actual, and delay tracking. (Per-customer on-time scoring expands once the delivery-performance file is loaded.)</p>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">13-wk plan attainment</div><div class="kpi-value" style="color:${custTotPct>=95?'#16a34a':custTotPct>=80?'#b45309':'#b91c1c'}">${custTotPct!=null?custTotPct+'%':'—'}</div><div class="kpi-delta flat">${fmtNum(custTotAct)} / ${fmtNum(custTotPlan)} units (YTD)</div></div>
      <div class="kpi"><div class="kpi-label">Open balance (cumulative)</div><div class="kpi-value">${fmtNum(prodRows[prodRows.length-1]?.openBalance || 0)}</div><div class="kpi-delta flat">units owed: plan − shipped</div></div>
      <div class="kpi"><div class="kpi-label">Late programs</div><div class="kpi-value" style="color:${latePrograms.length?'#b91c1c':'inherit'}">${latePrograms.length}</div><div class="kpi-delta flat">${fmtNum(lateTotalUnits)} units past req date</div></div>
      <div class="kpi"><div class="kpi-label">Capacity used (current wk)</div><div class="kpi-value" style="color:${(wkRange[wkRange.length-1]?.utilization||0)>=target?'#16a34a':(wkRange[wkRange.length-1]?.utilization||0)>=target*0.8?'#b45309':'#b91c1c'}">${(wkRange[wkRange.length-1]?.utilization||0).toFixed(1)}%</div><div class="kpi-delta flat">target ${target}%</div></div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>1. Weekly Production Performance</h2><span class="panel-meta">Week · Planned · Produced · Shipped · Open Balance</span></div>
      <div style="overflow-x:auto">
      <table>
        <thead><tr><th>Week ending</th><th>Planned</th><th>Produced</th><th>Shipped</th><th>% to plan</th><th>Open balance (cum.)</th></tr></thead>
        <tbody>${prodRows.map(r => `<tr>
          <td><strong>${escapeHtml(r.week)}</strong></td>
          <td>${fmtNum(r.planned)}</td>
          <td>${fmtNum(r.produced)}</td>
          <td>${fmtNum(r.shipped)}</td>
          <td>${fmtP(r.pct)}</td>
          <td style="color:${r.openBalance>15000?'#b91c1c':r.openBalance>5000?'#b45309':'inherit'};font-weight:600">${fmtNum(r.openBalance)}</td>
        </tr>`).join('')}</tbody>
      </table>
      </div>
      <p style="font-size:11px;color:var(--ink-dim);margin:8px 0 0">Produced = shipped (proxy — no separate production-line completion feed yet). Open Balance = running cumulative Planned − Shipped from start of window.</p>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>2. By Customer — Plan vs Actual (YTD)</h2><span class="panel-meta">${custRows.length} customer${custRows.length===1?'':'s'} · forecast = ASA_Sales_Tracker · actual = SHIPPINGREPORT</span></div>
      <div style="overflow-x:auto">
      <table>
        <thead><tr><th>Customer</th><th>Plan (units)</th><th>Actual (units)</th><th>% to plan</th><th>Plan US$</th><th>Actual US$</th><th>% US$</th></tr></thead>
        <tbody>${custRows.map(r => `<tr>
          <td><strong>${escapeHtml(r.customer)}</strong></td>
          <td>${fmtNum(r.plan)}</td>
          <td>${fmtNum(r.actual)}</td>
          <td>${fmtP(r.pct)}</td>
          <td>${fmtMoney(r.planUSD)}</td>
          <td>${fmtMoney(r.actualUSD)}</td>
          <td>${fmtP(r.planUSD>0?Math.round(r.actualUSD/r.planUSD*100):null)}</td>
        </tr>`).join('')}
        <tr style="background:#f8fafc;font-weight:700">
          <td>TOTAL</td>
          <td>${fmtNum(custTotPlan)}</td>
          <td>${fmtNum(custTotAct)}</td>
          <td>${fmtP(custTotPct)}</td>
          <td>${fmtMoney(custTotPlanD)}</td>
          <td>${fmtMoney(custTotActD)}</td>
          <td>${fmtP(custTotPlanD>0?Math.round(custTotActD/custTotPlanD*100):null)}</td>
        </tr>
        </tbody>
      </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>3. Capacity Utilization</h2><span class="panel-meta">Capacity = ${fmtNum(cap)} units/wk · Target ${target}% = ${fmtNum(Math.round(cap*target/100))} units/wk</span></div>
      <div style="overflow-x:auto">
      <table>
        <thead><tr><th>Week ending</th><th>Capacity</th><th>Scheduled</th><th>% sched</th><th>Actual</th><th>% actual</th><th>vs Target</th></tr></thead>
        <tbody>${capRows.map(r => `<tr>
          <td><strong>${escapeHtml(r.week)}</strong></td>
          <td>${fmtNum(r.capacity)}</td>
          <td>${fmtNum(r.scheduled)}</td>
          <td>${fmtP(r.schedPct)}</td>
          <td>${fmtNum(r.actual)}</td>
          <td>${fmtP(r.actPct)}</td>
          <td style="font-weight:600;color:${r.actPct-target>=0?'#16a34a':r.actPct-target>=-15?'#b45309':'#b91c1c'}">${r.actPct-target>=0?'+':''}${r.actPct-target}pp</td>
        </tr>`).join('')}</tbody>
      </table>
      </div>
    </div>

    <div class="panel" ${latePrograms.length?'style="border-left:4px solid #b91c1c"':''}>
      <div class="panel-head"><h2 ${latePrograms.length?'style="color:#b91c1c"':''}>4. Delay Tracking — programs past their req date</h2><span class="panel-meta">${latePrograms.length} late · ${fmtNum(lateTotalUnits)} units overdue · ${wip.length} total open programs</span></div>
      <div style="overflow-x:auto;max-height:560px;overflow-y:auto">
      <table>
        <thead><tr><th>Customer</th><th>Program</th><th>Units</th><th>Original ship date</th><th>Days late / remain</th><th>Status</th></tr></thead>
        <tbody>${delays.map(d => {
          const delayLabel = d.delay==null ? '<span style="color:var(--ink-dim)">—</span>' : d.delay>0 ? `<span class="tag tag-bad">${d.delay}d late</span>` : `<span style="color:var(--ink-dim);font-size:12px">${-d.delay}d remain</span>`;
          return `<tr>
            <td><strong>${escapeHtml(d.customer)}</strong></td>
            <td>${escapeHtml(d.program)}</td>
            <td>${fmtNum(d.promised)}</td>
            <td style="font-size:11px">${escapeHtml(d.reqDate||'—')}</td>
            <td>${delayLabel}</td>
            <td><span class="tag tag-${d.status}">${d.status==='good'?'On track':d.status==='warn'?'Watch':'At risk'}</span></td>
          </tr>`;
        }).join('')}</tbody>
      </table>
      </div>
    </div>

    <div class="panel" style="background:#f8fafc">
      <div class="panel-head"><h2>Executive read</h2></div>
      <ul style="font-size:14px;line-height:1.7;margin:0;padding:0 0 0 20px">
        <li><strong>Forecast accuracy:</strong> YTD attainment at <strong>${custTotPct!=null?custTotPct+'%':'—'}</strong> of plan (units). Customers with biggest variance shown above.</li>
        <li><strong>Factory throughput:</strong> ${fmtNum((bench.ytd&&bench.ytd.utilization)||0)}% YTD util vs ${target}% target = ${((bench.ytd&&bench.ytd.vsTarget)||0).toFixed(1)}pp ${((bench.ytd&&bench.ytd.vsTarget)||0)>=0?'above':'below'}.</li>
        <li><strong>Capacity gap:</strong> ${prodRows.filter(r=>r.openBalance>0).length} of last 13 weeks ended with units owed. Latest cumulative open balance = ${fmtNum(prodRows[prodRows.length-1]?.openBalance||0)} units.</li>
        <li><strong>Delivery risk:</strong> ${latePrograms.length} program${latePrograms.length===1?'':'s'} past original req date covering ${fmtNum(lateTotalUnits)} units. ${latePrograms.length?'<strong style="color:#b91c1c">Action required.</strong>':''}</li>
      </ul>
    </div>
  `;
}

function renderSales(root) {
  // Normalize the per-day arrays into {labels[], amounts[]} so charts work
  // whether the loop writes objects ({date, amount}) or flat numbers.
  function normalizeDaily(arr) {
    if (!Array.isArray(arr) || arr.length === 0) return { labels: [], amounts: [] };
    if (typeof arr[0] === 'object' && arr[0] !== null) {
      return {
        labels: arr.map(r => (r.date || '').slice(5)), // MM-DD
        amounts: arr.map(r => Number(r.amount) || 0),
      };
    }
    return { labels: dayLabels, amounts: arr.map(Number) };
  }
  const inv = normalizeDaily(MOCK.sales.invoicesPerDay);
  const rec = normalizeDaily(MOCK.sales.receivablesPerDay);
  const totalReceivables = (MOCK.sales.receivableSummary||[]).reduce((a,b)=>a+(b.open||0),0);
  const invoicesToday = inv.amounts.at(-1) || 0;
  const recvToday = rec.amounts.at(-1) || 0;
  const customersOpen = (MOCK.sales.receivableSummary||[]).filter(r => (r.open||0) > 0).length;
  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Sales & Invoices</p>
        <h1>Invoicing & receivables</h1>
        <p>Invoices sent per day, receivables, and account status by customer.</p>
      </div>
      ${SESSION.role !== 'admin' ? `<button class="btn btn-ghost btn-sm" onclick="navigate('upload')">+ Upload Data</button>` : ''}
    </div>
    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Latest invoiced day</div><div class="kpi-value">${fmtMoney(invoicesToday)}</div><div class="kpi-delta flat">${inv.labels.at(-1) || '—'}</div></div>
      <div class="kpi"><div class="kpi-label">Latest receivables day</div><div class="kpi-value">${fmtMoney(recvToday)}</div><div class="kpi-delta flat">${rec.labels.at(-1) || '—'}</div></div>
      <div class="kpi"><div class="kpi-label">Total open A/R</div><div class="kpi-value">${fmtMoney(totalReceivables)}</div><div class="kpi-delta flat" style="color:#b45309">live from AR_Report</div></div>
      <div class="kpi"><div class="kpi-label">Customers w/ open</div><div class="kpi-value">${customersOpen}</div><div class="kpi-delta flat">of ${(MOCK.sales.receivableSummary||[]).length} total</div></div>
    </div>
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><h2>Invoices per day</h2></div><div class="chart-wrap"><canvas id="slInv"></canvas></div></div>
      <div class="panel"><div class="panel-head"><h2>Receivables per day</h2></div><div class="chart-wrap"><canvas id="slRecv"></canvas></div></div>
    </div>

    ${(() => {
      const m = MOCK.sales.invoicesByCustomerByDay;
      if (!m || !Array.isArray(m.rows) || m.rows.length === 0) return '';
      const days = m.days || [];
      const fmtCol = (s) => { const d = new Date(s + 'T00:00:00'); return d.toLocaleDateString('en-US',{weekday:'short',month:'numeric',day:'numeric'}); };
      return `
      <div class="panel">
        <div class="panel-head"><h2>Invoices this week — by customer × day</h2><span class="panel-meta">${escapeHtml(m.weekStart)} → ${escapeHtml(m.weekEnd)} · total ${fmtMoney(m.weekTotal||0)}</span></div>
        <div style="overflow-x:auto">
          <table style="min-width:700px">
            <thead><tr><th>Customer</th>${days.map(d => `<th style="text-align:right">${escapeHtml(fmtCol(d))}</th>`).join('')}<th style="text-align:right">Week total</th></tr></thead>
            <tbody>${m.rows.map(r => `
              <tr>
                <td><strong>${escapeHtml(r.customer)}</strong></td>
                ${days.map(d => `<td style="text-align:right;color:${(r.days[d]||0)>0?'#0a3d62':'var(--ink-dim)'}">${(r.days[d]||0) > 0 ? fmtMoney(r.days[d]) : '—'}</td>`).join('')}
                <td style="text-align:right"><strong>${fmtMoney(r.weekTotal||0)}</strong></td>
              </tr>`).join('')}
              <tr style="background:#f8fafc;font-weight:700">
                <td>Day total</td>
                ${days.map(d => `<td style="text-align:right">${fmtMoney((m.dayTotals||{})[d]||0)}</td>`).join('')}
                <td style="text-align:right"><strong>${fmtMoney(m.weekTotal||0)}</strong></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>`;
    })()}

    <!-- INDIVIDUAL INVOICES (register) -->
    ${(() => {
      const il = MOCK.sales.invoicesList;
      if (!il || !Array.isArray(il.invoices) || !il.invoices.length) return '';
      return `
      <div class="panel">
        <div class="panel-head"><h2>All invoices</h2><span class="panel-meta">${il.count} invoices · ${fmtMoney(il.total||0)} total · newest first</span></div>
        <div style="padding:12px 18px 0"><input id="invSearch" type="search" placeholder="🔍 Search invoice #, customer or date…" style="width:100%;max-width:360px;background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:9px 12px;font-size:13px" /></div>
        <div style="overflow-x:auto;max-height:560px;overflow-y:auto">
          <table id="invTable">
            <thead><tr><th>Date</th><th>Invoice #</th><th>Customer</th><th style="text-align:right">Amount</th></tr></thead>
            <tbody>${il.invoices.map(v=>`<tr data-s="${escapeHtml((v.num+' '+v.customer+' '+(v.date||'')).toLowerCase())}">
              <td style="white-space:nowrap">${escapeHtml(v.date||'—')}</td>
              <td><strong>${escapeHtml(v.num)}</strong></td>
              <td>${escapeHtml(v.customer)}</td>
              <td style="text-align:right">${fmtMoney(v.amount)}</td>
            </tr>`).join('')}</tbody>
          </table>
        </div>
        <p style="padding:8px 18px 14px;font-size:11px;color:var(--ink-dim)">${escapeHtml(il.note||'')} Source: ${escapeHtml(il.source||'')}.</p>
      </div>`;
    })()}
    <!-- Account summary by customer moved to Finance & Receivables (per portal feedback r12) -->

    <div id="custDetailPanel" class="panel" style="display:none">
      <div class="panel-head" style="justify-content:space-between">
        <h2 id="custDetailTitle">Customer detail</h2>
        <span style="display:flex;gap:8px">
          <button class="btn btn-ghost btn-sm" onclick="window.__asaPrintCust && window.__asaPrintCust()">🖨 Print report</button>
          <button class="btn btn-ghost btn-sm" onclick="document.getElementById('custDetailPanel').style.display='none'">✕ Close</button>
        </span>
      </div>
      <div id="custDetailBody" style="padding:14px 22px"></div>
    </div>
  `;
  // Build a {customer → [invoice lines]} index from the raw AR source
  // (the loop writes arOpenInvoicesSource as a flat list of open invoice lines).
  const invoiceLinesByCust = (() => {
    const out = {};
    const raw = MOCK.sales.arOpenInvoicesSource;
    const list = Array.isArray(raw) ? raw : [];
    for (const ln of list) {
      const c = ln.customer || ln.cust || '—';
      (out[c] = out[c] || []).push({
        invoice: ln.num || ln.invoice || '—',
        type: ln.type || 'Invoice',
        date: ln.date || '—',
        terms: ln.terms || '',
        due: ln.dueDate || ln.due || '—',
        daysLate: Math.max(0, Number(ln.daysPast || ln.daysLate || 0)),
        bucket: (() => {
          const d = Number(ln.daysPast || 0);
          if (d <= 0) return 'current';
          if (d <= 30) return '1-30';
          if (d <= 60) return '31-60';
          return '61+';
        })(),
        amount: Number(ln.open || ln.amount || 0),
      });
    }
    return out;
  })();
  // Expose detail handler
  window.__asaShowCust = (customer) => {
    const invs = invoiceLinesByCust[customer] || [];
    const sum = (MOCK.sales.receivableSummary || []).find(r => r.customer === customer) || {};
    const panel = document.getElementById('custDetailPanel');
    const body = document.getElementById('custDetailBody');
    const title = document.getElementById('custDetailTitle');
    title.textContent = `${customer} — invoice detail (${invs.length} open)`;
    const buckets = {current:0,'1-30':0,'31-60':0,'61+':0};
    invs.forEach(i => { buckets[i.bucket] = (buckets[i.bucket]||0) + i.amount; });
    body.innerHTML = `
      <div id="custPrintRoot">
        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid var(--line)">
          <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Total open</div><div style="font-size:24px;font-weight:800">${fmtMoney(sum.open||0)}</div></div>
          <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Current</div><div style="font-size:18px;color:#16a34a;font-weight:700">${fmtMoney(buckets.current||0)}</div></div>
          <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">1–30</div><div style="font-size:18px;color:#b45309;font-weight:700">${fmtMoney(buckets['1-30']||0)}</div></div>
          <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">31–60</div><div style="font-size:18px;color:#b45309;font-weight:700">${fmtMoney(buckets['31-60']||0)}</div></div>
          <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">61+</div><div style="font-size:18px;color:#b91c1c;font-weight:700">${fmtMoney(buckets['61+']||0)}</div></div>
        </div>
        <table>
          <thead><tr><th>Invoice #</th><th>Type</th><th>Date</th><th>Terms</th><th>Due date</th><th>Days late</th><th>Bucket</th><th>Amount</th></tr></thead>
          <tbody>${invs.length === 0 ? `<tr><td colspan="8" style="text-align:center;color:var(--ink-dim);padding:18px">No invoices found.</td></tr>` : invs.map(i => `<tr>
            <td><strong>${escapeHtml(i.invoice)}</strong></td>
            <td style="font-size:11px;color:var(--ink-dim)">${escapeHtml(i.type||'')}</td>
            <td>${escapeHtml(i.date)}</td>
            <td style="font-size:11px">${escapeHtml(i.terms||'')}</td>
            <td>${escapeHtml(i.due||'—')}</td>
            <td>${i.daysLate>0?`<span class="tag tag-${i.daysLate>60?'bad':i.daysLate>30?'warn':'warn'}">${i.daysLate}d</span>`:'<span style="color:var(--ink-dim)">—</span>'}</td>
            <td><span class="tag tag-${i.bucket==='current'?'good':i.bucket==='61+'?'bad':'warn'}">${escapeHtml(i.bucket)}</span></td>
            <td><strong>${fmtMoney(i.amount)}</strong></td>
          </tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:700"><td colspan="7" style="text-align:right">TOTAL OPEN</td><td><strong>${fmtMoney(sum.open||0)}</strong></td></tr>
          </tbody>
        </table>
        <p style="font-size:10px;color:var(--ink-dim);margin-top:10px">Source: ${escapeHtml((MOCK.sales.arOpenInvoicesSource||'').split('/').pop()||'—')}. Credit memos / negative balances excluded per business rule.</p>
      </div>
    `;
    panel.style.display = 'block';
    panel.scrollIntoView({behavior:'smooth', block:'start'});
  };
  window.__asaPrintCust = () => {
    const body = document.getElementById('custPrintRoot');
    const title = (document.getElementById('custDetailTitle')||{}).textContent || 'Customer report';
    if (!body) return;
    const w = window.open('','_blank','width=900,height=700');
    if (!w) { alert('Pop-up blocked — allow pop-ups to print.'); return; }
    w.document.write(`<!doctype html><html><head><title>${title}</title>
      <style>
        body{font-family:Inter,system-ui,sans-serif;color:#1a1a1a;padding:24px;max-width:900px;margin:0 auto}
        h1{font-size:18px;border-bottom:2px solid #0a3d62;padding-bottom:6px}
        table{border-collapse:collapse;width:100%;font-size:12px}
        th{text-align:left;padding:8px 6px;border-bottom:2px solid #0a3d62;background:#f4f6f8;text-transform:uppercase;font-size:10px;letter-spacing:1px}
        td{padding:7px 6px;border-bottom:1px solid #e3e7eb}
        .tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700}
        .tag-good{background:#d1fae5;color:#065f46}
        .tag-warn{background:#fef3c7;color:#92400e}
        .tag-bad{background:#fee2e2;color:#991b1b}
        @media print { button{display:none} }
      </style></head><body>
      <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:12px">
        <div><strong>Summit Team Apparel, LLC</strong><br/><span style="font-size:11px;color:#666">A/R Detail Report</span></div>
        <div style="text-align:right;font-size:11px;color:#666">Printed: ${new Date().toLocaleString()}</div>
      </div>
      <h1>${title}</h1>
      ${body.innerHTML}
      <p style="margin-top:24px;font-size:10px;color:#999;border-top:1px solid #ddd;padding-top:8px">Generated by STA Admin Portal · summitteamapparel.com/admin</p>
      <script>setTimeout(() => window.print(), 300);<\/script>
      </body></html>`);
    w.document.close();
  };
  activeChart.push(new Chart(document.getElementById('slInv'), { type:'line', data:{labels:inv.labels,datasets:[{label:'Invoices',data:inv.amounts,borderColor:'#0a3d62',backgroundColor:'rgba(10,61,98,.12)',fill:true,tension:.3}]}, options: chartOpts() }));
  activeChart.push(new Chart(document.getElementById('slRecv'), { type:'bar', data:{labels:rec.labels,datasets:[{label:'$',data:rec.amounts,backgroundColor:'#f5a623'}]}, options: chartOpts(false, true) }));
  // Invoice register search
  const invSearch = document.getElementById('invSearch');
  if (invSearch) invSearch.addEventListener('input', () => {
    const q = invSearch.value.trim().toLowerCase();
    document.querySelectorAll('#invTable tbody tr').forEach(tr => {
      tr.style.display = (!q || (tr.dataset.s||'').includes(q)) ? '' : 'none';
    });
  });
}

function renderUA(root) { return renderAccount(root, (MOCK.production && MOCK.production.ua) || null, { short: 'NW', display: 'Northwind (Coreline)', brief: 'ua-brief', prepaid: true }); }
function renderRawlings(root) { return renderAccount(root, (MOCK.production && MOCK.production.rawlings) || null, { short: 'Granite', display: 'Granite', brief: 'rawlings-brief', prepaid: false }); }

function renderAccount(root, ua, cfg) {
  const SHORT = cfg.short, DISP = cfg.display, PREPAID = !!cfg.prepaid;
  if (!ua) {
    root.innerHTML = `<div class="page-head"><div><p class="eyebrow">${escapeHtml(DISP)}</p><h1>${escapeHtml(DISP)}</h1><p>Awaiting next loop pass to build the ${escapeHtml(SHORT)} section.</p></div></div>`;
    return;
  }
  const o = ua.orders||{}, s = ua.shipped||{}, pp = ua.productionPlan||{}, fc = ua.forecast||{}, adv = ua.advance||{};
  const sc = ua.scorecard||{}, aging = ua.pastDueAging||{}, ds = ua.deliverySchedule||{};
  const pct = (a,b) => b>0 ? Math.round(a/b*100) : null;
  const tag = (p) => p==null?'<span style="color:var(--ink-dim)">—</span>':p>=95?`<span class="tag tag-good">${p}%</span>`:p>=70?`<span class="tag tag-warn">${p}%</span>`:`<span class="tag tag-bad">${p}%</span>`;
  const scColor = (v,g,a)=> v==null?'var(--ink-dim)':v>=g?'#16a34a':v>=a?'#b45309':'#b91c1c';

  // find this-week + next-week production plan rows
  const planWeeks = pp.weeks || [];
  const thisWk = planWeeks[0] || {};

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Key Account${PREPAID ? ' · Prepaid' : ''}</p>
        <h1>${escapeHtml(DISP)}</h1>
        <p>${escapeHtml(ua.identityNote||'')}</p>
      </div>
      ${SESSION.role !== 'admin' ? `<button class="btn btn-ghost btn-sm" onclick="navigate('upload')">+ Upload Data</button>` : ''}
    </div>`;
  root.innerHTML += `

    <!-- EXECUTIVE STATUS HERO -->
    ${(() => {
      const owed = adv.owedUnits||0, delivered = adv.deliveredYtdUnits||0;
      const committed = owed + delivered;
      const dPct = committed>0 ? Math.round(delivered/committed*100) : 0;
      const dem = ua.demand || {};
      const pastDue = dem.behindUnits != null ? dem.behindUnits : (aging.total||0);
      const lateN = dem.lateProducts || 0;
      const inProd = pp.totalInProductionUnits||0;
      const wkPlan = thisWk.planUnits||0;
      // plain-English status — driven by the customer's committed dates
      let headline, hColor;
      if (lateN > 0) { headline = `${lateN} program${lateN>1?'s are':' is'} tracking behind ${SHORT}'s dates — ${fmtNum(pastDue)} units at risk. We know it and the lines are running to recover.`; hColor = pastDue > 2000 ? '#b91c1c' : '#b45309'; }
      else if ((aging.total||0) > 0) { headline = `${fmtNum(aging.total)} units are past their required date. ${fmtNum(inProd)} units in production now.`; hColor = (aging.total>2000)?'#b91c1c':'#b45309'; }
      else { headline = `On track — every program is pacing to its committed date. ${fmtNum(inProd)} units in production.`; hColor = '#16a34a'; }
      return `
      <div class="panel" style="background:linear-gradient(135deg,#14142b 0%,#2a2a5a 100%);color:#fff;padding:24px 26px;margin-bottom:18px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px">
          <div style="flex:1;min-width:280px">
            <p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;margin:0 0 8px;opacity:.65">Where ${escapeHtml(SHORT)} stands · ${escapeHtml(ua.asOf||'')}</p>
            <p style="font-size:19px;line-height:1.45;margin:0 0 4px;font-weight:600"><span style="color:${hColor==='#16a34a'?'#86efac':hColor==='#b45309'?'#fde68a':'#fca5a5'}">●</span> ${headline}</p>
            <p style="font-size:13px;opacity:.8;margin:8px 0 0">${fmtNum(o.openUnits||0)} units on open order · ${fmtNum(inProd)} in production · ${fmtNum(wkPlan)} planned this week · ${sc.fillRatePct!=null?sc.fillRatePct+'% fill rate YTD':''}</p>
          </div>
        </div>
        <!-- delivery burn-down -->
        <div style="margin-top:18px">
          <div style="display:flex;justify-content:space-between;font-size:12px;opacity:.85;margin-bottom:6px">
            <span>Delivered ${fmtNum(delivered)} units</span>
            <span>${fmtNum(owed)} still to ship</span>
          </div>
          <div style="height:14px;background:rgba(255,255,255,.15);border-radius:8px;overflow:hidden">
            <div style="height:100%;width:${dPct}%;background:linear-gradient(90deg,#22c55e,#86efac);border-radius:8px"></div>
          </div>
          <div style="font-size:11px;opacity:.7;margin-top:6px">${dPct}% of the committed program (${fmtNum(committed)} units) delivered to date${PREPAID ? ' · prepaid, drawing down' : ' · invoiced on shipment'}</div>
        </div>
      </div>`;
    })()}

    <!-- CUSTOMER DEMAND vs OUR PACE -->
    ${(() => {
      const dem = ua.demand; if (!dem || !Array.isArray(dem.targets) || !dem.targets.length) return '';
      const sCol = (s) => s === 'LATE' ? '#b91c1c' : '#16a34a';
      return `<div class="panel" style="border-left:3px solid #b45309">
        <div class="panel-head"><h2>What ${escapeHtml(SHORT)} is demanding — vs our pace</h2><span class="panel-meta">committed weekly rate + completion date per product · ${dem.lateProducts||0} tracking late · ${fmtNum(dem.behindUnits||0)} units at risk</span></div>
        <div style="overflow-x:auto"><table>
          <thead><tr><th>Product</th><th style="text-align:right">${escapeHtml(SHORT)} weekly target</th><th>Need by</th><th style="text-align:right">Open units</th><th>We project done</th><th style="text-align:right">Status</th></tr></thead>
          <tbody>${dem.targets.map(t => `<tr>
            <td><strong>${escapeHtml(t.product)}</strong></td>
            <td style="text-align:right">${fmtNum(t.weeklyTarget)}/wk</td>
            <td>${escapeHtml(t.dueDate)}</td>
            <td style="text-align:right">${fmtNum(t.openUnits)}</td>
            <td style="${t.status==='LATE'?'color:#b91c1c;font-weight:600':''}">${escapeHtml(t.projectedFinish)}</td>
            <td style="text-align:right;font-weight:700;color:${sCol(t.status)}">${t.status==='LATE'?`LATE · ~${t.weeksLate} wk`:'on track'}${t.status==='LATE'?`<div style="font-size:11px;font-weight:400;color:#b45309">${fmtNum(t.behindUnits)} units short by date</div>`:''}</td></tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td style="text-align:right">${fmtNum(dem.totalWeeklyTarget||0)}/wk</td><td></td><td style="text-align:right">${fmtNum(dem.targets.reduce((s,t)=>s+(t.openUnits||0),0))}</td><td></td><td style="text-align:right;color:#b45309">${fmtNum(dem.behindUnits||0)} at risk</td></tr>
          </tbody></table></div>
        <p style="padding:8px 18px 12px;font-size:11px;color:var(--ink-dim)">${escapeHtml(dem.note||'')} Source: ${escapeHtml(dem.source||'')}.</p>
      </div>`;
    })()}

    <!-- ORDER-BOOK / LIABILITY BANNER -->
    <div class="panel" style="background:linear-gradient(135deg,#1c1c3a 0%,#2a2a5a 100%);color:#fff;padding:22px 26px;margin-bottom:18px">
      <p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;margin:0 0 8px;opacity:.7">${PREPAID ? 'What we owe '+escapeHtml(SHORT)+' · they prepaid for production' : escapeHtml(SHORT)+' order book · still to deliver'}</p>
      <div style="display:flex;gap:40px;flex-wrap:wrap;align-items:flex-end">
        <div>
          <div style="font-size:11px;opacity:.7;text-transform:uppercase;letter-spacing:1px">${PREPAID ? 'Product still owed (open orders)' : 'Still to deliver (open orders)'}</div>
          <div style="font-size:34px;font-weight:800;color:#86efac">${fmtNum(adv.owedUnits||0)} <span style="font-size:16px;font-weight:600;opacity:.85">units · ${fmtMoney(adv.owedUsd||0)}</span></div>
        </div>
        <div>
          <div style="font-size:11px;opacity:.7;text-transform:uppercase;letter-spacing:1px">Delivered YTD (shipped)</div>
          <div style="font-size:28px;font-weight:800">${fmtNum(adv.deliveredYtdUnits||0)} <span style="font-size:14px;font-weight:600;opacity:.85">units · ${fmtMoney(adv.deliveredYtdUsd||0)}</span></div>
        </div>
      </div>
      <p style="font-size:12px;opacity:.85;margin:14px 0 0;line-height:1.5">${escapeHtml(adv.note||'')}</p>
    </div>

    <!-- KPI ROW -->
    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Weekly target</div><div class="kpi-value">${fmtNum(ua.weeklyTargetUnits||0)}</div><div class="kpi-delta flat">units/wk avg plan</div></div>
      <div class="kpi"><div class="kpi-label">Open orders</div><div class="kpi-value">${fmtNum(o.openUnits||0)}</div><div class="kpi-delta flat">${fmtMoney(o.openUsd||0)} · ${o.programCount||0} programs</div></div>
      <div class="kpi"><div class="kpi-label">In production (pipeline)</div><div class="kpi-value">${fmtNum(pp.totalInProductionUnits||0)}</div><div class="kpi-delta flat">heading to shipping</div></div>
      <div class="kpi"><div class="kpi-label">Shipped YTD</div><div class="kpi-value">${fmtNum(s.totalUnits||0)}</div><div class="kpi-delta flat">${fmtMoney(s.totalUsd||0)}${PREPAID ? ' (prepaid)' : ''}</div></div>
    </div>

    <!-- SUPPLIER SCORECARD -->
    <div class="panel">
      <div class="panel-head"><h2>Supplier scorecard</h2><span class="panel-meta">the metrics a brand like ${escapeHtml(SHORT)} runs on you</span></div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0">
        <div style="padding:18px;text-align:center;border-right:1px solid var(--line)">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Fill rate</div>
          <div style="font-size:36px;font-weight:800;color:${scColor(sc.fillRatePct,95,80)}">${sc.fillRatePct!=null?sc.fillRatePct+'%':'—'}</div>
          <div style="font-size:11px;color:var(--ink-dim)">${fmtNum(sc.fillRateShipped||0)} / ${fmtNum(sc.fillRatePlanned||0)} planned</div>
        </div>
        <div style="padding:18px;text-align:center;border-right:1px solid var(--line)">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Weeks on target</div>
          <div style="font-size:36px;font-weight:800;color:${scColor(sc.onTimePct,90,70)}">${sc.onTimePct!=null?sc.onTimePct+'%':'—'}</div>
          <div style="font-size:11px;color:var(--ink-dim)">${sc.weeksOnTarget||0} of ${sc.weeksTotal||0} weeks ≥95%</div>
        </div>
        <div style="padding:18px;text-align:center;border-right:1px solid var(--line)">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Past-due units</div>
          <div style="font-size:36px;font-weight:800;color:${(sc.pastDueUnits||0)>0?'#b45309':'#16a34a'}">${fmtNum(sc.pastDueUnits||0)}</div>
          <div style="font-size:11px;color:var(--ink-dim)">${sc.pastDuePctOfBook||0}% of order book</div>
        </div>
        <div style="padding:18px;text-align:center">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Forecast attainment</div>
          <div style="font-size:36px;font-weight:800;color:${scColor(sc.forecastAttainmentPct,80,50)}">${sc.forecastAttainmentPct!=null?sc.forecastAttainmentPct+'%':'—'}</div>
          <div style="font-size:11px;color:var(--ink-dim)">YTD received vs full-year plan</div>
        </div>
      </div>
    </div>

    <!-- CHARTS -->
    <div class="grid-2">
      <div class="panel"><div class="panel-head"><h2>Monthly forecast vs actual</h2><span class="panel-meta">units, full year</span></div><div class="chart-wrap"><canvas id="uaMonthly"></canvas></div></div>
      <div class="panel"><div class="panel-head"><h2>Weekly shipped vs plan</h2><span class="panel-meta">units, recent weeks</span></div><div class="chart-wrap"><canvas id="uaWeekly"></canvas></div></div>
    </div>

    <!-- PAST-DUE AGING -->
    ${(aging.total||0) > 0 ? `
    <div class="panel" style="border-left:4px solid ${aging.d90plus>0||aging.d29_90>0?'#b91c1c':'#b45309'}">
      <div class="panel-head"><h2>Past-due aging</h2><span class="panel-meta">${fmtNum(aging.total)} units past required date — how late</span></div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0;text-align:center">
        <div style="padding:16px;border-right:1px solid var(--line)"><div style="font-size:11px;text-transform:uppercase;color:#b45309;letter-spacing:1px">0–2 weeks</div><div style="font-size:28px;font-weight:800;color:#b45309">${fmtNum(aging.d0_14||0)}</div></div>
        <div style="padding:16px;border-right:1px solid var(--line)"><div style="font-size:11px;text-transform:uppercase;color:#b45309;letter-spacing:1px">2–4 weeks</div><div style="font-size:28px;font-weight:800;color:#b45309">${fmtNum(aging.d15_28||0)}</div></div>
        <div style="padding:16px;border-right:1px solid var(--line)"><div style="font-size:11px;text-transform:uppercase;color:#b91c1c;letter-spacing:1px">1–3 months</div><div style="font-size:28px;font-weight:800;color:#b91c1c">${fmtNum(aging.d29_90||0)}</div></div>
        <div style="padding:16px"><div style="font-size:11px;text-transform:uppercase;color:#b91c1c;letter-spacing:1px">3+ months</div><div style="font-size:28px;font-weight:800;color:#b91c1c">${fmtNum(aging.d90plus||0)}</div></div>
      </div>
      <div style="padding:10px 22px;font-size:12px;color:var(--ink-dim)">By program: ${(aging.byProgram||[]).map(x=>`${escapeHtml(x.program)} <strong>${fmtNum(x.units)}</strong>`).join(' · ')}</div>
    </div>` : ''}

    <!-- PER-PROGRAM DELIVERY SCHEDULE -->
    ${ds.byProgram && ds.byProgram.length ? `
    <div class="panel">
      <div class="panel-head"><h2>Delivery schedule — units due by program × week</h2><span class="panel-meta">what's committed to ship each week, next ${ds.weeks.length} weeks</span></div>
      <div style="overflow-x:auto">
        <table style="min-width:720px">
          <thead><tr><th>Program</th>${(ds.weekLabels||[]).map(l=>`<th style="text-align:right">${escapeHtml(l)}</th>`).join('')}<th style="text-align:right;background:#1c1c3a;color:#fff">Total</th></tr></thead>
          <tbody>${ds.byProgram.map(pr=>`<tr>
            <td><strong>${escapeHtml(pr.program)}</strong></td>
            ${pr.byWeek.map(u=>`<td style="text-align:right;color:${u>0?'#0a3d62':'var(--ink-dim)'}">${u>0?fmtNum(u):'—'}</td>`).join('')}
            <td style="text-align:right;background:#1c1c3a;color:#fff"><strong>${fmtNum(pr.total)}</strong></td>
          </tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:700"><td>Total due</td>${(ds.weekLabels||[]).map((_,wi)=>`<td style="text-align:right">${fmtNum(ds.byProgram.reduce((a,b)=>a+(b.byWeek[wi]||0),0))}</td>`).join('')}<td style="text-align:right;background:#1c1c3a;color:#fff">${fmtNum(ds.byProgram.reduce((a,b)=>a+b.total,0))}</td></tr>
          </tbody>
        </table>
      </div>
    </div>` : ''}

    <!-- PRODUCTION PLAN: by week (CAPACITY) OR by sewing stage (WIP fallback) -->
    ${(pp.byStatus && pp.byStatus.length) ? `
    <div class="panel">
      <div class="panel-head"><h2>${escapeHtml(SHORT)} in production — by sewing stage</h2><span class="panel-meta">${fmtNum(pp.totalInProductionUnits||0)} units / ${fmtMoney(pp.totalInProductionUsd||0)} on the floor · from WIP order book</span></div>
      <table>
        <thead><tr><th>Stage</th><th style="text-align:right">Units</th><th style="text-align:right">US$</th></tr></thead>
        <tbody>${pp.byStatus.map(s=>`<tr>
            <td><strong>${escapeHtml(s.status)}</strong></td>
            <td style="text-align:right;color:#0a3d62;font-weight:700">${fmtNum(s.units)}</td>
            <td style="text-align:right;color:var(--ink-dim)">${fmtMoney(s.usd)}</td></tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:700"><td>Total in production</td><td style="text-align:right">${fmtNum(pp.totalInProductionUnits||0)}</td><td style="text-align:right">${fmtMoney(pp.totalInProductionUsd||0)}</td></tr>
        </tbody>
      </table>
      <p style="padding:8px 22px;font-size:11px;color:var(--ink-dim)">“In production” = ${escapeHtml(SHORT)} units in an active sewing stage in the WIP order book (excludes NO FABRIC = blocked, and READY-TO-SHIP / PACKING = finished). The CAPACITY export no longer carries a weekly WIP column, so this is sourced from WIP directly.</p>
    </div>` : `
    <div class="panel">
      <div class="panel-head"><h2>${escapeHtml(SHORT)} production plan — by week</h2><span class="panel-meta">how much we're set to produce each week · ${escapeHtml((pp.source||'').split('—')[0])}</span></div>
      <table>
        <thead><tr><th>Week of</th><th style="text-align:right">Weekly plan</th><th style="text-align:right">Ordered (due)</th><th style="text-align:right">In production</th><th style="text-align:right">In-prod US$</th></tr></thead>
        <tbody>${planWeeks.length===0?emptyRow(5):planWeeks.map((w,i)=>`
          <tr${i===0?' style="background:#eff6ff;font-weight:600"':''}>
            <td><strong>${escapeHtml(w.label)}</strong>${i===0?' <span style="font-size:10px;background:#0a3d62;color:#fff;padding:1px 6px;border-radius:8px">this week</span>':''}</td>
            <td style="text-align:right">${fmtNum(w.planUnits)}</td>
            <td style="text-align:right">${fmtNum(w.orderedUnits)}</td>
            <td style="text-align:right;color:#0a3d62;font-weight:700">${fmtNum(w.inProductionUnits)}</td>
            <td style="text-align:right;color:var(--ink-dim)">${fmtMoney(w.inProductionUsd)}</td>
          </tr>`).join('')}</tbody>
      </table>
      <p style="padding:8px 22px;font-size:11px;color:var(--ink-dim)">“Weekly plan” = forecast target. “Ordered” = units with a req date that week. “In production” = units in the WIP pipeline (closest signal we have to produced-and-waiting).</p>
    </div>`}

    <!-- BETTER WIP REPORT: open orders by program, ordered vs shipped -->
    <div class="panel">
      <div class="panel-head"><h2>${escapeHtml(SHORT)} WIP report — open orders by program</h2><span class="panel-meta">the order book ${escapeHtml(SHORT)} cares about · ${escapeHtml(o.source||'')}</span></div>
      <table>
        <thead><tr><th>Program</th><th style="text-align:right">Open units</th><th style="text-align:right">US$</th><th style="text-align:right">Order lines</th><th>Earliest req</th><th style="text-align:right">Past due</th></tr></thead>
        <tbody>${(o.byProgram||[]).length===0?emptyRow(6):(o.byProgram||[]).map(p=>`
          <tr>
            <td><strong>${escapeHtml(p.program)}</strong></td>
            <td style="text-align:right"><strong>${fmtNum(p.units)}</strong></td>
            <td style="text-align:right">${fmtMoney(p.usd)}</td>
            <td style="text-align:right;color:var(--ink-dim)">${p.lines}</td>
            <td>${escapeHtml(p.earliestReq||'—')}</td>
            <td style="text-align:right;color:${p.lateUnits>0?'#b91c1c':'var(--ink-dim)'};font-weight:${p.lateUnits>0?'700':'400'}">${p.lateUnits>0?fmtNum(p.lateUnits):'—'}</td>
          </tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:700"><td>TOTAL</td><td style="text-align:right">${fmtNum(o.openUnits||0)}</td><td style="text-align:right">${fmtMoney(o.openUsd||0)}</td><td style="text-align:right">${(o.byProgram||[]).reduce((a,b)=>a+b.lines,0)}</td><td></td><td style="text-align:right">${fmtNum((o.byProgram||[]).reduce((a,b)=>a+b.lateUnits,0))}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- SHIPPED vs PLAN BY WEEK -->
    <div class="panel">
      <div class="panel-head"><h2>${escapeHtml(SHORT)} shipped vs plan — by week</h2><span class="panel-meta">what actually went out the door · ${escapeHtml(s.source||'')}</span></div>
      <table>
        <thead><tr><th>Week ending</th><th style="text-align:right">Planned</th><th style="text-align:right">Shipped</th><th style="text-align:right">% to plan</th><th style="text-align:right">US$</th></tr></thead>
        <tbody>${(s.byWeek||[]).slice(-12).map(w=>`
          <tr>
            <td><strong>${escapeHtml(w.weekEnding)}</strong></td>
            <td style="text-align:right">${fmtNum(w.planned)}</td>
            <td style="text-align:right"><strong>${fmtNum(w.shipped)}</strong></td>
            <td style="text-align:right">${tag(pct(w.shipped,w.planned))}</td>
            <td style="text-align:right">${fmtMoney(w.usd)}</td>
          </tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:700"><td>TOTAL YTD</td><td style="text-align:right">${fmtNum(s.plannedUnits||0)}</td><td style="text-align:right">${fmtNum(s.totalUnits||0)}</td><td style="text-align:right">${tag(pct(s.totalUnits,s.plannedUnits))}</td><td style="text-align:right">${fmtMoney(s.totalUsd||0)}</td></tr>
        </tbody>
      </table>
    </div>

    <!-- FORECAST + RECONCILIATION -->
    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h2>Full-year forecast</h2><span class="panel-meta">${escapeHtml((fc.source||'').split('(')[0])}</span></div>
        <div style="padding:18px 22px">
          <div style="display:flex;gap:28px;flex-wrap:wrap">
            <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Forecast units</div><div style="font-size:24px;font-weight:800">${fmtNum(fc.yearUnits||0)}</div></div>
            <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Received YTD</div><div style="font-size:24px;font-weight:800">${fmtNum(fc.actualReceivedUnits||0)}</div></div>
            <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">% complete</div><div style="font-size:24px;font-weight:800;color:#0a3d62">${fc.pctComplete!=null?fc.pctComplete+'%':'—'}</div></div>
          </div>
          <div style="margin-top:10px;font-size:13px;color:var(--ink-dim)">Forecast value: ${fmtMoney(fc.yearUsd||0)}</div>
        </div>
      </div>
      <div class="panel" style="border-left:4px solid #b45309">
        <div class="panel-head"><h2 style="color:#b45309">⚠ Data reconciliation</h2><span class="panel-meta">read before sending to ${escapeHtml(SHORT)}</span></div>
        <div style="padding:14px 22px">
          ${(ua.dataNotes||[]).map(n=>`<p style="font-size:12px;line-height:1.55;margin:0 0 10px;color:#1a1a1a">• ${escapeHtml(n)}</p>`).join('')}
        </div>
      </div>
    </div>

    <!-- RAW MATERIALS held for this account -->
    ${(() => {
      const inv = ua.inventory; if (!inv) return '';
      const cats = inv.byCategory || []; const items = inv.topItems || [];
      const catVal = (c) => c.cost != null ? c.cost : (c.value || 0);
      const itVal = (it) => it.cost != null ? it.cost : (it.value || 0);
      return `
      <div class="panel">
        <div class="panel-head"><h2>Raw materials we hold for ${escapeHtml(SHORT)} — $ left</h2><span class="panel-meta">fabric, trims &amp; supplies STA is holding for ${escapeHtml(SHORT)} · ${escapeHtml(inv.source||'')}</span></div>
        <div class="kpi-grid" style="margin-bottom:4px">
          <div class="kpi" style="border-left:3px solid #0a3d62"><div class="kpi-label">Raw materials left ($)</div><div class="kpi-value">${fmtMoney(inv.onHandCost||0)}</div><div class="kpi-delta flat">on-hand value · ${inv.lineCount||0} materials</div></div>
          <div class="kpi"><div class="kpi-label">On hand</div><div class="kpi-value">${fmtNum(inv.onHandUnits||0)}</div><div class="kpi-delta flat">units / yards</div></div>
          <div class="kpi"><div class="kpi-label">Pending available</div><div class="kpi-value">${fmtNum(inv.pendingAvailable||0)}</div><div class="kpi-delta flat">incl. on order</div></div>
          <div class="kpi"><div class="kpi-label">On order</div><div class="kpi-value">${fmtNum(inv.ordered||0)}</div><div class="kpi-delta flat">inbound</div></div>
        </div>
        ${cats.length ? `<table><thead><tr><th>Material type</th><th style="text-align:right">$ value left</th><th style="text-align:right">On hand</th><th style="text-align:right">% used</th><th>Who paid</th></tr></thead>
          <tbody>${cats.map(c=>`<tr><td><strong>${escapeHtml(c.category)}</strong></td><td style="text-align:right;font-weight:700">${fmtMoney(catVal(c))}</td><td style="text-align:right">${fmtNum(c.onHand)}</td><td style="text-align:right;color:${(c.consumedPct||0)>=70?'#b45309':'var(--ink-dim)'}">${c.consumedPct!=null?c.consumedPct+'%':'—'}</td><td style="font-size:12px;color:var(--ink-dim)">${escapeHtml(c.owner||(/trim|suppl/i.test(c.category)?'STA':SHORT))}</td></tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td style="text-align:right">${fmtMoney(inv.onHandCost||0)}</td><td style="text-align:right">${fmtNum(inv.onHandUnits||0)}</td><td></td><td></td></tr></tbody></table>` : ''}
        ${items.length ? `<div class="panel-head" style="border-top:1px solid var(--line);margin-top:6px"><h2 style="font-size:14px">Biggest materials by value</h2><span class="panel-meta">top ${items.length} of ${inv.lineCount||items.length}</span></div>
        <div style="overflow-x:auto"><table style="min-width:520px"><thead><tr><th>Material</th><th>Type</th><th style="text-align:right">On hand</th><th style="text-align:right">$ value</th></tr></thead>
          <tbody>${items.map(it=>`<tr><td><strong>${escapeHtml(it.material||it.partNumber||'—')}</strong></td><td style="font-size:12px;color:var(--ink-dim)">${escapeHtml(it.category||'')}</td><td style="text-align:right">${fmtNum(it.onHand||0)}</td><td style="text-align:right"><strong>${fmtMoney(itVal(it))}</strong></td></tr>`).join('')}</tbody></table></div>` : ''}
        <p style="padding:8px 22px;font-size:11px;color:var(--ink-dim)">${escapeHtml(inv.note||'')}</p>
      </div>`;
    })()}
  `;

  // ---- Charts ----
  const mfva = ua.monthlyFvA || [];
  if (mfva.length && document.getElementById('uaMonthly')) {
    activeChart.push(new Chart(document.getElementById('uaMonthly'), {
      type:'bar',
      data:{ labels: mfva.map(m=>m.month.slice(0,3)), datasets:[
        { label:'Forecast', data: mfva.map(m=>m.forecast), backgroundColor:'#cfe6f5' },
        { label:'Actual',   data: mfva.map(m=>m.actual),   backgroundColor:'#1c1c3a' },
      ]},
      options:{ responsive:true, maintainAspectRatio:false,
        scales:{ y:{ beginAtZero:true, ticks:{font:{size:10}} }, x:{ grid:{display:false}, ticks:{font:{size:10}} } },
        plugins:{ legend:{ position:'bottom', labels:{font:{size:11}} } } }
    }));
  }
  const sw = (s.byWeek||[]).slice(-13);
  if (sw.length && document.getElementById('uaWeekly')) {
    activeChart.push(new Chart(document.getElementById('uaWeekly'), {
      type:'bar',
      data:{ labels: sw.map(w=>w.weekEnding.slice(5)), datasets:[
        { label:'Planned', data: sw.map(w=>w.planned), backgroundColor:'#cfe6f5' },
        { label:'Shipped', data: sw.map(w=>w.shipped), backgroundColor:'#15803d' },
      ]},
      options:{ responsive:true, maintainAspectRatio:false,
        scales:{ y:{ beginAtZero:true, ticks:{font:{size:10}} }, x:{ grid:{display:false}, ticks:{font:{size:9}} } },
        plugins:{ legend:{ position:'bottom', labels:{font:{size:11}} } } }
    }));
  }
}

function renderProductionFlow(root) {
  const flow = (MOCK.production && MOCK.production.flow) || {};
  const oo = (MOCK.production && MOCK.production.openOrdersByCustomer) || [];
  const load = (MOCK.production && MOCK.production.loadByWeek) || {weeks:[]};
  const fc = (MOCK.production && MOCK.production.forecastByCustomer) || [];
  const wm = (MOCK.shipping && MOCK.shipping.weekMonday) || null;
  const ord = flow.ordersOpen || {units:0,usd:0};
  const shp = flow.shippedYTD || {units:0,usd:0};
  const pns = flow.producedNotShipped || {status:'NOT_CAPTURED'};
  const fp = (MOCK.production && MOCK.production.floorProduction) || null;       // bihorario by line/product/date
  const pvs = (MOCK.production && MOCK.production.producedVsShipped) || null;    // produced vs shipped by product
  const ca = (MOCK.production && MOCK.production.capacityAttainment) || null;    // capacity vs produced

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Production</p>
        <h1>Orders → Production → Shipped</h1>
        <p>The factory gets paid on shipment. This page follows the work from order to cash — by customer, by week.</p>
      </div>
      ${SESSION.role !== 'admin' ? `<button class="btn btn-ghost btn-sm" onclick="navigate('upload')">+ Upload Data</button>` : ''}
    </div>

    ${productionLinesPanel()}

    <!-- THE FLOW: orders → produced(?) → shipped -->
    <div class="panel" style="padding:0;margin-bottom:18px">
      <div style="display:grid;grid-template-columns:1fr auto 1fr auto 1fr;align-items:stretch;gap:0">
        <div style="padding:22px;text-align:center;background:#eff6ff">
          <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#0a3d62;font-weight:700">Open Orders</div>
          <div style="font-size:34px;font-weight:800;color:#0a3d62;line-height:1.1;margin-top:6px">${fmtNum(ord.units)}</div>
          <div style="font-size:13px;color:#0a3d62">${fmtMoney(ord.usd)}</div>
          <div style="font-size:11px;color:var(--ink-dim);margin-top:6px">in the system, not yet shipped</div>
        </div>
        <div style="display:flex;align-items:center;padding:0 8px;color:var(--ink-dim);font-size:24px">→</div>
        ${pns.units != null ? `
        <div style="padding:22px;text-align:center;background:#fffbeb;border:2px solid #b45309;cursor:pointer" onclick="navigate('invAccum')">
          <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#b45309;font-weight:700">Produced · Not Shipped</div>
          <div style="font-size:34px;font-weight:800;color:#b45309;line-height:1.1;margin-top:6px">${pns.units>=0?'+':''}${fmtNum(pns.units)}</div>
          <div style="font-size:13px;color:#b45309;font-weight:700">in the warehouse</div>
          <div style="font-size:11px;color:var(--ink-dim);margin-top:6px">sewn (Bihorario) − shipped · detail →</div>
        </div>` : `
        <div style="padding:22px;text-align:center;background:#fff3f3;border:2px dashed #b91c1c">
          <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#b91c1c;font-weight:700">Produced · Not Shipped</div>
          <div style="font-size:34px;font-weight:800;color:#b91c1c;line-height:1.1;margin-top:6px">?</div>
          <div style="font-size:13px;color:#b91c1c;font-weight:700">NOT CAPTURED</div>
          <div style="font-size:11px;color:var(--ink-dim);margin-top:6px">we don't log production yet</div>
        </div>`}
        <div style="display:flex;align-items:center;padding:0 8px;color:var(--ink-dim);font-size:24px">→</div>
        <div style="padding:22px;text-align:center;background:#f0fdf4">
          <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#15803d;font-weight:700">Shipped YTD = Paid</div>
          <div style="font-size:34px;font-weight:800;color:#15803d;line-height:1.1;margin-top:6px">${fmtNum(shp.units)}</div>
          <div style="font-size:13px;color:#15803d">${fmtMoney(shp.usd)}</div>
          <div style="font-size:11px;color:var(--ink-dim);margin-top:6px">revenue recognized on shipment</div>
        </div>
      </div>
      <div style="padding:14px 22px;background:#fff8eb;border-top:1px solid var(--line);font-size:13px;color:#1a1a1a;line-height:1.5">
        ${pns.units != null
          ? `<strong style="color:#b45309">ℹ How it's measured:</strong> ${escapeHtml(pns.why || '')} Produced ${fmtNum(pns.produced || 0)} − shipped ${fmtNum(pns.shipped || 0)} = <strong>${fmtNum(pns.units)} units</strong> sitting in the warehouse — see Inventory Accumulation for the by-product / by-customer detail.`
          : `<strong style="color:#b45309">⚠ The blind spot:</strong> ${escapeHtml(pns.why || 'No production count is logged.')} <strong>To fix:</strong> ${escapeHtml(pns.toFix || 'Upload a daily production log.')} Until then, anything cut/sewn/finished but not yet shipped is invisible — it sits between the blue and green boxes above.`}
      </div>
    </div>

    <!-- THIS WEEK vs LAST WEEK (Monday-start) -->
    ${wm ? `
    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h2>This week so far</h2><span class="panel-meta">${escapeHtml(wm.thisWeekSoFar.weekStart)} → today (Mon-start)</span></div>
        <div style="padding:14px 22px">
          <div style="font-size:30px;font-weight:800;color:#0a3d62">${fmtNum(wm.thisWeekSoFar.totalUnits)} <span style="font-size:15px;font-weight:600;color:var(--ink-dim)">units · ${fmtMoney(wm.thisWeekSoFar.totalUsd)}</span></div>
        </div>
        <table><thead><tr><th>Customer</th><th style="text-align:right">Units</th><th style="text-align:right">US$</th></tr></thead>
          <tbody>${wm.thisWeekSoFar.byCustomer.length===0 ? `<tr><td colspan="3" style="text-align:center;color:var(--ink-dim);padding:18px">Nothing shipped yet this week.</td></tr>` : wm.thisWeekSoFar.byCustomer.map(r=>`<tr><td><strong>${escapeHtml(r.customer)}</strong></td><td style="text-align:right">${fmtNum(r.units)}</td><td style="text-align:right">${fmtMoney(r.usd)}</td></tr>`).join('')}</tbody>
        </table>
      </div>
      <div class="panel" style="opacity:.9">
        <div class="panel-head"><h2>Last week</h2><span class="panel-meta">${escapeHtml(wm.lastWeek.weekStart)} → ${escapeHtml(wm.lastWeek.weekEnd)}</span></div>
        <div style="padding:14px 22px">
          <div style="font-size:30px;font-weight:800">${fmtNum(wm.lastWeek.totalUnits)} <span style="font-size:15px;font-weight:600;color:var(--ink-dim)">units · ${fmtMoney(wm.lastWeek.totalUsd)}</span></div>
        </div>
        <table><thead><tr><th>Customer</th><th style="text-align:right">Units</th><th style="text-align:right">US$</th></tr></thead>
          <tbody>${wm.lastWeek.byCustomer.length===0 ? `<tr><td colspan="3" style="text-align:center;color:var(--ink-dim);padding:18px">No data.</td></tr>` : wm.lastWeek.byCustomer.map(r=>`<tr><td><strong>${escapeHtml(r.customer)}</strong></td><td style="text-align:right">${fmtNum(r.units)}</td><td style="text-align:right">${fmtMoney(r.usd)}</td></tr>`).join('')}</tbody>
        </table>
      </div>
    </div>` : ''}

    <!-- OPEN ORDERS BY CUSTOMER (the backlog) -->
    <div class="panel">
      <div class="panel-head"><h2>Open orders by customer</h2><span class="panel-meta">the order book — what's committed and not yet shipped · ${oo.length} customers</span></div>
      <table>
        <thead><tr><th>Customer</th><th style="text-align:right">Open units</th><th style="text-align:right">Open US$</th><th style="text-align:right">Programs</th><th style="text-align:right">% of book</th></tr></thead>
        <tbody>${oo.length===0 ? emptyRow(5) : oo.map(r=>{
          const pctBook = ord.usd>0 ? Math.round(r.usd/ord.usd*100) : 0;
          return `<tr>
            <td><strong>${escapeHtml(r.customer)}</strong></td>
            <td style="text-align:right"><strong>${fmtNum(r.units)}</strong></td>
            <td style="text-align:right">${fmtMoney(r.usd)}</td>
            <td style="text-align:right;color:var(--ink-dim)">${r.programs}</td>
            <td style="text-align:right">${pctBook}%</td>
          </tr>`;
        }).join('')}
        <tr style="background:#f8fafc;font-weight:700"><td>TOTAL</td><td style="text-align:right">${fmtNum(ord.units)}</td><td style="text-align:right">${fmtMoney(ord.usd)}</td><td style="text-align:right">${oo.reduce((a,b)=>a+b.programs,0)}</td><td style="text-align:right">100%</td></tr>
        </tbody>
      </table>
    </div>

    <!-- PRODUCED (BIHORARIO) vs SHIPPED + CAPACITY ATTAINMENT (portal feedback r7/r10) -->
    ${pvs ? `
    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h2>Produced vs shipped</h2><span class="panel-meta">floor output (Bihorario) vs shipped — units</span></div>
        <div style="padding:16px 22px;display:flex;gap:28px;flex-wrap:wrap">
          <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Produced YTD</div><div style="font-size:26px;font-weight:800;color:#0a3d62">${fmtNum(pvs.totalProduced)}</div></div>
          <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Shipped YTD</div><div style="font-size:26px;font-weight:800;color:#15803d">${fmtNum(pvs.totalShipped)}</div></div>
          <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Made, not shipped</div><div style="font-size:26px;font-weight:800;color:#b45309">${fmtNum(Math.max(0,pvs.totalProduced-pvs.totalShipped))}</div></div>
        </div>
        ${ca ? `<div style="padding:0 22px 14px"><span style="font-size:13px">Capacity attainment: <strong style="color:${ca.attainmentPct>=90?'#16a34a':ca.attainmentPct>=70?'#b45309':'#b91c1c'}">${ca.attainmentPct!=null?ca.attainmentPct+'%':'—'}</strong> — ${fmtNum(ca.totalProduced)} produced / ${fmtNum(ca.totalAllocated)} allocated</span></div>`:''}
        <p style="padding:0 22px 12px;font-size:11px;color:var(--ink-dim)">${escapeHtml(pvs.note||'')}</p>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Produced by line</h2><span class="panel-meta">SEW · module × product · units assembled</span></div>
        <div style="overflow-x:auto;max-height:360px;overflow-y:auto"><table>
          <thead><tr><th>Module</th><th>Product</th><th style="text-align:right">Units</th></tr></thead>
          <tbody>${(fp&&fp.byLine&&fp.byLine.length)?fp.byLine.map(l=>`<tr><td><strong>${escapeHtml(l.module)}</strong></td><td>${escapeHtml(l.product)}</td><td style="text-align:right">${fmtNum(l.units)}</td></tr>`).join(''):emptyRow(3)}</tbody>
        </table></div>
      </div>
    </div>` : ''}

    <!-- WEEKLY SEWING LINE SCORECARD (SEWING PRODUCTION RESULTS) -->
    ${(() => {
      const sr = (MOCK.production && MOCK.production.sewingResults) || null;
      if (!sr || !sr.lines || !sr.lines.length) return '';
      const t = sr.totals || {};
      const attmColor = (p) => p == null ? 'var(--ink-dim)' : p >= 95 ? '#16a34a' : p >= 80 ? '#b45309' : '#b91c1c';
      const dl = sr.dayLabels || sr.dayNames || [];
      return `
      <div class="panel">
        <div class="panel-head"><h2>Sewing line scorecard — week ${sr.week || ''}</h2><span class="panel-meta">${sr.weekStart ? 'wk of ' + sr.weekStart + ' · ' : ''}goal vs actual vs attainment, by line · source: SEWING PRODUCTION RESULTS</span></div>
        <div class="kpi-grid" style="margin:0">
          <div class="kpi"><div class="kpi-label">Sewn this week</div><div class="kpi-value">${fmtNum(t.total||0)}</div><div class="kpi-delta flat">${sr.lines.length} lines · ${fmtNum(t.operators||0)} operators</div></div>
          <div class="kpi"><div class="kpi-label">Week goal</div><div class="kpi-value">${fmtNum(t.weekGoal||0)}</div><div class="kpi-delta flat">${(t.diff||0)>=0?'+':''}${fmtNum(t.diff||0)} vs goal</div></div>
          <div class="kpi"><div class="kpi-label">Attainment</div><div class="kpi-value" style="color:${attmColor(t.attainmentPct)}">${t.attainmentPct!=null?t.attainmentPct+'%':'—'}</div><div class="kpi-delta flat">sewn ÷ goal</div></div>
        </div>
        <div style="overflow-x:auto;padding:0 18px 6px"><table>
          <thead><tr><th>Line</th><th>Coordinator</th><th>Module</th><th style="text-align:right">Ops</th>${dl.map(d=>`<th style="text-align:right">${escapeHtml(d)}</th>`).join('')}<th style="text-align:right">Total</th><th style="text-align:right">Goal</th><th style="text-align:right">Attm</th></tr></thead>
          <tbody>${sr.lines.map(l=>`<tr>
            <td><strong>${escapeHtml(l.line)}</strong></td>
            <td style="color:var(--ink-dim)">${escapeHtml(l.coord||'')}</td>
            <td style="color:var(--ink-dim)">${escapeHtml(l.module||'')}</td>
            <td style="text-align:right">${fmtNum(l.operators||0)}</td>
            ${(l.daily||[]).map(u=>`<td style="text-align:right;color:var(--ink-dim)">${u?fmtNum(u):'·'}</td>`).join('')}
            <td style="text-align:right;font-weight:700">${fmtNum(l.total||0)}</td>
            <td style="text-align:right;color:var(--ink-dim)">${fmtNum(l.weekGoal||0)}</td>
            <td style="text-align:right;font-weight:700;color:${attmColor(l.attainmentPct)}">${l.attainmentPct!=null?l.attainmentPct+'%':'—'}</td></tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:800"><td>TOTAL</td><td></td><td></td><td style="text-align:right">${fmtNum(t.operators||0)}</td>${(t.daily||[]).map(u=>`<td style="text-align:right">${fmtNum(u)}</td>`).join('')}<td style="text-align:right">${fmtNum(t.total||0)}</td><td style="text-align:right">${fmtNum(t.weekGoal||0)}</td><td style="text-align:right;color:${attmColor(t.attainmentPct)}">${t.attainmentPct!=null?t.attainmentPct+'%':'—'}</td></tr>
          </tbody></table></div>
        <p style="padding:6px 18px 12px;font-size:11px;color:var(--ink-dim)">${escapeHtml(sr.note||'')}</p>
      </div>`;
    })()}

    <!-- PRODUCED vs OPEN BY PRODUCT TYPE (portal feedback r9) -->
    ${(() => {
      const pvo = (MOCK.production && MOCK.production.producedVsOpen) || null;
      if (!pvo || !pvo.byProductType || !pvo.byProductType.length) return '';
      return `
      <div class="panel">
        <div class="panel-head"><h2>Produced vs open — by product type</h2><span class="panel-meta">do we already have units made? "Available" = produced − open</span></div>
        <div style="overflow-x:auto">
          <table>
            <thead><tr><th>Product type</th><th style="text-align:right">Produced</th><th style="text-align:right">Open orders</th><th style="text-align:right">Open w/ fabric</th><th style="text-align:right">Available (made − open)</th></tr></thead>
            <tbody>${pvo.byProductType.map(r=>`<tr>
              <td><strong>${escapeHtml(r.productType)}</strong></td>
              <td style="text-align:right;color:#0a3d62">${fmtNum(r.produced)}</td>
              <td style="text-align:right">${fmtNum(r.open)}</td>
              <td style="text-align:right;color:var(--ink-dim)">${fmtNum(r.openWithFabric)}</td>
              <td style="text-align:right;color:${r.available>0?'#16a34a':'#b45309'};font-weight:700">${r.available>0?'+':''}${fmtNum(r.available)}</td>
            </tr>`).join('')}</tbody>
          </table>
        </div>
        <p style="padding:10px 22px;font-size:11px;color:var(--ink-dim)">${escapeHtml(pvo.note||'')}</p>
      </div>`;
    })()}

    <!-- PRODUCTION LOAD BY WEEK PER CUSTOMER -->
    ${load.weeks && load.weeks.length ? `
    <div class="panel">
      <div class="panel-head"><h2>Production load by week — per customer</h2><span class="panel-meta">how much is scheduled to produce each week, from orders in the system · Monday-start</span></div>
      <div style="overflow-x:auto">
        ${(() => {
          const weeks = load.weeks;
          const custs = Array.from(new Set(weeks.flatMap(w => w.byCustomer.map(c=>c.customer))));
          // order customers by total load desc
          const tot = {}; custs.forEach(c => tot[c] = weeks.reduce((s,w)=>{const m=w.byCustomer.find(x=>x.customer===c);return s+(m?m.units:0);},0));
          custs.sort((a,b)=>tot[b]-tot[a]);
          return `<table style="min-width:720px">
            <thead><tr><th>Week of</th>${custs.map(c=>`<th style="text-align:right">${escapeHtml(c)}</th>`).join('')}<th style="text-align:right;background:#0a3d62;color:#fff">Total</th></tr></thead>
            <tbody>${weeks.map(w=>`<tr>
              <td><strong>${escapeHtml(w.label)}</strong></td>
              ${custs.map(c=>{const m=w.byCustomer.find(x=>x.customer===c);return `<td style="text-align:right;color:${m&&m.units>0?'#0a3d62':'var(--ink-dim)'}">${m&&m.units>0?fmtNum(m.units):'—'}</td>`;}).join('')}
              <td style="text-align:right;background:#0a3d62;color:#fff"><strong>${fmtNum(w.totalUnits)}</strong></td>
            </tr>`).join('')}
            <tr style="background:#f8fafc;font-weight:700"><td>Customer total</td>${custs.map(c=>`<td style="text-align:right">${fmtNum(tot[c])}</td>`).join('')}<td style="text-align:right;background:#0a3d62;color:#fff">${fmtNum(weeks.reduce((s,w)=>s+w.totalUnits,0))}</td></tr>
            </tbody>
          </table>`;
        })()}
      </div>
      <p style="padding:10px 22px;font-size:11px;color:var(--ink-dim);font-style:italic">${escapeHtml(load.note||'')}</p>
    </div>` : ''}

    <!-- FORECAST BY CUSTOMER -->
    ${fc.length ? `
    <div class="panel">
      <div class="panel-head"><h2>Forecast by customer (full year)</h2><span class="panel-meta">planned units + revenue for the year, with actuals to date</span></div>
      <table>
        <thead><tr><th>Customer</th><th style="text-align:right">Forecast units</th><th style="text-align:right">Actual to date</th><th style="text-align:right">% done</th><th style="text-align:right">Forecast US$</th></tr></thead>
        <tbody>${fc.map(r=>{
          const p = r.forecastUnits>0 ? Math.round(r.actualUnits/r.forecastUnits*100) : null;
          const tag = p==null?'—':p>=95?`<span class="tag tag-good">${p}%</span>`:p>=60?`<span class="tag tag-warn">${p}%</span>`:`<span class="tag tag-bad">${p}%</span>`;
          return `<tr><td><strong>${escapeHtml(r.customer)}</strong></td><td style="text-align:right">${fmtNum(r.forecastUnits)}</td><td style="text-align:right">${fmtNum(r.actualUnits)}</td><td style="text-align:right">${tag}</td><td style="text-align:right">${fmtMoney(r.forecastUsd)}</td></tr>`;
        }).join('')}</tbody>
      </table>
    </div>` : ''}
  `;
}

function renderProduction(root) {
  // Inventory now sourced from ON_HAND_POLYPM (per portal feedback r4); WIP table removed (r5).
  const pp = MOCK.production.polypm || null;
  const byCust = (pp && pp.byCustomer) || [];
  const byCat = (pp && pp.byCategory) || [];
  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Inventory</p>
        <h1>On-hand inventory</h1>
        <p>Live on-hand inventory from the ON&nbsp;HAND&nbsp;POLYPM report — units and landed cost by customer and category.${pp&&pp.asOf?` As of ${escapeHtml(pp.asOf)}.`:''}</p>
      </div>
      ${SESSION.role !== 'admin' ? `<button class="btn btn-ghost btn-sm" onclick="navigate('upload')">+ Upload Data</button>` : ''}
    </div>

    ${!pp ? `<div class="panel"><p style="padding:20px;color:var(--ink-dim)">Upload the ON HAND POLYPM file to populate inventory.</p></div>` : `
    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Units on hand</div><div class="kpi-value">${fmtNum(pp.totalOnHand||0)}</div><div class="kpi-delta flat">${(pp.lineItems||0).toLocaleString()} line items</div></div>
      <div class="kpi"><div class="kpi-label">On-hand cost</div><div class="kpi-value">${fmtMoney(pp.totalOnHandCost||0)}</div><div class="kpi-delta flat">landed value</div></div>
      <div class="kpi"><div class="kpi-label">Customers</div><div class="kpi-value">${byCust.length}</div><div class="kpi-delta flat">with inventory on hand</div></div>
      <div class="kpi"><div class="kpi-label">Categories</div><div class="kpi-value">${byCat.length}</div><div class="kpi-delta flat">fabric · trim · finished</div></div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head"><h2>On hand by customer</h2><span class="panel-meta">units · cost · pending available</span></div>
        <div style="overflow-x:auto;max-height:520px;overflow-y:auto"><table>
          <thead><tr><th>Customer</th><th style="text-align:right">On hand</th><th style="text-align:right">Cost</th><th style="text-align:right">Pending avail.</th><th style="text-align:right">Lines</th></tr></thead>
          <tbody>${byCust.length===0?emptyRow(5):byCust.map(c=>`<tr>
            <td><strong>${escapeHtml(c.customer)}</strong></td>
            <td style="text-align:right">${fmtNum(c.onHand)}</td>
            <td style="text-align:right">${fmtMoney(c.cost)}</td>
            <td style="text-align:right;color:var(--ink-dim)">${fmtNum(c.pendingAvailable||0)}</td>
            <td style="text-align:right;color:var(--ink-dim)">${c.lines}</td>
          </tr>`).join('')}
          <tr style="background:#f8fafc;font-weight:700"><td>TOTAL</td><td style="text-align:right">${fmtNum(pp.totalOnHand||0)}</td><td style="text-align:right">${fmtMoney(pp.totalOnHandCost||0)}</td><td></td><td></td></tr>
          </tbody>
        </table></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>On hand by category</h2><span class="panel-meta">fabric / trim / finished</span></div>
        <table>
          <thead><tr><th>Category</th><th style="text-align:right">On hand</th><th style="text-align:right">Cost</th><th style="text-align:right">Lines</th></tr></thead>
          <tbody>${byCat.length===0?emptyRow(4):byCat.map(c=>`<tr>
            <td><strong>${escapeHtml(c.category)}</strong></td>
            <td style="text-align:right">${fmtNum(c.onHand)}</td>
            <td style="text-align:right">${fmtMoney(c.cost)}</td>
            <td style="text-align:right;color:var(--ink-dim)">${c.lines}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
    </div>
    <p style="font-size:11px;color:var(--ink-dim);margin-top:4px">${escapeHtml((pp.note||''))} Source: ${escapeHtml((pp.source||'').split('/').pop()||'ON_HAND_POLYPM.xlsx')}.</p>
    `}
  `;
}

function renderCapacityWip(root) {
  const wipAll = MOCK.production.wip || [];
  // Coreline is paid up-front — separate it so it doesn't distort the main view, and zero its $$ on display
  const isMomentec = (w) => String(w.customer||'').toLowerCase().includes('coreline');
  const wip = wipAll.filter(w => !isMomentec(w));
  const wipMomentec = wipAll.filter(isMomentec).map(w => ({...w, usd: 0, usdNote: 'Paid up front — no \\$ at risk'}));
  const byCustAll = MOCK.production.wipByCustomer || [];
  const byCust = byCustAll.filter(c => !isMomentec(c));
  const byCustMomentec = byCustAll.filter(isMomentec).map(c => ({...c, usd: 0}));
  const cap = MOCK.production.capacityByWeek || [];
  const com = MOCK.production.capacityCommitted || [];
  const totalCap = cap.at(-1) || 0;
  const totalCommit = com.at(-1) || 0;
  const utilization = totalCap ? Math.round((totalCommit / totalCap) * 100) : 0;
  const totalUnits = wip.reduce((a,b)=>a+(b.promised||0), 0);
  const totalUsd = wip.reduce((a,b)=>a+(b.usd||0), 0);
  const momentecUnits = wipMomentec.reduce((a,b)=>a+(b.promised||0), 0);
  const momentecPrograms = wipMomentec.length;
  const atRisk = wip.filter(w => w.status === 'bad').length;
  const watch = wip.filter(w => w.status === 'warn').length;
  const utilColor = utilization >= 95 ? '#b91c1c' : utilization >= 80 ? '#b45309' : '#16a34a';
  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Capacity & WIP</p>
        <h1>Open programs and weekly capacity load</h1>
        <p>Active programs (Work-In-Progress) and weekly capacity vs commitments. Source: ${escapeHtml((MOCK.production.wipSource||'WIP file').split('/').pop())}.</p>
      </div>
      ${SESSION.role !== 'admin' ? `<button class="btn btn-ghost btn-sm" onclick="navigate('upload')">+ Upload Data</button>` : ''}
    </div>

    <!-- CAPACITY ALLOCATED vs PRODUCED — attainment to plan (portal feedback r10/r11) -->
    ${(() => {
      const ca = (MOCK.production && MOCK.production.capacityAttainment) || null;
      if (!ca) return '';
      const att = ca.attainmentPct;
      const col = att==null?'#5a6b85':att>=90?'#16a34a':att>=70?'#b45309':'#b91c1c';
      const top = (ca.allocatedByCustomer||[]).slice(0,8);
      const maxA = Math.max(1, ...top.map(c=>c.allocated));
      return `
      <div class="panel" style="margin-bottom:18px">
        <div class="panel-head"><h2>Capacity plan attainment</h2><span class="panel-meta">allocated capacity (CAPACITY report) vs produced (Bihorario)</span></div>
        <div style="display:flex;gap:34px;flex-wrap:wrap;padding:18px 22px;align-items:center">
          <div style="text-align:center">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Attainment to plan</div>
            <div style="font-size:48px;font-weight:800;color:${col};line-height:1.1">${att!=null?att+'%':'—'}</div>
          </div>
          <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Produced</div><div style="font-size:24px;font-weight:800;color:#0a3d62">${fmtNum(ca.totalProduced)}</div></div>
          <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim)">Allocated capacity</div><div style="font-size:24px;font-weight:800">${fmtNum(ca.totalAllocated)}</div></div>
          <div style="flex:1;min-width:220px">
            <div style="height:22px;background:var(--paper-3);border-radius:11px;overflow:hidden;position:relative">
              <div style="height:100%;width:${Math.min(100,att||0)}%;background:${col};border-radius:11px"></div>
            </div>
            <div style="font-size:11px;color:var(--ink-dim);margin-top:4px">produced as a share of allocated capacity</div>
          </div>
        </div>
        ${top.length?`<div style="padding:0 22px 16px">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--ink-dim);margin-bottom:8px">Allocated capacity by customer</div>
          ${top.map(c=>`<div style="display:flex;align-items:center;gap:10px;margin-bottom:5px">
            <div style="width:120px;font-size:12px;font-weight:600">${escapeHtml(c.customer)}</div>
            <div style="flex:1;height:14px;background:var(--paper-3);border-radius:7px;overflow:hidden"><div style="height:100%;width:${Math.round(c.allocated/maxA*100)}%;background:#1c5b8a;border-radius:7px"></div></div>
            <div style="width:70px;text-align:right;font-size:12px">${fmtNum(c.allocated)}</div>
          </div>`).join('')}
        </div>`:''}
        <p style="padding:0 22px 12px;font-size:11px;color:var(--ink-dim)">${escapeHtml(ca.note||'')}</p>
      </div>` ;
    })()}

    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Open WIP programs</div><div class="kpi-value">${wip.length}</div><div class="kpi-delta flat">${byCust.length} customer${byCust.length===1?'':'s'}</div></div>
      <div class="kpi"><div class="kpi-label">WIP units (excl. Coreline)</div><div class="kpi-value">${fmtNum(totalUnits)}</div><div class="kpi-delta flat">${momentecUnits>0?'+ '+fmtNum(momentecUnits)+' Coreline separate':'across all programs'}</div></div>
      <div class="kpi"><div class="kpi-label">WIP value at risk</div><div class="kpi-value">${fmtMoney(Math.round(totalUsd))}</div><div class="kpi-delta flat">Coreline excluded — paid up front</div></div>
      <div class="kpi"><div class="kpi-label">At risk / watch</div><div class="kpi-value" style="color:${atRisk?'#b91c1c':'inherit'}">${atRisk} <span style="font-size:14px;color:#b45309">/ ${watch}</span></div><div class="kpi-delta flat">past req / due ≤7d</div></div>
    </div>

    ${(() => {
      const bench = MOCK.production && MOCK.production.capacityBenchmark;
      if (!bench) return '';
      const fmtUtil = (u) => `<span style="color:${u>=bench.targetPct?'#16a34a':u>=bench.targetPct*0.8?'#b45309':'#b91c1c'};font-weight:700">${u.toFixed(1)}%</span>`;
      const target = bench.targetPct;
      const ytd = bench.ytd;
      const ytdColor = ytd.utilization>=target?'#16a34a':ytd.utilization>=target*0.8?'#b45309':'#b91c1c';
      // Current week util = last weekly_data row (or first that's <= today)
      const currentWk = bench.weekly_data[bench.weekly_data.length-1] || {utilization:0,units:0};
      const currColor = currentWk.utilization>=target?'#16a34a':currentWk.utilization>=target*0.8?'#b45309':'#b91c1c';
      // Latest month
      const currentMo = bench.monthly_data[bench.monthly_data.length-1] || {utilization:0,label:'—'};
      const moColor = currentMo.utilization>=target?'#16a34a':currentMo.utilization>=target*0.8?'#b45309':'#b91c1c';
      return `
      <div class="panel" style="background:linear-gradient(135deg,#0a3d62 0%,#1c5b8a 100%);color:#fff;padding:24px;margin-bottom:18px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px">
          <div>
            <p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;margin:0 0 4px;opacity:.7">Capacity Benchmark</p>
            <h2 style="margin:0;color:#fff;font-size:22px">${fmtNum(bench.weekly)} units / week @ 100% · Target ${target}% = ${fmtNum(bench.weeklyTargetUnits)} units/wk</h2>
            <p style="margin:8px 0 0;opacity:.8;font-size:13px">Annual capacity ${fmtNum(bench.annual)} · Annual target ${fmtNum(bench.annualTargetUnits)} units</p>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin-top:24px">
          <div style="background:rgba(255,255,255,.1);padding:18px;border-radius:10px;text-align:center">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:1.5px;opacity:.7">Current Week</div>
            <div style="font-size:14px;opacity:.8;margin-top:4px">${escapeHtml(currentWk.label||'—')}</div>
            <div style="font-size:48px;font-weight:800;color:${currColor};line-height:1.1;margin-top:8px">${currentWk.utilization.toFixed(1)}%</div>
            <div style="font-size:13px;opacity:.85;margin-top:6px">${fmtNum(currentWk.units)} / ${fmtNum(bench.weekly)} units</div>
            <div style="font-size:12px;margin-top:6px">vs target: <strong>${currentWk.vsTarget>=0?'+':''}${currentWk.vsTarget.toFixed(1)}pp</strong></div>
          </div>
          <div style="background:rgba(255,255,255,.1);padding:18px;border-radius:10px;text-align:center">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:1.5px;opacity:.7">Current Month</div>
            <div style="font-size:14px;opacity:.8;margin-top:4px">${escapeHtml(currentMo.label||'—')}</div>
            <div style="font-size:48px;font-weight:800;color:${moColor};line-height:1.1;margin-top:8px">${currentMo.utilization.toFixed(1)}%</div>
            <div style="font-size:13px;opacity:.85;margin-top:6px">${fmtNum(currentMo.units||0)} / ${fmtNum(currentMo.capacity||0)} units</div>
            <div style="font-size:12px;margin-top:6px">vs target: <strong>${currentMo.vsTarget>=0?'+':''}${currentMo.vsTarget.toFixed(1)}pp</strong></div>
          </div>
          <div style="background:rgba(255,255,255,.1);padding:18px;border-radius:10px;text-align:center">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:1.5px;opacity:.7">YTD ${ytd.year}</div>
            <div style="font-size:14px;opacity:.8;margin-top:4px">${ytd.weeksReported} weeks reported</div>
            <div style="font-size:48px;font-weight:800;color:${ytdColor};line-height:1.1;margin-top:8px">${ytd.utilization.toFixed(1)}%</div>
            <div style="font-size:13px;opacity:.85;margin-top:6px">${fmtNum(ytd.units)} / ${fmtNum(ytd.capacity)} units</div>
            <div style="font-size:12px;margin-top:6px">vs target: <strong>${ytd.vsTarget>=0?'+':''}${ytd.vsTarget.toFixed(1)}pp</strong></div>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Weekly capacity utilization vs ${target}% target</h2><span class="panel-meta">12k units/wk @ 100% · ${bench.weeklyTargetUnits.toLocaleString()} units/wk @ ${target}%</span></div>
        <div class="chart-wrap tall"><canvas id="cwWeeklyUtil"></canvas></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Monthly capacity utilization vs ${target}% target</h2></div>
        <div class="chart-wrap"><canvas id="cwMonthlyUtil"></canvas></div>
      </div>`;
    })()}

    <div class="panel">
      <div class="panel-head"><h2>WIP by customer</h2></div>
      <table><thead><tr><th>Customer</th><th>Programs</th><th>Units</th><th>US$</th></tr></thead>
      <tbody>${byCust.length === 0 ? emptyRow(4) : byCust.map(r=>`<tr><td><strong>${escapeHtml(r.customer||'')}</strong></td><td>${r.programs}</td><td>${fmtNum(r.units)}</td><td>${fmtMoney(Math.round(r.usd||0))}</td></tr>`).join('')}</tbody></table>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>Open WIP programs — full list (excl. Coreline)</h2><span class="panel-meta">${wip.length} program${wip.length===1?'':'s'} · ${atRisk} at risk · ${watch} watch · Coreline shown separately below</span></div>
      <div style="overflow-x:auto"><table><thead><tr><th>Customer</th><th>Program</th><th>Units</th><th>US$</th><th>Earliest req</th><th>Status</th></tr></thead>
      <tbody>${wip.length === 0 ? emptyRow(6) : wip.map(r=>`<tr><td><strong>${escapeHtml(r.customer||'')}</strong></td><td>${escapeHtml(r.program)}</td><td>${fmtNum(r.promised)}</td><td>${fmtMoney(r.usd||0)}</td><td>${escapeHtml(r.reqDate||'—')}</td><td><span class="tag tag-${r.status||'good'}">${r.status==='good'?'On track':r.status==='warn'?'Watch':'At risk'}</span></td></tr>`).join('')}</tbody></table></div>
    </div>

    ${wipMomentec.length ? `
    <div class="panel" style="border-left:5px solid #1c5b8a;background:#eff6ff">
      <div class="panel-head" style="background:transparent">
        <h2 style="color:#0a3d62">Coreline — separate track (paid up front)</h2>
        <span class="panel-meta" style="color:#0a3d62"><strong>${momentecPrograms}</strong> programs · <strong>${fmtNum(momentecUnits)}</strong> units · <strong>no \\$ at risk</strong> · work down over time</span>
      </div>
      <div style="padding:12px 22px;background:rgba(255,255,255,.5);border-bottom:1px solid var(--line);font-size:13px;color:#0a3d62;line-height:1.5">
        Coreline has paid in advance, so these programs carry no receivable risk. They are isolated here so they don't distort attainment %, late-order \\$ at risk, or capacity pressure on the main view. Manage these as throughput-only — pace the work, don't chase the calendar.
      </div>
      <div style="overflow-x:auto"><table><thead><tr><th>Program</th><th>Units</th><th>Earliest req</th><th>Status</th></tr></thead>
      <tbody>${wipMomentec.map(r=>`<tr><td>${escapeHtml(r.program||'')}</td><td>${fmtNum(r.promised)}</td><td>${escapeHtml(r.reqDate||'—')}</td><td><span class="tag tag-${r.status||'good'}">${r.status==='good'?'On track':r.status==='warn'?'Watch':'At risk'}</span></td></tr>`).join('')}</tbody></table></div>
    </div>` : ''}
  `;
  const bench = MOCK.production && MOCK.production.capacityBenchmark;
  if (bench && document.getElementById('cwWeeklyUtil')) {
    const wkD = bench.weekly_data;
    const target = bench.targetPct;
    activeChart.push(new Chart(document.getElementById('cwWeeklyUtil'), {
      type: 'bar',
      data: { labels: wkD.map(w=>w.label), datasets: [
        { label: '% Utilization', data: wkD.map(w=>w.utilization), backgroundColor: wkD.map(w => w.utilization >= target ? '#16a34a' : w.utilization >= target*0.8 ? '#b45309' : '#b91c1c'), yAxisID:'y' },
        { label: `${target}% target`, data: wkD.map(()=>target), type:'line', borderColor:'#0a3d62', borderDash:[6,4], borderWidth:2, pointRadius:0, fill:false, yAxisID:'y' },
        { label: 'Units shipped', data: wkD.map(w=>w.units), type:'line', borderColor:'#cfe6f5', backgroundColor:'rgba(207,230,245,.3)', fill:false, tension:.25, pointRadius:3, yAxisID:'y1' },
      ]},
      options: {
        responsive:true, maintainAspectRatio:false,
        scales: {
          y: { position:'left', title:{display:true,text:'% Util'}, beginAtZero:true, max:100, ticks:{callback:(v)=>v+'%'} },
          y1:{ position:'right', title:{display:true,text:'Units'}, beginAtZero:true, grid:{display:false} },
          x: { ticks:{font:{size:10}} }
        },
        plugins:{ legend:{position:'bottom',labels:{font:{size:11}}} }
      }
    }));
  }
  if (bench && document.getElementById('cwMonthlyUtil')) {
    const moD = bench.monthly_data;
    const target = bench.targetPct;
    activeChart.push(new Chart(document.getElementById('cwMonthlyUtil'), {
      type: 'bar',
      data: { labels: moD.map(m=>m.label), datasets: [
        { label: '% Utilization', data: moD.map(m=>m.utilization), backgroundColor: moD.map(m => m.utilization >= target ? '#16a34a' : m.utilization >= target*0.8 ? '#b45309' : '#b91c1c') },
        { label: `${target}% target`, data: moD.map(()=>target), type:'line', borderColor:'#0a3d62', borderDash:[6,4], borderWidth:2, pointRadius:0, fill:false },
      ]},
      options: { responsive:true, maintainAspectRatio:false, scales:{ y:{beginAtZero:true,max:100,ticks:{callback:(v)=>v+'%'}}, x:{ticks:{font:{size:11}}} }, plugins:{ legend:{position:'bottom'} } }
    }));
  }
}

function renderFinance(root) {
  const totalPastDue = MOCK.finance.pastDueExpenses.reduce((a,b)=>a+(b.amount||0),0);
  const totalOpen = MOCK.finance.openExpenses.reduce((a,b)=>a+(b.amount||0),0);
  const totalShipped = MOCK.finance.shippedByCustomer.reduce((a,b)=>a+(b.shipped||0),0);
  const totalRevenue = MOCK.finance.shippedByCustomer.reduce((a,b)=>a+(b.revenue||0),0);
  const recSum = (MOCK.sales && MOCK.sales.receivableSummary) || [];
  const arOpen = recSum.reduce((a,b)=>a+(b.open||0),0);
  const arCurrent = recSum.reduce((a,b)=>a+(b.current||0),0);
  const arPast = recSum.reduce((a,b)=>a+((b.dpd30||0)+(b.dpd60||0)+(b.dpd90||0)),0);
  const arSorted = [...recSum].sort((a,b)=>(b.open||0)-(a.open||0));
  // 30/60/90 cash-flow projection — assume customers pay current within 30d,
  // dpd30 within ~15d, dpd60 within ~30d, dpd90 over the next 60-90d
  const cf30 = recSum.reduce((s,r)=>s+(r.current||0)+(r.dpd30||0)*0.5, 0);
  const cf60 = recSum.reduce((s,r)=>s+(r.dpd30||0)*0.5+(r.dpd60||0)*0.7, 0);
  const cf90 = recSum.reduce((s,r)=>s+(r.dpd60||0)*0.3+(r.dpd90||0)*0.5, 0);
  const cfTotal = cf30 + cf60 + cf90;
  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">Finance & Receivables</p>
        <h1>Who owes us money</h1>
        <p>Open A/R by customer — biggest first. Cash-flow projection. Expenses below.</p>
      </div>
      ${SESSION.role !== 'admin' ? `<button class="btn btn-ghost btn-sm" onclick="navigate('upload')">+ Upload Data</button>` : ''}
    </div>

    <!-- MONEY COMING IN — PRIORITY -->
    <div class="panel" style="background:linear-gradient(135deg,#16a34a 0%,#15803d 100%);color:#fff;padding:24px;margin-bottom:18px">
      <p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;margin:0 0 4px;opacity:.85">Money Coming In · Open A/R</p>
      <div style="display:flex;align-items:baseline;gap:24px;flex-wrap:wrap">
        <h2 style="margin:0;color:#fff;font-size:48px;font-weight:800;line-height:1">${fmtMoney(arOpen)}</h2>
        <span style="font-size:14px;opacity:.9">${recSum.length} customer${recSum.length===1?'':'s'} · ${fmtMoney(arCurrent)} current · <strong>${fmtMoney(arPast)} past due</strong></span>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2 style="font-weight:800">Who owes us money — biggest first</h2><span class="panel-meta">click any customer for invoice detail · live from AR_Report</span></div>
      <table>
        <thead><tr><th>Customer</th><th>Open</th><th>Current</th><th>1–30</th><th>31–60</th><th>61+</th><th>Status</th></tr></thead>
        <tbody>${arSorted.length === 0 ? emptyRow(7) : arSorted.map((r,i) => `
          <tr style="${i===0 ? 'background:#fff3f3;font-weight:700' : ''};cursor:pointer" onclick="navigate('sales')">
            <td><strong style="color:#0a3d62;font-size:${i===0?'15px':'13px'}">${escapeHtml(r.customer)}</strong>${i===0?' <span style="font-size:10px;background:#b91c1c;color:#fff;padding:2px 7px;border-radius:10px;margin-left:4px">#1</span>':''}</td>
            <td><strong style="font-size:${i===0?'15px':'13px'}">${fmtMoney(r.open||0)}</strong></td>
            <td>${fmtMoney(r.current||0)}</td>
            <td>${fmtMoney(r.dpd30||0)}</td>
            <td>${fmtMoney(r.dpd60||0)}</td>
            <td><strong style="color:${(r.dpd90||0)>0?'#b91c1c':'inherit'}">${fmtMoney(r.dpd90||0)}</strong></td>
            <td><span class="tag tag-${r.status||'good'}">${r.status==='good'?'Paying on time':r.status==='warn'?'Watch':'Past due'}</span></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>

    <!-- TERMS-BASED RECEIVABLES FORECAST -->
    ${(() => {
      const ex = MOCK.sales.expectedByDueDate;
      if (!ex) return '';
      const upcoming = (ex.upcoming || []).slice(0, 6);
      return `
      <div class="panel">
        <div class="panel-head"><h2>Expected receivables — by invoice due date</h2><span class="panel-meta">from real QB invoice due dates (not aging estimates)</span></div>
        <div style="padding:14px 22px 0">
          <p style="margin:0 0 14px;font-size:13px;color:#1a1a1a;line-height:1.5">
            <strong>Past due:</strong> <span style="color:#b91c1c;font-weight:700">${fmtMoney(ex.pastDue.total||0)}</span> already overdue, biggest = <strong>${ex.pastDue.byCustomer[0]?escapeHtml(ex.pastDue.byCustomer[0].customer):'—'}</strong> ${ex.pastDue.byCustomer[0]?fmtMoney(ex.pastDue.byCustomer[0].amount):''}. <strong>Next 4 weeks:</strong> ${fmtMoney(ex.upcoming4wk||0)} expected based on invoice due dates currently on file.
          </p>
        </div>
        <div style="overflow-x:auto;padding:0 22px 18px">
          <table>
            <thead>
              <tr style="border-bottom:2px solid #0a3d62">
                <th>Week</th>
                ${upcoming.map(u => `<th style="text-align:right">${escapeHtml(u.label)}</th>`).join('')}
                <th style="text-align:right;background:#f8fafc">Past due</th>
                <th style="text-align:right;background:#0a3d62;color:#fff">Total expected</th>
              </tr>
            </thead>
            <tbody>
              ${(() => {
                const allCusts = new Set();
                upcoming.forEach(u => u.byCustomer.forEach(b => allCusts.add(b.customer)));
                ex.pastDue.byCustomer.forEach(b => allCusts.add(b.customer));
                const custList = Array.from(allCusts);
                custList.sort((a,b) => {
                  const sumOf = (cust) => {
                    let s = 0;
                    upcoming.forEach(u => { const m = u.byCustomer.find(x => x.customer===cust); if (m) s+=m.amount; });
                    const pd = ex.pastDue.byCustomer.find(x => x.customer===cust); if (pd) s += pd.amount;
                    return s;
                  };
                  return sumOf(b) - sumOf(a);
                });
                return custList.map(c => {
                  const pd = (ex.pastDue.byCustomer.find(x => x.customer===c) || {}).amount || 0;
                  const cells = upcoming.map(u => {
                    const m = u.byCustomer.find(x => x.customer===c);
                    return m && m.amount > 0 ? fmtMoney(m.amount) : '<span style="color:var(--ink-dim)">—</span>';
                  });
                  let tot = pd + upcoming.reduce((s,u) => {
                    const m = u.byCustomer.find(x => x.customer===c); return s + (m?m.amount:0);
                  }, 0);
                  return `<tr>
                    <td><strong>${escapeHtml(c)}</strong></td>
                    ${cells.map(v => `<td style="text-align:right">${v}</td>`).join('')}
                    <td style="text-align:right;background:#f8fafc;color:${pd>0?'#b91c1c':'inherit'};font-weight:${pd>0?'700':'400'}">${pd>0?fmtMoney(pd):'—'}</td>
                    <td style="text-align:right;background:#0a3d62;color:#fff"><strong>${fmtMoney(tot)}</strong></td>
                  </tr>`;
                }).join('');
              })()}
              <tr style="background:#f8fafc;font-weight:700">
                <td>Week total</td>
                ${upcoming.map(u => `<td style="text-align:right"><strong>${fmtMoney(u.total||0)}</strong></td>`).join('')}
                <td style="text-align:right;color:#b91c1c"><strong>${fmtMoney(ex.pastDue.total||0)}</strong></td>
                <td style="text-align:right;background:#0a3d62;color:#fff"><strong>${fmtMoney((ex.pastDue.total||0) + (ex.upcoming4wk||0))}</strong></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p style="padding:0 22px 14px;font-size:11px;color:var(--ink-dim);font-style:italic">Source: AR_Report open invoices with real due dates from QuickBooks. Past-due column = invoices that have already passed their due date but haven't been paid. Each weekly column = amount due that week.</p>
      </div>
    `;
    })()}
    <div class="panel" style="background:#fff3f3;border-left:5px solid #b91c1c;padding:18px 22px;margin-top:28px;margin-bottom:0">
      <p style="font-size:11px;letter-spacing:2px;text-transform:uppercase;margin:0 0 4px;color:#b91c1c;font-weight:700">Money Going Out · A/P</p>
      <div style="display:flex;align-items:baseline;gap:24px;flex-wrap:wrap">
        <h2 style="margin:0;color:#b91c1c;font-size:32px;font-weight:800;line-height:1">${fmtMoney(totalPastDue)} past-due</h2>
        <span style="font-size:13px;color:#1a1a1a">${MOCK.finance.pastDueExpenses.length} late bills · ${fmtMoney(totalOpen)} also coming due (${MOCK.finance.openExpenses.length} bills)</span>
      </div>
    </div>

    <!-- AP BY CATEGORY (from FINANCE_PARA_REPORTES) -->
    ${(() => {
      const ac = (MOCK.finance && MOCK.finance.apByCategory) || null;
      if (!ac || !ac.byCategory || !ac.byCategory.length) return '';
      const max = Math.max(1, ...ac.byCategory.map(c=>c.open));
      return `
      <div class="panel">
        <div class="panel-head"><h2>What we owe — by category</h2><span class="panel-meta">${fmtMoney(ac.totalOpen)} open A/P across ${ac.byCategory.length} categories</span></div>
        <div style="padding:6px 22px 16px">
          ${ac.byCategory.slice(0,10).map(c=>`<div style="display:flex;align-items:center;gap:10px;margin:7px 0">
            <div style="width:160px;font-size:13px;font-weight:600">${escapeHtml(c.category)}</div>
            <div style="flex:1;height:16px;background:var(--paper-3);border-radius:8px;overflow:hidden"><div style="height:100%;width:${Math.round(c.open/max*100)}%;background:#b45309;border-radius:8px"></div></div>
            <div style="width:110px;text-align:right;font-size:13px;font-weight:700">${fmtMoney(c.open)}</div>
            <div style="width:90px;text-align:right;font-size:11px;color:${c.pastDue>0?'#b91c1c':'var(--ink-dim)'}">${c.pastDue>0?fmtMoney(c.pastDue)+' late':''}</div>
          </div>`).join('')}
        </div>
        <p style="padding:0 22px 12px;font-size:11px;color:var(--ink-dim)">${escapeHtml(ac.note||'')}</p>
      </div>` ;
    })()}

    <div class="grid-2">
      <div class="panel">
        <div class="panel-head" style="cursor:pointer" onclick="(function(){var el=document.getElementById('pastDueExp');var ch=document.getElementById('pastDueChev');if(el){var open=el.style.display!=='none';el.style.display=open?'none':'block';if(ch)ch.textContent=open?'▸':'▾';}})()">
          <h2>Past-due expenses</h2>
          <span class="panel-meta"><strong>${fmtMoney(totalPastDue)}</strong> across ${MOCK.finance.pastDueExpenses.length} bill${MOCK.finance.pastDueExpenses.length===1?'':'s'} <span id="pastDueChev" style="margin-left:6px">▸</span></span>
        </div>
        <div id="pastDueExp" style="display:none;overflow-x:auto;max-height:520px;overflow-y:auto"><table>
        <thead><tr><th>Vendor</th><th>Category</th><th>Amount</th><th>Days late</th><th>Due date</th></tr></thead>
        <tbody>${MOCK.finance.pastDueExpenses.length === 0 ? emptyRow(5) : MOCK.finance.pastDueExpenses.map(r=>{
          const d=r.dueDays||0;
          const sev=d>365?'bad':d>60?'bad':d>14?'warn':'good';
          const label=d>365?Math.round(d/365)+'y '+(d%365)+'d': d>30?Math.round(d/30)+'mo': d+'d';
          return `<tr><td><strong>${escapeHtml(r.vendor)}</strong></td><td style="font-size:11px;color:var(--ink-dim)">${escapeHtml(r.category||'')}</td><td><strong>${fmtMoney(r.amount)}</strong></td><td><span class="tag tag-${sev}">${label} late</span></td><td style="font-size:11px;color:var(--ink-dim)">${escapeHtml(r.due||'—')}</td></tr>`;
        }).join('')}</tbody></table></div>
      </div>
      <div class="panel">
        <div class="panel-head" style="cursor:pointer" onclick="(function(){var el=document.getElementById('openExp');var ch=document.getElementById('openExpChev');if(el){var open=el.style.display!=='none';el.style.display=open?'none':'block';if(ch)ch.textContent=open?'▸':'▾';}})()">
          <h2>Open expenses (upcoming)</h2>
          <span class="panel-meta"><strong>${fmtMoney(totalOpen)}</strong> across ${MOCK.finance.openExpenses.length} bill${MOCK.finance.openExpenses.length===1?'':'s'} <span id="openExpChev" style="margin-left:6px">▸</span></span>
        </div>
        <div id="openExp" style="display:none;overflow-x:auto;max-height:520px;overflow-y:auto"><table>
        <thead><tr><th>Vendor</th><th>Category</th><th>Amount</th><th>Due</th></tr></thead>
        <tbody>${MOCK.finance.openExpenses.length === 0 ? emptyRow(4) : MOCK.finance.openExpenses.map(r=>`<tr><td><strong>${escapeHtml(r.vendor)}</strong></td><td style="font-size:11px;color:var(--ink-dim)">${escapeHtml(r.category||'')}</td><td><strong>${fmtMoney(r.amount)}</strong></td><td style="font-size:11px;color:var(--ink-dim)">${escapeHtml(r.due||'—')}</td></tr>`).join('')}</tbody></table></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>Shipped to date by customer (YTD ${MOCK.finance.shippedYear || 2026})</h2><span class="panel-meta">${MOCK.finance.shippedByCustomer.length} customer${MOCK.finance.shippedByCustomer.length===1?'':'s'} · single source: SHIPPINGREPORT · Bellforge shown net of its 35% discount</span></div>
      <div class="chart-wrap"><canvas id="fnByCust"></canvas></div>
      <div style="overflow-x:auto;padding:0 18px 14px">
        <table>
          <thead><tr><th>Customer</th><th style="text-align:right">Units shipped (YTD)</th><th style="text-align:right">$ shipped (YTD)</th><th style="text-align:right">$ net of discount</th><th style="text-align:right">Avg $/unit</th></tr></thead>
          <tbody>${MOCK.finance.shippedByCustomer.length === 0 ? emptyRow(5) : MOCK.finance.shippedByCustomer.map(r => {
            const ppu = r.units > 0 ? (r.usdShipped/r.units) : null;
            const net = r.revenueNet != null ? r.revenueNet : (r.revenue||0);
            return `<tr>
              <td><strong>${escapeHtml(r.customer)}</strong>${r.discountPct ? ` <span class="tag tag-warn">-${r.discountPct}%</span>` : ''}</td>
              <td style="text-align:right"><strong>${fmtNum(r.units||0)}</strong></td>
              <td style="text-align:right">${fmtMoney(r.usdShipped||0)}</td>
              <td style="text-align:right${r.discountPct ? ';color:#b45309;font-weight:700' : ''}">${fmtMoney(net)}</td>
              <td style="text-align:right;color:var(--ink-dim)">${ppu==null?'—':'$'+ppu.toFixed(2)}</td>
            </tr>`;
          }).join('')}
          <tr style="background:#f8fafc;font-weight:700">
            <td>TOTAL</td>
            <td style="text-align:right"><strong>${fmtNum(MOCK.finance.shippedByCustomer.reduce((a,b)=>a+(b.units||0),0))}</strong></td>
            <td style="text-align:right">${fmtMoney(MOCK.finance.shippedByCustomer.reduce((a,b)=>a+(b.usdShipped||0),0))}</td>
            <td style="text-align:right">${fmtMoney(MOCK.finance.shippedByCustomer.reduce((a,b)=>a+(b.revenueNet!=null?b.revenueNet:(b.revenue||0)),0))}</td>
            <td></td>
          </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>13-week revenue PROJECTION</h2><span class="panel-meta" style="color:#b45309">forecast — not real A/R</span></div>
      <div class="chart-wrap"><canvas id="fn13wk"></canvas></div>
      <p style="font-size:12px;color:#b45309;margin-top:8px;font-weight:600">⚠ ${(MOCK.sales && MOCK.sales.thirteenWeekOutlook && MOCK.sales.thirteenWeekOutlook.note) ? escapeHtml(MOCK.sales.thirteenWeekOutlook.note) : 'Projection from forecast file.'}</p>
    </div>

    <div class="panel">
      ${(() => {
        const yb = (MOCK.sales && MOCK.sales.yearByMonth) || {};
        const labels = yb.labels || ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        const actualMos = new Set(yb.monthsActual || [0,1,2,3]);
        const byCust = yb.byCustomer || [];
        const totals = yb.totalRevenue || [];
        const ytdActual = totals.filter((_,i)=>actualMos.has(i)).reduce((s,v)=>s+(v||0),0);
        const fcRemainder = totals.filter((_,i)=>!actualMos.has(i)).reduce((s,v)=>s+(v||0),0);
        const annual = ytdActual + fcRemainder;
        const headTags = labels.map((m,i) => actualMos.has(i)
          ? `<th style="background:#dbeafe;color:#0a3d62">${m}<br/><span style="font-size:9px;font-weight:600;letter-spacing:1px">ACTUAL</span></th>`
          : `<th>${m}<br/><span style="font-size:9px;font-weight:600;letter-spacing:1px;color:#b45309">forecast</span></th>`).join('');
        const bodyRows = byCust.length === 0 ? emptyRow(14) : byCust.map(r => `<tr>
          <td><strong>${escapeHtml(r.customer)}</strong></td>
          ${r.monthly.map((v,i) => {
            const isActual = (r.monthlyKind && r.monthlyKind[i]==='actual') || actualMos.has(i);
            const bg = isActual ? 'background:#eff6ff' : '';
            return `<td style="${bg}">${v?fmtMoney(v):'—'}</td>`;
          }).join('')}
          <td><strong>${fmtMoney(r.annual)}</strong></td>
        </tr>`).join('');
        const totalsRow = `<tr style="background:#f8fafc;font-weight:700">
          <td>TOTAL</td>
          ${totals.map((t,i) => {
            const bg = actualMos.has(i) ? 'background:#dbeafe' : '';
            return `<td style="${bg}">${fmtMoney(t||0)}</td>`;
          }).join('')}
          <td><strong>${fmtMoney(annual)}</strong></td>
        </tr>`;
        return `
        <div class="panel-head"><h2>2026 revenue by month — actual + forecast</h2><span class="panel-meta"><strong style="color:#0a3d62">ACTUAL</strong> = invoiced revenue from the Sales report · later months <strong style="color:#b45309">forecast</strong></span></div>
        <div style="display:flex;gap:18px;flex-wrap:wrap;padding:0 18px 12px">
          <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">YTD Actual${(()=>{const a=[...actualMos].sort((x,y)=>x-y);return a.length?` (${labels[a[0]]}–${labels[a[a.length-1]]})`:'';})()}</div><div style="font-size:22px;font-weight:800;color:#0a3d62">${fmtMoney(ytdActual)}</div></div>
          <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Forecast (rest of year)</div><div style="font-size:22px;font-weight:800;color:#b45309">${fmtMoney(fcRemainder)}</div></div>
          <div><div style="font-size:11px;color:var(--ink-dim);text-transform:uppercase;letter-spacing:1px">Year total (actual + forecast)</div><div style="font-size:22px;font-weight:800">${fmtMoney(annual)}</div></div>
        </div>
        ${yb.actualSource ? `<p style="font-size:11px;color:var(--ink-dim);margin:0 18px 8px">Actual source: <code>${escapeHtml((yb.actualSource||'').split('/').pop())}</code></p>` : ''}
        ${yb.note ? `<p style="font-size:11px;color:#b45309;margin:0 18px 12px">⚠ ${escapeHtml(yb.note)}</p>` : ''}
        <div class="chart-wrap"><canvas id="fnYearMonth"></canvas></div>
        <div style="overflow-x:auto;margin-top:14px">
          <table>
            <thead><tr><th>Customer</th>${headTags}<th>Annual</th></tr></thead>
            <tbody>${bodyRows}${totalsRow}</tbody>
          </table>
        </div>`;
      })()}
    </div>
  `;
  activeChart.push(new Chart(document.getElementById('fnByCust'), { type:'bar', data:{labels:MOCK.finance.shippedByCustomer.map(b=>b.customer),datasets:[
    {label:'Units shipped',data:MOCK.finance.shippedByCustomer.map(b=>b.shipped),backgroundColor:'#0a3d62',yAxisID:'y'},
    {label:'Revenue ($)',data:MOCK.finance.shippedByCustomer.map(b=>b.revenue),backgroundColor:'#f5a623',yAxisID:'y1'},
  ]}, options: { ...chartOpts(true), scales: {
    y:  { position:'left',  title:{display:true,text:'Units'}, grid:{color:'rgba(0,0,0,.05)'}, ticks:{font:{size:11}} },
    y1: { position:'right', title:{display:true,text:'Revenue ($)'}, grid:{display:false}, ticks:{font:{size:11}, callback:(v)=>'$'+(v/1000).toFixed(0)+'k'} },
    x:  { grid:{display:false}, ticks:{font:{size:11}} },
  } }}));

  // 13-week outlook chart
  const tw = (MOCK.sales && MOCK.sales.thirteenWeekOutlook) || {};
  if (tw.labels && tw.projection) {
    activeChart.push(new Chart(document.getElementById('fn13wk'), {
      type: 'bar',
      data: { labels: tw.labels, datasets: [{ label: 'Projected $', data: tw.projection, backgroundColor: '#2bb673' }] },
      options: { ...chartOpts(false, true) },
    }));
  }
  // Year by month chart
  const ym = (MOCK.sales && MOCK.sales.yearByMonth) || {};
  if (ym.labels && ym.totalRevenue) {
    activeChart.push(new Chart(document.getElementById('fnYearMonth'), {
      type: 'bar',
      data: { labels: ym.labels, datasets: [{ label: 'Revenue $', data: ym.totalRevenue, backgroundColor: '#0a3d62' }] },
      options: { ...chartOpts(false, true) },
    }));
  }
}

/* ============================================================
 * UPLOAD VIEW (sub-account)
 * ============================================================ */
function renderUpload(root) {
  const isAdmin = SESSION.role === 'admin';
  // Per-user (multi-section) accounts have section: null — route their uploads by
  // filename into uploads/admin/ (where the loop processes them), like jdorf.
  const isMulti = Array.isArray(SESSION.sections) && SESSION.sections.length > 0;
  const routeByName = isAdmin || isMulti;
  const secMeta = SECTIONS[SESSION.section];
  const sectionLabel = routeByName ? (isAdmin ? 'Admin · Upload' : 'Upload') : (secMeta ? secMeta.label : 'Upload');
  const targetDescription = routeByName
    ? 'Drop your file — we\'ll route it to the right section based on the filename.'
    : `Files go to <code>uploads/${SESSION.section}/</code> and are processed within 15 minutes.`;
  const defaultSection = routeByName ? 'admin' : SESSION.section;
  const sectionPicker = `<input type="hidden" id="uploadSection" value="${defaultSection}" />`;

  // Pre-flight: is the GitHub token present? With SHARED_GH_TOKEN baked in at script load,
  // this is essentially always true. The unlock path remains as a safety net.
  const hasToken = !!(localStorage.getItem('asa_github_token') || (SESSION.secrets && SESSION.secrets.githubToken) || (typeof SHARED_GH_TOKEN !== 'undefined' && SHARED_GH_TOKEN));
  // Paste-a-key UI: drop in a fine-grained GitHub PAT to enable real uploads.
  // The key lives only in this browser (localStorage) and is never committed.
  const repoSlug = `${SESSION.repo.owner}/${SESSION.repo.repo}`;
  const unlockBlock = hasToken ? `
    <div class="panel" style="background:#f0fbf4;border:1px solid #16a34a">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <strong style="color:#16a34a">✓ Uploads enabled</strong>
        <span style="color:var(--ink-dim);font-size:13px">committing to <code>${escapeHtml(repoSlug)}</code></span>
        <button id="ghKeyRemove" class="btn btn-ghost btn-sm" style="margin-left:auto">Remove key</button>
      </div>
    </div>
  ` : `
    <div class="panel" style="background:#fff8e6;border:1px solid #d4a017">
      <div class="panel-head"><h2 style="color:#8a6d1f">🔑 Paste a GitHub key to enable uploads</h2></div>
      <p style="font-size:13px;color:var(--ink-dim);margin:0 0 12px">Create a fine-grained token at <a href="https://github.com/settings/personal-access-tokens" target="_blank" rel="noopener" style="color:#1c5b8a">github.com/settings</a> with <strong>Contents: Read and write</strong> on <code>${escapeHtml(repoSlug)}</code>. Stored only in this browser; never committed.</p>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="password" id="ghKeyInput" placeholder="Paste a GitHub token (ghp_… or github_pat_…)" style="flex:1;min-width:260px;padding:10px 14px;border:1px solid #d4a017;border-radius:8px;font-size:14px" />
        <button id="ghKeySave" class="btn btn-primary">Save key</button>
        <span id="ghKeyMsg" style="font-size:13px;font-weight:600"></span>
      </div>
    </div>
  `;

  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">${sectionLabel}</p>
        <h1>Upload data</h1>
        <p>${targetDescription}</p>
      </div>
    </div>
    ${unlockBlock}
    <div class="panel upload-panel">
      ${sectionPicker}
      <label class="upload-zone" id="dropZone" style="${hasToken ? '' : 'opacity:.5;pointer-events:none'}">
        <div class="upload-cloud">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 16l-4-4-4 4"/><path d="M12 12v9"/><path d="M20.4 14.5A5 5 0 0 0 18 5h-1.3A8 8 0 1 0 4 14.7"/></svg>
        </div>
        <strong>Drop files here</strong>
        <span class="upload-sub">or <u>click to browse</u></span>
        <div class="upload-types">
          <span class="ftype ftype-xls">XLSX</span>
          <span class="ftype ftype-csv">CSV</span>
          <span class="ftype ftype-pdf">PDF</span>
          <span class="ftype ftype-doc">DOCX</span>
          <span class="ftype ftype-img">PNG/JPG</span>
        </div>
        <span class="upload-limit">up to 25 MB per file · multiple files OK</span>
        <input type="file" multiple class="upload-input" id="fileInput" ${hasToken ? '' : 'disabled'} />
      </label>
      <div id="uploadStatus" style="margin-top:14px"></div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Recent uploads</h2><span class="panel-meta">${isAdmin ? 'all sections' : 'your section'}</span></div>
      <div class="uploaded-list" id="uploadedList"><p style="color:var(--ink-dim);font-size:13px">Loading…</p></div>
    </div>
  `;


  if (hasToken) {
    const removeBtn = document.getElementById('ghKeyRemove');
    removeBtn?.addEventListener('click', () => {
      try { localStorage.removeItem('asa_github_token'); } catch {}
      if (SESSION.secrets) SESSION.secrets.githubToken = null;
      try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(SESSION)); } catch {}
      showToast('GitHub key removed.', 'info');
      renderUpload(root); // re-render back to the paste-key state
    });
  } else {
    const keyEl = document.getElementById('ghKeyInput');
    const btn = document.getElementById('ghKeySave');
    const msg = document.getElementById('ghKeyMsg');
    const doSave = () => {
      const tok = (keyEl.value || '').trim();
      if (!tok) { msg.style.color = '#7a1f1f'; msg.textContent = 'paste a key first'; return; }
      localStorage.setItem('asa_github_token', tok);
      if (SESSION.secrets) SESSION.secrets.githubToken = tok;
      try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(SESSION)); } catch {}
      showToast('✓ GitHub key saved — uploads enabled.', 'success');
      renderUpload(root); // re-render to enable the dropzone
    };
    btn.addEventListener('click', doSave);
    keyEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doSave(); } });
  }

  const drop = document.getElementById('dropZone');
  const input = document.getElementById('fileInput');
  drop.addEventListener('click', () => { if (hasToken) input.click(); });
  ['dragenter','dragover'].forEach((ev) => drop.addEventListener(ev, (e)=>{ e.preventDefault(); if (hasToken) drop.classList.add('drag'); }));
  ['dragleave','drop'].forEach((ev) => drop.addEventListener(ev, (e)=>{ e.preventDefault(); drop.classList.remove('drag'); }));
  drop.addEventListener('drop', (e) => { if (hasToken) handleFiles(e.dataTransfer.files); });
  input.addEventListener('change', () => handleFiles(input.files));
  refreshSectionUploads();
}

function getUploadSection() {
  const sel = document.getElementById('uploadSection');
  if (sel) return sel.value;
  return SESSION.section || 'admin';
}

const PENDING_UPLOADS_KEY = 'asa_pending_uploads_v1';
function getPendingUploads() {
  try {
    const raw = sessionStorage.getItem(PENDING_UPLOADS_KEY) || localStorage.getItem(PENDING_UPLOADS_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    const now = Date.now();
    return arr.filter(p => !p._pending_until || p._pending_until > now);
  } catch { return []; }
}
function addPendingUpload(u) {
  const arr = getPendingUploads();
  arr.push(u);
  try { sessionStorage.setItem(PENDING_UPLOADS_KEY, JSON.stringify(arr)); } catch {}
  try { localStorage.setItem(PENDING_UPLOADS_KEY, JSON.stringify(arr)); } catch {}
}
function dropPendingUploadsByPaths(paths) {
  if (!paths || !paths.size) return;
  const arr = getPendingUploads().filter(p => !paths.has(p.path));
  try { sessionStorage.setItem(PENDING_UPLOADS_KEY, JSON.stringify(arr)); } catch {}
  try { localStorage.setItem(PENDING_UPLOADS_KEY, JSON.stringify(arr)); } catch {}
}

/* ============================================================
 * TOAST — top-center notification for upload/comment success/failure.
 * Visible for 4s, click-to-dismiss.
 * ============================================================ */
function showToast(msg, type) {
  let host = document.getElementById('asaToastHost');
  if (!host) {
    host = document.createElement('div');
    host.id = 'asaToastHost';
    host.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:9999;display:flex;flex-direction:column;gap:8px;align-items:center;pointer-events:none';
    document.body.appendChild(host);
  }
  const t = document.createElement('div');
  const bg = type === 'error' ? '#7a1f1f' : type === 'info' ? '#1c5b8a' : '#16a34a';
  t.style.cssText = `pointer-events:auto;background:${bg};color:#fff;padding:12px 22px;border-radius:10px;font-size:14px;font-weight:600;box-shadow:0 8px 24px rgba(0,0,0,0.2);max-width:560px;cursor:pointer;animation:asaToastIn 0.18s ease-out`;
  t.textContent = msg;
  t.addEventListener('click', () => t.remove());
  host.appendChild(t);
  setTimeout(() => t.remove(), type === 'error' ? 8000 : 4000);
}
(function injectToastCSS() {
  if (document.getElementById('asaToastStyles')) return;
  const s = document.createElement('style');
  s.id = 'asaToastStyles';
  s.textContent = '@keyframes asaToastIn { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:none; } }';
  document.head.appendChild(s);
})();

async function handleFiles(files) {
  const status = document.getElementById('uploadStatus');
  const section = getUploadSection();
  // Token from local Settings beats anything else — direct GitHub commit, no Azure needed.
  const localToken = localStorage.getItem('asa_github_token') || (typeof SHARED_GH_TOKEN !== 'undefined' ? SHARED_GH_TOKEN : null);

  for (const f of Array.from(files)) {
    status.innerHTML = `<div class="uploaded-row"><div class="file-icon">…</div><div class="file-name">Uploading ${escapeHtml(f.name)} → ${section}…</div></div>`;
    try {
      const buf = await f.arrayBuffer();
      const contentBase64 = bytesToB64(buf);

      if (localToken) {
        // Direct GitHub path — bypasses Azure completely
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const safe = f.name.replace(/[^A-Za-z0-9._-]/g, '_');
        const path = `uploads/${section}/${ts}__${SESSION.username}__${safe}`;
        const r = await fetch(`https://api.github.com/repos/${SESSION.repo.owner}/${SESSION.repo.repo}/contents/${path}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${localToken}`,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message: `Upload ${safe} (${section}) by ${SESSION.username}`,
            content: contentBase64,
            branch: 'main',
          }),
        });
        if (!r.ok) {
          const err = (await r.text()).slice(0, 200);
          if (r.status === 401 || r.status === 403) {
            // Shared token was rejected — likely expired/revoked at GitHub. Tell the admin to rotate.
            throw new Error(`GitHub ${r.status} — shared upload token was rejected. It may have expired or been revoked. Contact the site admin to rotate SHARED_GH_TOKEN in admin/admin.js.`);
          }
          throw new Error(`GitHub ${r.status}: ${err}`);
        }
        // Track as pending so the file is visible in the list even if GitHub's
        // directory-listing cache hasn't caught up yet (~30-60s lag).
        addPendingUpload({
          path,
          name: ts + '__' + SESSION.username + '__' + safe,
          original: f.name,
          uploader: SESSION.username,
          uploadedAt: new Date().toISOString(),
          section,
          size: f.size,
          sha: null,
          _pending_until: Date.now() + 10 * 60 * 1000,
        });
      } else if (API_BASE) {
        // Azure path: POST to /api/upload (cookie auth)
        const r = await fetch(API_BASE + '/api/upload', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename: f.name, contentBase64, section }),
        });
        if (!r.ok) throw new Error('Upload failed: ' + r.status + ' ' + (await r.text()).slice(0, 200));
      } else {
        throw new Error('No upload method configured. Open Settings and paste a GitHub token.');
      }
      status.innerHTML = `<div style="color:var(--green);font-weight:700;font-size:13px">✓ Uploaded ${escapeHtml(f.name)} → ${section}</div>`;
      showToast('✓ Uploaded ' + f.name + ' → ' + section, 'success');
    } catch (e) {
      status.innerHTML = `<div style="color:var(--red);font-weight:700;font-size:13px">✗ ${escapeHtml(e.message)}</div>`;
      showToast('Upload failed: ' + (e.message || 'unknown error'), 'error');
    }
  }
  // Refresh immediately and again later — pending list keeps the upload visible
  // throughout the GitHub CDN lag window.
  refreshSectionUploads();
  setTimeout(refreshSectionUploads, 6000);
  setTimeout(refreshSectionUploads, 20000);
}

async function getSnapshotData() {
  // The decrypted dashboard snapshot (uploadsIndex / commentsIndex live here).
  // Prefer the already-decrypted in-memory MOCK; fall back to decrypting
  // data.enc.json. Replaces the old plaintext /admin/data.json fetch, which is
  // no longer served (it was publicly readable — removed for security).
  try {
    if (typeof MOCK === 'object' && MOCK && (Array.isArray(MOCK.uploadsIndex) || Array.isArray(MOCK.commentsIndex))) return MOCK;
  } catch {}
  if (MASTER_PASSWORD) {
    try {
      const r = await fetch('/admin/data.enc.json?t=' + Date.now(), { cache: 'no-store' });
      if (r.ok) { const d = await AsaCrypto.decryptJSON(await r.json(), MASTER_PASSWORD); if (d) return d; }
    } catch {}
  }
  return null;
}

async function loadUploadsViaSnapshot(section) {
  // uploadsIndex from the decrypted snapshot — no GitHub API, no rate limit, no
  // CORS. The AI loop keeps uploadsIndex up to date on every pass.
  const d = await getSnapshotData();
  if (!d) throw new Error('snapshot unavailable');
  let arr = Array.isArray(d.uploadsIndex) ? d.uploadsIndex : [];
  // Normalize: snapshot entries only carry path/id/section/size/mtime — derive
  // original/uploader/uploadedAt from the filename so renderers don't crash on
  // f.original.split('.').
  arr = arr.map(u => {
    const filename = u.name || (u.path ? u.path.split('/').pop() : (u.id || ''));
    const meta = parseUploadName(filename);
    return {
      ...u,
      name: filename,
      original: u.original || meta.original || filename,
      uploader: u.uploader || meta.uploader || '',
      uploadedAt: u.uploadedAt || meta.uploadedAt || u.mtime || '',
      derivedSection: classifyUploadByName(u.original || meta.original || filename) || u.section,
    };
  });
  if (section) arr = arr.filter(u => (u.derivedSection || u.section) === section);
  return arr;
}

function fileExtClass(name) {
  const ext = ((name||'').split('.').pop() || '').toLowerCase();
  if (['xlsx','xls','xlsm','csv','tsv'].includes(ext)) return ext === 'csv' || ext === 'tsv' ? 'fcsv' : 'fxls';
  if (['pdf'].includes(ext)) return 'fpdf';
  if (['doc','docx','rtf','txt','md'].includes(ext)) return 'fdoc';
  if (['png','jpg','jpeg','gif','webp','svg','heic'].includes(ext)) return 'fimg';
  if (['pptx','ppt','key'].includes(ext)) return 'fppt';
  if (['zip','rar','7z','tar','gz'].includes(ext)) return 'fzip';
  return 'fgen';
}

function classifyUploadByName(name) {
  const s = (name || '').toLowerCase();
  if (/inventory|on[_ -]?hand|stock|trims|fabric/.test(s)) return 'production';
  if (/wip|work[_ -]?in[_ -]?progress|capacity/.test(s)) return 'production';
  if (/forecast.*billing|billing|invoice|accounts?[_ -]?receivable|ar[_ -]?aging|receivable/.test(s)) return 'sales';
  if (/expense|past[_ -]?due|payable|cash[_ -]?flow|p&l|financial/.test(s)) return 'finance';
  if (/shipping|shipped|ship[_ -]?report|forecast.*ship/.test(s)) return 'shipping';
  return null;
}

async function refreshSectionUploads() {
  const el = document.getElementById('uploadedList');
  if (!el) return;
  const isAdmin = SESSION.role === 'admin';
  // Public repo — every signed-in user sees uploads regardless of whether
  // their own browser has a token. Token is only needed for posting/deleting.
  const localToken = localStorage.getItem('asa_github_token');
  const useGitHub = true;

  try {
    if (useGitHub) {
      let files = [];
      // Path 1: snapshot from data.json (same origin, never fails on rate limit/CORS).
      try {
        files = await loadUploadsViaSnapshot(isAdmin ? null : SESSION.section);
      } catch {}
      // Path 2 (fallback): live GitHub listing — only if snapshot was empty.
      if (!files.length) {
        if (isAdmin) {
          const all = await listAllUploads();
          files = all.map(u => ({
            path: u.path, name: u.name, sha: u.sha, size: u.size,
            original: u.original, uploader: u.uploader, uploadedAt: u.uploadedAt, section: u.section,
          }));
        } else {
          const dir = `uploads/${SESSION.section}`;
          const raw = await GH.listDir(dir);
          files = (Array.isArray(raw) ? raw : []).filter(f => f.type === 'file').map(f => {
            const meta = parseUploadName(f.name);
            return { path: f.path, name: f.name, sha: f.sha, size: f.size, section: SESSION.section, ...meta };
          });
        }
      }
      // Drop pending entries that GitHub has now confirmed, then merge what's still pending.
      const livePaths = new Set(files.map(f => f.path));
      dropPendingUploadsByPaths(livePaths);
      let pending = getPendingUploads();
      if (!isAdmin) pending = pending.filter(p => p.section === SESSION.section);
      pending = pending.filter(p => !livePaths.has(p.path));
      if (pending.length) {
        files = [...pending, ...files];
      }
      if (!files.length) { el.innerHTML = '<p style="color:var(--ink-dim);font-size:13px">No files uploaded yet.</p>'; return; }
      files.sort((a,b) => (b.uploadedAt||'').localeCompare(a.uploadedAt||''));
      el.innerHTML = files.map(f => `
        <div class="uploaded-row">
          <div class="file-icon ${fileExtClass(f.original||f.name||'')}">${((f.original||f.name||'').split('.').pop() || 'FILE').toUpperCase().slice(0,4)}</div>
          <div class="file-name">${escapeHtml(f.original||f.name||'(file)')}<div class="file-meta">${fmtDate(f.uploadedAt)} · ${fmtBytes(f.size)} · ${escapeHtml(f.section)} · ${escapeHtml(f.uploader||'')}</div></div>
          ${localToken ? `<button class="file-remove" data-path="${escapeHtml(f.path)}" data-sha="${f.sha}" title="Delete">✕</button>` : ''}
        </div>
      `).join('');
      el.querySelectorAll('.file-remove').forEach(b => b.addEventListener('click', async () => {
        if (!confirm('Delete this file from the repo?')) return;
        try { await GH.deleteFile(b.dataset.path, b.dataset.sha); } catch (e) { alert('Delete failed: ' + e.message); return; }
        refreshSectionUploads();
      }));
      return;
    }

    if (API_BASE) {
      // Azure: /api/uploads returns scoped list (admin sees all, sub-account sees their section only)
      const data = await apiGet('/api/uploads');
      const list = (data && data.uploads) || [];
      if (!list.length) { el.innerHTML = '<p style="color:var(--ink-dim);font-size:13px">No files uploaded yet.</p>'; return; }
      el.innerHTML = list.map(u => `
        <div class="uploaded-row">
          <div class="file-icon">${(u.filename.split('.').pop() || 'FILE').toUpperCase().slice(0,4)}</div>
          <div class="file-name">${escapeHtml(u.filename)}<div class="file-meta">${fmtDate(u.uploaded_at)} · ${fmtBytes(u.size_bytes)} · ${escapeHtml(u.section)} · ${escapeHtml(u.uploader)} · ${u.status}</div></div>
          <button class="file-remove" data-id="${u.id}" title="Delete">✕</button>
        </div>
      `).join('');
      el.querySelectorAll('.file-remove').forEach(b => b.addEventListener('click', async () => {
        if (!confirm('Permanently delete this upload (blob + GitHub + database row)?')) return;
        try { await apiDelete('/api/uploads?id=' + encodeURIComponent(b.dataset.id)); } catch (e) { alert('Delete failed: ' + e.message); return; }
        refreshSectionUploads();
      }));
      return;
    }

    el.innerHTML = '<p style="color:var(--ink-dim);font-size:13px">Open Settings and paste a GitHub token to see uploads.</p>';
  } catch (e) {
    let hint = '';
    if (/401/.test(e.message)) hint = ' Sign in again.';
    else if (/rate limit/i.test(e.message) || /403/.test(e.message)) hint = ' Unlock your token via the red banner at top to lift the 60/hr anonymous rate limit.';
    el.innerHTML = `<p style="color:var(--red);font-size:13px">Could not load uploads: ${escapeHtml(e.message)}.${hint}</p>`;
  }
}

/* ============================================================
 * ADMIN UPLOADS LIST (all sections)
 * ============================================================ */
async function renderUploadsList(root) {
  // Public repo: every signed-in user can READ uploads/comments without a token.
  // Token is only required for posting and deleting.
  const localToken = localStorage.getItem('asa_github_token');
  const useApi = false; // GitHub direct is authoritative
  const useGitHub = true;
  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">All Uploads</p>
        <h1>Files from every section</h1>
        <p>${useGitHub ? `Pulled live from <code>${SESSION.repo.owner}/${SESSION.repo.repo}/uploads/</code>.` : useApi ? 'Live from Azure SQL — admins see every section.' : 'Open Settings and paste a GitHub token to see uploads.'}</p>
      </div>
      <button class="btn btn-ghost btn-sm" onclick="navigate('uploads')">↻ Refresh</button>
    </div>
    <div class="panel"><p style="color:var(--ink-dim);font-size:13px">Loading…</p></div>
  `;
  let all = [];
  try {
    if (useGitHub) {
      // Prefer snapshot in admin/data.json — zero network risk.
      try { all = await loadUploadsViaSnapshot(null); } catch {}
      if (!all.length) all = await listAllUploads();
      const livePaths = new Set(all.map(u => u.path));
      dropPendingUploadsByPaths(livePaths);
      const pending = getPendingUploads().filter(p => !livePaths.has(p.path));
      if (pending.length) all = [...pending, ...all].sort((a,b) => (b.uploadedAt||'').localeCompare(a.uploadedAt||''));
    } else if (useApi) {
      const data = await apiGet('/api/uploads');
      all = ((data && data.uploads) || []).map(u => ({
        id: u.id, original: u.filename, section: u.section, size: u.size_bytes,
        uploader: u.uploader, status: u.status, uploadedAt: u.uploaded_at,
      }));
    }
  } catch (e) {
    let hint = '';
    if (/401/.test(e.message)) hint = ' Sign in again.';
    else if (/rate limit/i.test(e.message) || /403/.test(e.message)) hint = ' Unlock your token via the red banner at top — that switches you to 5000 requests/hour instead of 60.';
    root.innerHTML += `<div class="panel"><p style="color:var(--red);font-size:13px">${escapeHtml(e.message)}.${hint}</p></div>`;
    return;
  }
  // Count by derivedSection (classifies WIP/inventory/forecast files into their real category)
  // rather than the literal upload-folder section.
  const _sec = (u) => u.derivedSection || classifyUploadByName(u.original || u.name || '') || u.section;
  const bySection = Object.keys(SECTIONS).map(k => ({ key:k, label:SECTIONS[k].label, count: all.filter(u=>_sec(u)===k).length }));
  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">All Uploads</p>
        <h1>Files from every section</h1>
        <p>${useGitHub ? `Pulled live from <code>${SESSION.repo.owner}/${SESSION.repo.repo}/uploads/</code>.` : useApi ? 'Live from Azure SQL — admins see every section.' : 'Open Settings and paste a GitHub token to see uploads.'}</p>
      </div>
      <button class="btn btn-ghost btn-sm" onclick="navigate('uploads')">↻ Refresh</button>
    </div>
    <div class="kpi-grid">${bySection.map(s=>`<div class="kpi"><div class="kpi-label">${s.label}</div><div class="kpi-value">${s.count}</div><div class="kpi-delta flat">files</div></div>`).join('')}</div>
    <div class="panel">
      <div class="panel-head"><h2>Recent uploads</h2><span class="panel-meta">${all.length} total</span></div>
      <div class="uploaded-list">
        ${all.length ? all.map(f => `
          <div class="uploaded-row">
            <div class="file-icon ${fileExtClass(f.original||f.name||'')}">${((f.original||f.name||'').split('.').pop()||'FILE').toUpperCase().slice(0,4)}</div>
            <div class="file-name">${f.downloadUrl ? `<a href="${f.downloadUrl}" target="_blank">${escapeHtml(f.original||f.name||'(file)')}</a>` : escapeHtml(f.original||f.name||'(file)')}<div class="file-meta">${fmtDate(f.uploadedAt)} · ${fmtBytes(f.size)} · ${escapeHtml(f.section)} · ${escapeHtml(f.uploader||'')}${f.status ? ' · ' + escapeHtml(f.status) : ''}</div></div>
            ${useApi ? `<button class="file-remove" data-id="${f.id}" title="Delete">✕</button>` : useGitHub ? `<button class="file-remove" data-path="${escapeHtml(f.path)}" data-sha="${f.sha}" title="Delete">✕</button>` : ''}
          </div>`).join('') : '<p style="color:var(--ink-dim);font-size:13px">No uploads yet.</p>'}
      </div>
    </div>
  `;
  if (useApi) {
    root.querySelectorAll('.file-remove').forEach(b => b.addEventListener('click', async () => {
      if (!confirm('Permanently delete this upload (blob + GitHub + database row)?')) return;
      try { await apiDelete('/api/uploads?id=' + encodeURIComponent(b.dataset.id)); } catch (e) { alert('Delete failed: ' + e.message); return; }
      renderUploadsList(root);
    }));
  } else if (useGitHub) {
    root.querySelectorAll('.file-remove').forEach(b => b.addEventListener('click', async () => {
      if (!confirm('Delete this file from the repo?')) return;
      try { await GH.deleteFile(b.dataset.path, b.dataset.sha); } catch (e) { alert('Delete failed: ' + e.message); return; }
      renderUploadsList(root);
    }));
  }
}

/* ============================================================
 * AI SUMMARY (admin only, requires Anthropic key)
 * ============================================================ */
async function renderAI(root) {
  root.innerHTML = `
    <div class="page-head">
      <div>
        <p class="eyebrow">AI Summary</p>
        <h1>Ask Claude about the business</h1>
        <p>Pulls the most recent uploads from GitHub and sends them to Claude for analysis. Stays in your browser — no server in between.</p>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>Generate summary</h2><span class="panel-meta">model: claude-sonnet-4-6</span></div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
        <button class="btn btn-primary btn-sm" id="aiRun">Run summary on latest uploads</button>
        <button class="btn btn-ghost btn-sm" id="aiClear">Clear</button>
      </div>
      <div id="aiOutput" class="ai-summary" style="display:none"></div>
    </div>
  `;
  document.getElementById('aiRun').addEventListener('click', runAISummary);
  document.getElementById('aiClear').addEventListener('click', () => { document.getElementById('aiOutput').style.display='none'; });
}

async function runAISummary() {
  const out = document.getElementById('aiOutput');
  out.style.display = 'block';
  out.innerHTML = `<div class="ai-summary-label">Working…</div><p>Pulling latest uploads from GitHub…</p>`;
  try {
    const all = await listAllUploads();
    const recent = all.slice(0, 10);
    if (!recent.length) { out.innerHTML = `<p>No uploads yet — go to a section and upload some files first.</p>`; return; }

    out.innerHTML = `<div class="ai-summary-label">Working…</div><p>Reading ${recent.length} files…</p>`;
    const fileBlobs = [];
    for (const f of recent) {
      try {
        const r = await fetch(f.downloadUrl, { headers: { 'Authorization': `Bearer ${SESSION.secrets.githubToken}` } });
        const text = await r.text();
        // truncate big files to keep token cost bounded
        fileBlobs.push({ name: f.original, section: f.section, content: text.slice(0, 20000) });
      } catch {}
    }

    out.innerHTML = `<div class="ai-summary-label">Working…</div><p>Sending to Claude…</p>`;
    const sysPrompt = `You are an analyst assistant for Summit Team Apparel, a custom team apparel manufacturer. The user (admin) has uploaded operational data (shipping logs, invoices, inventory, expenses). Produce a concise executive summary covering: (1) shipping volume and forecast variance; (2) invoicing & receivables — flag any customer paying late; (3) production/WIP — highlight at-risk programs vs promised; (4) finance — past-due expenses to act on now. Use bullet points. Be specific with numbers. Bold the top 3 things to act on today.`;

    const userMsg = `Here are recent uploads from each section. Analyze them and give me today's executive summary.\n\n` +
      fileBlobs.map(b => `--- ${b.section} / ${b.name} ---\n${b.content}\n`).join('\n');

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': SESSION.secrets.anthropicKey,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1500,
        system: sysPrompt,
        messages: [{ role: 'user', content: userMsg }],
      }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error?.message || 'Claude API error');
    const text = (j.content || []).map(c => c.text || '').join('\n');

    out.innerHTML = `<div class="ai-summary-label">Claude · just now</div>${formatMarkdown(text)}`;
  } catch (e) {
    out.innerHTML = `<div class="ai-summary-label" style="color:var(--red)">Error</div><p>${escapeHtml(e.message)}</p>`;
  }
}

function formatMarkdown(s) {
  // very small markdown subset: bold, line breaks, bullets
  return s
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>[\s\S]*?<\/li>)+/g, (m) => `<ul style="margin:8px 0 8px 18px;padding:0">${m}</ul>`)
    .split('\n').map(l => l.trim()).filter(Boolean).map(l => l.startsWith('<') ? l : `<p>${l}</p>`).join('');
}

/* ============================================================
 * CHART OPTIONS
 * ============================================================ */
function chartOpts(showLegend = false, money = false) {
  return {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: showLegend, labels: { font: { size: 12 }, color: '#324158' } } },
    scales: {
      x: { grid: { display: false }, ticks: { font: { size: 11 }, color: '#5a6b85' } },
      y: { grid: { color: 'rgba(0,0,0,.05)' }, ticks: { font: { size: 11 }, color: '#5a6b85', callback: money ? (v)=>'$'+(v/1000).toFixed(0)+'k' : undefined } },
    },
  };
}

/* ============================================================
 * AUTO-RESUME — never blocks the login form on failure
 * ============================================================ */
(function init() {
  const stored = sessionStorage.getItem(SESSION_KEY);
  if (!stored) return;
  let restored = null;
  try {
    restored = JSON.parse(stored);
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
    return;
  }
  if (!restored || !restored.username || !FALLBACK_USERS[restored.username]) {
    sessionStorage.removeItem(SESSION_KEY);
    return;
  }
  if (!restored.secrets) restored.secrets = { githubToken: null, anthropicKey: null };
  if (!restored.repo) restored.repo = REPO;
  // Sync vault-decrypted token into localStorage so legacy code paths see it.
  if (restored.secrets.githubToken) {
    try { localStorage.setItem('asa_github_token', restored.secrets.githubToken); } catch {}
  }
  // Restore the master password (sessionStorage, tab-scoped) so the encrypted
  // data.enc.json decrypts on reload — otherwise the numbers vanish until the
  // user re-logs in (there is no plaintext data.json served anymore).
  try {
    const mpw = sessionStorage.getItem('asa_mpw');
    if (mpw) MASTER_PASSWORD = mpw;
  } catch {}
  try {
    SESSION = restored;
    bootApp(SESSION);
  } catch (err) {
    console.error('Auto-resume failed, falling back to login:', err);
    sessionStorage.removeItem(SESSION_KEY);
    SESSION = null;
    const lv = document.getElementById('loginView');
    const av = document.getElementById('appView');
    if (lv) lv.hidden = false;
    if (av) av.hidden = true;
  }
})();

/* ============================================================
 * i18n — English ⇆ Dominican-Spanish. Translations are hand-written (below) and
 * applied ONCE per render (called from navigate's post-render tick) — no
 * MutationObserver, so it never thrashes. English is the source of truth, so
 * toggling back to EN re-renders the originals untouched.
 * ============================================================ */
var LANG = (function(){ try { return localStorage.getItem('asa_lang') || 'en'; } catch { return 'en'; } })();
function T(en, es){ return (typeof LANG !== 'undefined' && LANG === 'es') ? es : en; }
const I18N_DICT = {
  // nav + chrome
  'Overview':'Resumen','Sections':'Secciones','Files':'Archivos','Tracker':'Seguimiento','Admin':'Admin',
  'Shipping & Logistics':'Envíos y Logística','Sales & Invoices':'Ventas y Facturas','Granite':'Granite',
  'Production':'Producción','Inventory':'Inventario','Capacity & WIP':'Capacidad y WIP','Finance & Receivables':'Finanzas y Cobros',
  'Inventory Accumulation':'Acumulación de Inventario','Collections':'Cobros','Expenses':'Gastos','Price List':'Lista de Precios',
  'On-Time Delivery':'Entrega a Tiempo','Forecast vs Actual':'Pronóstico vs Real','AI Coaching':'Coaching de IA','AI Summary':'Resumen de IA',
  'Employees':'Empleados','Upload Data':'Subir Datos','All Uploads':'Todas las Cargas','AI Comments':'Comentarios de IA',
  'Settings':'Configuración','Sign out':'Cerrar sesión','+ Upload Data':'+ Subir Datos','Upload data':'Subir datos','Upload key':'Clave de carga',
  'GitHub token':'Token de GitHub','Admin · Settings':'Admin · Configuración','Files from every section':'Archivos de cada sección',
  // page heads / eyebrows / section heads
  'Today at a glance':'La empresa de un vistazo','Admin Overview':'Resumen Administrativo','Money in':'Dinero que entra',
  'Pipeline':'Pipeline','Inventory building up':'Inventario acumulándose','Who owes us':'Quién nos debe','Who owes us money':'Quién nos debe dinero',
  'Raw materials on hand':'Materia prima en inventario','Production & warehouse':'Producción y almacén','NW analytics':'Analítica NW',
  'Key Account':'Cuenta Clave','Key Account · Prepaid':'Cuenta Clave · Prepagado','Markets':'Mercados','Markets · for fun':'Mercados · por diversión',
  'Finance':'Finanzas','Finance · Cash in':'Finanzas · Entrada de efectivo','Finance · Spend':'Finanzas · Gasto','Sales':'Ventas',
  'Sales · Pricing':'Ventas · Precios','Employees · HR':'Empleados · RRHH','Support · Requests':'Soporte · Solicitudes','AI Tracker · Comments':'Rastreador IA · Comentarios',
  'Collections — getting paid':'Cobros — recibir pagos','Collections — when we get paid':'Cobros — cuándo nos pagan',
  'Invoicing & receivables':'Facturación y cobros','Invoices':'Facturas','All invoices':'Todas las facturas','Invoices per day':'Facturas por día',
  'Receivables per day':'Cobros por día','Who owes us money — biggest first':'Quién nos debe — de mayor a menor','What each customer owes us':'Lo que nos debe cada cliente',
  'Who to chase now':'A quién perseguir ahora','Overdue — chase now':'Vencido — perseguir ahora','Coming due (not yet overdue)':'Por vencer (aún no vencido)',
  'Expected cash by due date':'Efectivo esperado por vencimiento','Expected receivables — by invoice due date':'Cobros esperados — por fecha de factura',
  'Total open A/R':'Total A/R abierto','Open A/R':'A/R abierto','Open A/P':'A/P abierto','A/R open':'A/R abierto','A/P open':'A/P abierto',
  'A/R past due':'A/R vencido','Past due':'Vencido','Past due (31+)':'Vencido (31+)','Past-due aging':'Antigüedad de vencidos','Past-due expenses':'Gastos vencidos',
  'Open expenses (upcoming)':'Gastos abiertos (próximos)','Open A/P · biggest first':'A/P abierto · de mayor a menor','Spend by category':'Gasto por categoría',
  'A/P by category':'A/P por categoría','What we owe — by category':'Lo que debemos — por categoría','Top vendors':'Principales proveedores',
  'Vendor':'Proveedor','Suppliers':'Proveedores','Bills':'Facturas','Customers w/ open':'Clientes con saldo',
  'Price List — by customer & item':'Lista de Precios — por cliente y artículo','Price List — by customer &amp; item':'Lista de Precios — por cliente y artículo',
  'Items priced':'Artículos con precio','Highest price':'Precio más alto','Lowest price':'Precio más bajo','Item':'Artículo','Price':'Precio',
  'Basis':'Base','Terms':'Términos','Planned / fcst price':'Precio plan / pronóstico','SHIPPINGREPORT actuals':'Reales de SHIPPINGREPORT',
  'Total expected':'Total esperado','Due in 7 days':'Vence en 7 días','Due in 30 days':'Vence en 30 días','Due in':'Vence en','Expected cash':'Efectivo esperado',
  'Current':'Al día','Coming due':'Por vencer',
  // KPI / labels
  'Owed to us':'Lo que nos deben','Overdue — call now':'Vencido — llamar ahora','This week vs plan':'Esta semana vs plan',
  'Revenue this year':'Ingresos este año','Sitting in warehouse':'En el almacén','Units shipped YTD':'Unidades enviadas YTD',
  'Revenue · shipped YTD':'Ingresos · enviado YTD','Open orders ($)':'Órdenes abiertas ($)','Inventory on hand':'Inventario disponible',
  'Open orders':'Órdenes abiertas','Shipped YTD':'Enviado YTD','On hand':'En inventario','Weekly target':'Meta semanal',
  'In production (pipeline)':'En producción (pipeline)','In production':'En producción','Fill rate':'Tasa de cumplimiento','Past-due units':'Unidades vencidas',
  'Forecast attainment':'Cumplimiento de pronóstico','Net accumulation':'Acumulación neta','Produced YTD':'Producido YTD','Produced':'Producido',
  'Piling up':'Acumulándose','Materials on hand':'Materia prima en inventario','Raw materials left ($)':'Materia prima restante ($)',
  'Money in (YTD)':'Dinero que entra (YTD)','YTD vs plan':'YTD vs plan','Order book':'Libro de órdenes','We owe (A/P)':'Lo que debemos (A/P)',
  'Full-year outlook':'Perspectiva del año','% used up':'% usado','% used':'% usado','Behind committed dates':'Atraso vs fechas',
  'On order':'En pedido','On-hand cost':'Costo en inventario','Pending available':'Disponible pendiente','Pending avail.':'Disp. pendiente',
  'Units on hand':'Unidades en inventario','Units planned':'Unidades planificadas','Units shipped':'Unidades enviadas','Units shipped (YTD)':'Unidades enviadas (YTD)',
  'Delivered YTD':'Entregado YTD','Open to ship':'Pendiente por enviar','Shipped this wk':'Enviado esta sem','Shipped last wk':'Enviado sem pasada',
  'Planned this wk':'Planificado esta sem','% to plan':'% al plan','vs plan':'vs plan','vs Target':'vs Meta','Sewn this week':'Cosido esta semana',
  'Produced this year':'Producido este año','Produced, not shipped':'Producido, no enviado','In the warehouse':'En el almacén','Units waiting':'Unidades en espera',
  'Who paid':'Quién pagó','Who paid (STA / cust)':'Quién pagó (STA / cliente)','STA paid for':'STA pagó','Customer paid for':'El cliente pagó',
  'What it is':'Qué es','What it means':'Qué significa','YTD shipped':'Enviado YTD','Forecast — rest of year':'Pronóstico — resto del año',
  'Late programs':'Programas atrasados','WIP value at risk':'Valor WIP en riesgo','Weekly capacity':'Capacidad semanal','Run-rate /mo':'Ritmo /mes',
  'Fwd forecast':'Pronóstico futuro','We project done':'Proyectamos terminar',
  // common words / table headers
  'Customer':'Cliente','Product':'Producto','Units':'Unidades','Total':'Total','Week':'Semana','Month':'Mes','Months':'Meses','Status':'Estado',
  'Revenue':'Ingresos','Shipped':'Enviado','Planned':'Planificado','Open':'Abierto','Stage':'Etapa','Value':'Valor','Program':'Programa','Programs':'Programas',
  'Need by':'Fecha límite','Open units':'Unidades abiertas','Last full week':'Última semana completa','vs our average':'vs nuestro promedio',
  'Best week this year':'Mejor semana del año','Shipped this year':'Enviado este año','This week':'Esta semana','This week so far':'Esta semana hasta ahora',
  'Last week':'Semana pasada','TOTAL':'TOTAL','Excel':'Excel','PDF':'PDF','Amount':'Monto','Date':'Fecha','Due':'Vence','Due date':'Fecha de vencimiento',
  'Days late':'Días de atraso','Description':'Descripción','Type':'Tipo','Category':'Categoría','Categories':'Categorías','Code':'Código','Rank':'Rango',
  'Score':'Puntaje','Invoice #':'Factura #','Earliest req':'Req más temprano','Order lines':'Líneas de pedido','Lines':'Líneas','Line':'Línea','Module':'Módulo',
  'Goal':'Meta','Week goal':'Meta semanal','Week of':'Semana del','Week ending':'Semana que termina','Week total':'Total semana','Weekly plan':'Plan semanal',
  'Remaining':'Restante','Material':'Material','Material type':'Tipo de material','Forecast':'Pronóstico','Forecast units':'Unidades pronosticadas',
  'Actual':'Real','Actual to date':'Real a la fecha','Plan':'Plan','Attainment':'Cumplimiento','Att %':'% Cumpl','Attm':'Cumpl','% complete':'% completo',
  'Coordinator':'Coordinador','Supervisor':'Supervisor','Supervisors':'Supervisores','Employee':'Empleado','Position':'Puesto','Oldest':'Más antiguo',
  'Owner':'Dueño','By product':'Por producto','By customer':'Por cliente','by volume':'por volumen','Cost':'Costo','Bucket':'Grupo','Annual':'Anual',
  'Scheduled':'Programado','Current status':'Estado actual','At risk / watch':'En riesgo / vigilar','Customer detail':'Detalle del cliente',
  'Customers':'Clientes','Product notes':'Notas de producto','Recent uploads':'Cargas recientes','2026 revenue':'Ingresos 2026','2026 units':'Unidades 2026',
  'Momentum':'Impulso','Full-year forecast':'Pronóstico de todo el año','Forecast by customer (full year)':'Pronóstico por cliente (todo el año)',
  "Owner's Brief":'Resumen del Dueño','NW Brief':'Resumen NW','Granite Brief':'Resumen Granite','Diagnose':'Diagnosticar','Generate summary':'Generar resumen',
  'Post a comment':'Publicar comentario','New request':'Nueva solicitud','Markets · for fun':'Mercados · por diversión',
  'Produced vs shipped':'Producido vs enviado','In production now — by sewing stage':'En producción ahora — por etapa de costura',
  // ----- expanded coverage (2026-06-17) -----
  "% Attainment by month — line chart": "% de cumplimiento por mes — gráfico de líneas",
  "% Units": "% Unidades",
  "% actual": "% real",
  "% attainment (units)": "% cumplimiento (unidades)",
  "% done": "% hecho",
  "% of A/P": "% del A/P",
  "% of book": "% del libro",
  "% of materials": "% de materiales",
  "% sched": "% prog",
  "% this wk": "% esta sem",
  "+gap = in the warehouse · −gap = filled from January stock": "+brecha = en el almacén · −brecha = surtido del inventario de enero",
  "1. Weekly Production Performance": "1. Desempeño de producción semanal",
  "10 areas of the business · color-coded severity": "10 áreas del negocio · severidad por color",
  "13-week revenue PROJECTION": "PROYECCIÓN de ingresos a 13 semanas",
  "13-week weekly — forecast vs actual": "13 semanas — pronóstico vs real",
  "13-wk plan attainment": "cumplimiento plan 13 sem",
  "2. By Customer — Plan vs Actual (YTD)": "2. Por cliente — Plan vs Real (YTD)",
  "2026 revenue by month — actual + forecast": "Ingresos 2026 por mes — real + pronóstico",
  "3. Capacity Utilization": "3. Utilización de capacidad",
  "4. Delay Tracking — programs past their req date": "4. Seguimiento de atrasos — programas pasados de su fecha",
  "Actual (units)": "Real (unidades)",
  "Ask Claude about the business": "Pregúntale a Claude sobre el negocio",
  "Available (made − open)": "Disponible (hecho − abierto)",
  "Biggest category": "Categoría más grande",
  "Biggest materials by value": "Materiales más grandes por valor",
  "Cancel": "Cancelar",
  "Capacity": "Capacidad",
  "Capacity plan attainment": "Cumplimiento del plan de capacidad",
  "Capacity used (current wk)": "Capacidad usada (sem actual)",
  "Clear": "Limpiar",
  "Clear token": "Borrar token",
  "Close": "Cerrar",
  "Collapse all": "Contraer todo",
  "Customer / Program": "Cliente / Programa",
  "Customer reliability — forecast vs actual, by month": "Confiabilidad del cliente — pronóstico vs real, por mes",
  "DR Labor Code · required to terminate without severance": "Código de Trabajo RD · requerido para despedir sin cesantía",
  "DR Labor Law — Article 88 just-cause grounds": "Ley Laboral RD — causas justas del Artículo 88",
  "Daily shipping this week — by customer × day": "Envíos diarios esta semana — por cliente × día",
  "Daily tracking — all open programs (grouped by customer)": "Seguimiento diario — todos los programas abiertos (por cliente)",
  "Days late / remain": "Días atraso / restan",
  "Delay / Remain": "Atraso / Restan",
  "Delivery schedule — units due by program × week": "Calendario de entrega — unidades por programa × semana",
  "Employee scoreboard": "Tablero de empleados",
  "Employees on file": "Empleados registrados",
  "Executive read": "Lectura ejecutiva",
  "Gap (in warehouse)": "Brecha (en almacén)",
  "Ground (cause)": "Causa",
  "Has incidents": "Tiene incidentes",
  "Highlights (90d)": "Destacados (90d)",
  "How this brief is generated": "Cómo se genera este resumen",
  "How this is computed — the pipeline": "Cómo se calcula — el flujo",
  "How this section works": "Cómo funciona esta sección",
  "How we're doing — by month": "Cómo vamos — por mes",
  "Incidents": "Incidentes",
  "Invoices this week — by customer × day": "Facturas esta semana — por cliente × día",
  "Latest invoiced day": "Último día facturado",
  "Latest receivables day": "Último día de cobros",
  "Coreline — separate track (paid up front)": "Coreline — vía aparte (prepagado)",
  "Monthly forecast vs actual": "Pronóstico vs real mensual",
  "Monthly forecast vs actual — chart": "Pronóstico vs real mensual — gráfico",
  "Needs attention": "Requiere atención",
  "On hand by category": "En inventario por categoría",
  "On hand by customer": "En inventario por cliente",
  "On the production lines": "En las líneas de producción",
  "On-hand inventory": "Inventario disponible",
  "On-time delivery & production performance": "Entrega a tiempo y desempeño de producción",
  "Open WIP programs": "Programas WIP abiertos",
  "Open WIP programs — full list (excl. Coreline)": "Programas WIP abiertos — lista completa (excl. Coreline)",
  "Open balance (cum.)": "Saldo abierto (acum.)",
  "Open balance (cumulative)": "Saldo abierto (acumulado)",
  "Open incidents (90d)": "Incidentes abiertos (90d)",
  "Open orders (pipeline)": "Órdenes abiertas (pipeline)",
  "Open orders by customer": "Órdenes abiertas por cliente",
  "Open positions": "Vacantes",
  "Open programs and weekly capacity load": "Programas abiertos y carga semanal de capacidad",
  "Open w/ fabric": "Abierto con tela",
  "Operational observations — detail": "Observaciones operativas — detalle",
  "Ops": "Ops",
  "Ordered (due)": "Pedido (vence)",
  "Orders → Production → Shipped": "Órdenes → Producción → Enviado",
  "Original ship date": "Fecha de envío original",
  "Out the door (shipped)": "Despachado (enviado)",
  "Overdue": "Vencido",
  "Pipeline & forward outlook": "Pipeline y perspectiva futura",
  "Plan (units)": "Plan (unidades)",
  "Post": "Publicar",
  "Post reply": "Publicar respuesta",
  "Priority decisions this week": "Decisiones prioritarias esta semana",
  "Produced but not shipped": "Producido pero no enviado",
  "Produced by line": "Producido por línea",
  "Produced vs open — by product type": "Producido vs abierto — por tipo de producto",
  "Produced vs shipped — by customer": "Producido vs enviado — por cliente",
  "Produced vs shipped — by week": "Producido vs enviado — por semana",
  "Produced vs shipped — top products": "Producido vs enviado — productos top",
  "Product type": "Tipo de producto",
  "Production by customer": "Producción por cliente",
  "Production load by week — per customer": "Carga de producción por semana — por cliente",
  "Recent incidents — 90 day window": "Incidentes recientes — ventana de 90 días",
  "Remaining to ship — by customer": "Pendiente por enviar — por cliente",
  "Run diagnostics": "Ejecutar diagnóstico",
  "Run summary on latest uploads": "Generar resumen de las últimas cargas",
  "SEW · module × product · units assembled": "SEW · módulo × producto · unidades ensambladas",
  "Sales pipeline — 2026 outlook by momentum": "Pipeline de ventas — perspectiva 2026 por impulso",
  "Save token": "Guardar token",
  "Severity": "Severidad",
  "Sewn (produced)": "Cosido (producido)",
  "Sewn for them (est.)": "Cosido para ellos (est.)",
  "Shipped (actual)": "Enviado (real)",
  "Shipped (units)": "Enviado (unidades)",
  "Shipped to them": "Enviado a ellos",
  "Shipped units — by week ending": "Unidades enviadas — por semana que termina",
  "Shipped, but not sewn on the tracked lines": "Enviado, pero no cosido en las líneas registradas",
  "Single-incident fireable?": "¿Despido por incidente único?",
  "Started → % used": "Inicial → % usado",
  "Strategic lenses": "Lentes estratégicos",
  "Strategic operating brief": "Resumen operativo estratégico",
  "Submit report": "Enviar reporte",
  "Submit request": "Enviar solicitud",
  "Submit termination request": "Enviar solicitud de despido",
  "Supplier scorecard": "Tarjeta de desempeño del proveedor",
  "This month": "Este mes",
  "This week by customer — production, shipping, receivables": "Esta semana por cliente — producción, envíos, cobros",
  "This week vs last week": "Esta semana vs semana pasada",
  "Thread": "Hilo",
  "Threshold if not": "Umbral si no",
  "Today's plan": "Plan de hoy",
  "Top customers by revenue (YTD 2026)": "Mejores clientes por ingresos (YTD 2026)",
  "Top customers by volume (units YTD)": "Mejores clientes por volumen (unidades YTD)",
  "Top performers": "Mejores desempeños",
  "Unlock": "Desbloquear",
  "WIP by customer": "WIP por cliente",
  "WIP units (excl. Coreline)": "Unidades WIP (excl. Coreline)",
  "Warnings": "Advertencias",
  "Week · Planned · Produced · Shipped · Open Balance": "Semana · Planificado · Producido · Enviado · Saldo abierto",
  "Weekly shipped vs plan": "Enviado vs plan semanal",
  "What's in the warehouse — by customer and product": "Qué hay en el almacén — por cliente y producto",
  "Witnesses": "Testigos",
  "Workforce & supervisor command": "Mando de personal y supervisores",
  "YTD": "YTD",
  "YTD %": "YTD %",
  "YTD Forecast Attainment": "Cumplimiento de pronóstico YTD",
  "YTD act": "YTD real",
  "YTD fcst": "YTD pron",
  "allocated capacity (CAPACITY report) vs produced (Bihorario)": "capacidad asignada (reporte CAPACITY) vs producido (Bihorario)",
  "cash sitting in the warehouse · full breakdown →": "efectivo parado en el almacén · desglose completo →",
  "click any customer for invoice detail · live from AR_Report": "haz clic en un cliente para ver el detalle · en vivo desde AR_Report",
  "do we already have units made? \"Available\" = produced − open": "¿ya tenemos unidades hechas? \"Disponible\" = producido − abierto",
  "drops in uploads/employees/": "se guarda en uploads/employees/",
  "encrypted & persisted to repo vault.json": "encriptado y guardado en el repo vault.json",
  "expected cash, soonest first": "efectivo esperado, lo más pronto primero",
  "fabric / trim / finished": "tela / avíos / terminado",
  "floor output (Bihorario) vs shipped — units": "producción de planta (Bihorario) vs enviado — unidades",
  "from real QB invoice due dates (not aging estimates)": "de fechas reales de factura QB (no estimados de antigüedad)",
  "inventory value — capital tied up": "valor de inventario — capital inmovilizado",
  "live line status · awaiting data upload": "estado de línea en vivo · esperando carga de datos",
  "model: claude-sonnet-4-6": "modelo: claude-sonnet-4-6",
  "open A/P by supplier": "A/P abierto por proveedor",
  "open A/P · biggest first": "A/P abierto · de mayor a menor",
  "overdue A/R — approach these customers, biggest first": "A/R vencido — contactar a estos clientes, de mayor a menor",
  "paste reply from email / WhatsApp / notes": "pega la respuesta de correo / WhatsApp / notas",
  "planned units + revenue for the year, with actuals to date": "unidades + ingresos planificados del año, con reales a la fecha",
  "private · saved straight to the AI, not shown on the portal": "privado · guardado directo a la IA, no se muestra en el portal",
  "three views into the business this week": "tres vistas del negocio esta semana",
  "two files, one subtraction": "dos archivos, una resta",
  "units sewn vs shipped each week · the gap is what's accumulating": "unidades cosidas vs enviadas cada semana · la brecha es lo que se acumula",
  "units · cost · pending available": "unidades · costo · disponible pendiente",
  "units, full year": "unidades, año completo",
  "units, recent weeks": "unidades, semanas recientes",
  "use this to see why uploads/comments aren't working": "úsalo para ver por qué no funcionan las cargas/comentarios",
  "what we owe by type — the budget lines to target": "lo que debemos por tipo — las líneas de presupuesto a atacar",
  "when the open A/R should land": "cuándo debería entrar el A/R abierto",
  "↳ of which NW": "↳ de lo cual NW",
  "⚠ Data reconciliation": "⚠ Conciliación de datos",
  "⚠ Upload key missing on this device": "⚠ Falta la clave de carga en este dispositivo",
  "📋 Directory upload pending": "📋 Carga de directorio pendiente",
  "📝 Operation notes — tell the AI what's going on": "📝 Notas de operación — dile a la IA qué está pasando",
  "📥 Submit daily report (supervisors)": "📥 Enviar reporte diario (supervisores)",
  "📧 Today's supervisor emails — draft from WIP": "📧 Correos de supervisores de hoy — borrador desde WIP",
  "🗺 Plant organization map": "🗺 Mapa de organización de planta",
  // ----- data prose (AI coaching) translated 2026-06-17 -----
  "YTD util 61.6% vs 70% target (-8.4pp). 21 late programs / 11,736 units / $66,196. A/R $218,290 open ($148,459 past-due). Top customer Granite = 64% of revenue. 88.2% inventory aged >180d.": "Utilización YTD 61.6% vs meta 70% (-8.4pp). 21 programas atrasados / 11,736 unidades / $66,196. A/R $218,290 abierto ($148,459 vencido). Cliente principal Granite = 64% de los ingresos. 88.2% del inventario con más de 180 días.",
  "Production is carrying 21 late programs worth $66,196 in committed shipments. Oldest is 124d past req date — at this scale every day late is a customer trust event, not a scheduling note. YTD plant utilization is 61.6% against a 70% target — 8.4pp short. To hit the target by year-end we'd need to deliver an extra 318,536 units across the remaining weeks. That's a step-change in throughput, not a stretch. A/R has $148,459 sitting past-due across the 1-30/31-60/61+ buckets out of $218,290 total open. The dpd60+ $2,484 is the collection focus this week — beyond 60 days the cost to collect rises sharply. Granite represents 64% of YTD revenue. The business is one customer relationship away from a step-change in either direction. Diversification needs to be on the strategic agenda — not next quarter. 88.2% of inventory ($1,148,557) is over 6 months old. That's cash sitting on the shelf. A sell-through campaign on aged customer-attached fabric is a real lever — not a bookkeeping exercise.": "Producción carga 21 programas atrasados por $66,196 en envíos comprometidos. El más viejo tiene 124 días de atraso — a esta escala cada día tarde es un asunto de confianza del cliente, no una nota de programación. La utilización de planta YTD es 61.6% frente a una meta de 70% — 8.4pp por debajo. Para alcanzar la meta a fin de año habría que entregar 318,536 unidades adicionales en las semanas restantes. Eso es un salto de producción, no un esfuerzo menor. El A/R tiene $148,459 vencidos entre los tramos 1-30/31-60/61+ de $218,290 abiertos en total. Los $2,484 a más de 60 días son el foco de cobro de esta semana — pasados los 60 días el costo de cobrar sube bruscamente. Granite representa 64% de los ingresos YTD. El negocio está a una sola relación de cliente de un cambio drástico en cualquier dirección. La diversificación debe estar en la agenda estratégica — no el próximo trimestre. 88.2% del inventario ($1,148,557) tiene más de 6 meses. Eso es efectivo parado en el estante. Una campaña de venta de la tela vieja asignada a clientes es una palanca real — no un ejercicio contable.",
  "Open A/R is $218,290 across 8 customers. Of that, $148,459 (68%) is past due. Current bucket $69,831 is healthy; the 60+ bucket $2,484 is the problem.": "El A/R abierto es $218,290 entre 8 clientes. De eso, $148,459 (68%) está vencido. El tramo al día $69,831 está sano; el tramo de 60+ $2,484 es el problema.",
  "A/P past-due is $1,004,840 across 458 bills — but a meaningful chunk is QuickBooks bank-transfer accounting artifacts (the +/-$74k, +/-$32k offsets your bookkeeper should reconcile). True operating A/P past-due after netting those out is materially smaller — work with bookkeeping to clean the GL so this dashboard shows the real number.": "El A/P vencido es $1,004,840 entre 458 facturas — pero una parte importante son artefactos contables de transferencias bancarias de QuickBooks (los ajustes de +/-$74k, +/-$32k que su contable debe reconciliar). El A/P operativo vencido real, después de netear esos, es mucho menor — trabaje con contabilidad para limpiar el libro mayor y que este panel muestre el número real.",
  "Net working-capital posture is $-786,549 — negative. Tightening receivables and rebooking aged A/P should be week-one priorities.": "La posición de capital de trabajo neto es $-786,549 — negativa. Apretar los cobros y reclasificar el A/P viejo deben ser prioridades de la primera semana.",
  "Most recent week (May 29) ran at 46.5% capacity, vs 4-wk trailing avg 47.5% — trend is steady (-1.0pp).": "La semana más reciente (29 de mayo) corrió a 46.5% de capacidad, vs promedio de 4 sem 47.5% — la tendencia es estable (-1.0pp).",
  "YTD plant utilization 61.6% vs 70% goal. The plant is built for 12,000 units/wk × 52 = 624,000 units annually; YTD throughput 118,264 units is 19.0% of theoretical capacity. The gap is not 'factory can't' — it's 'demand isn't loading the calendar evenly'.": "Utilización de planta YTD 61.6% vs meta 70%. La planta está hecha para 12,000 unidades/sem × 52 = 624,000 unidades al año; la producción YTD de 118,264 unidades es 19.0% de la capacidad teórica. La brecha no es 'la fábrica no puede' — es 'la demanda no llena el calendario de forma pareja'.",
  "21 programs past req date represent $66,196 in committed revenue tied up in WIP rather than billed and shipped. Pulling those forward frees the next week's schedule and clears trust debt with the customer simultaneously — double-effect investment.": "21 programas pasados de fecha representan $66,196 en ingresos comprometidos atrapados en WIP en vez de facturados y enviados. Adelantarlos libera el calendario de la próxima semana y salda la deuda de confianza con el cliente a la vez — inversión de doble efecto.",
  "Customer-level attainment laggards (YTD vs forecast): Dance 0%, Zenith 0%, Slugger 3%. Either we're not getting the orders we forecast, or the factory is starving these accounts. Each laggard is either a sales conversation or a production-planning conversation — name which one before the next FvA review.": "Rezagados de cumplimiento por cliente (YTD vs pronóstico): Dance 0%, Zenith 0%, Slugger 3%. O no estamos recibiendo las órdenes que pronosticamos, o la fábrica está descuidando estas cuentas. Cada rezagado es una conversación de ventas o una de planificación de producción — defina cuál antes de la próxima revisión de Pronóstico vs Real.",
  "Customer concentration: Granite is 64% of YTD revenue. In this category, anything above 40% for a single customer is operating risk; above 60% is existential. This isn't about loyalty — it's about the math when they renegotiate.": "Concentración de clientes: Granite es 64% de los ingresos YTD. En esta categoría, cualquier cosa por encima de 40% en un solo cliente es riesgo operativo; por encima de 60% es existencial. Esto no es sobre lealtad — es sobre las cuentas cuando renegocien.",
  "Inventory mix: $1,302,657 on hand, $1,148,557 (88.2%) older than 6 months. Customer-attached fabric that doesn't get used is a sunk cost in two ways — capital tied up, plus warehouse space crowding fresh-cycle material. The fix is operational (sell-through) and structural (smaller initial fabric buys until customer commits to volume).": "Mezcla de inventario: $1,302,657 en inventario, $1,148,557 (88.2%) con más de 6 meses. La tela asignada a clientes que no se usa es un costo hundido por partida doble — capital inmovilizado, más espacio de almacén quitándole lugar al material de ciclo fresco. La solución es operativa (venta) y estructural (compras iniciales de tela más pequeñas hasta que el cliente comprometa volumen).",
  "Fabric reorder triggers: 1 line(s) short of need. At the same time, $1,148,557 of inventory sits aged. The signal: purchasing isn't matched to consumption velocity by SKU. The fix isn't 'more inventory' — it's better SKU-level demand sensing.": "Disparadores de reorden de tela: 1 línea(s) por debajo de lo necesario. Al mismo tiempo, $1,148,557 de inventario está envejecido. La señal: las compras no están alineadas con la velocidad de consumo por SKU. La solución no es 'más inventario' — es mejor lectura de demanda a nivel de SKU.",
  "Triage the late book": "Priorizar el libro de atrasos",
  "21 programs / 11,736 units / $66,196 past req date. Top late: Bellforge PANT (124d), Bellforge SHORT (103d), Bellforge FULL BUTTON (12d).": "21 programas / 11,736 unidades / $66,196 pasados de fecha. Más atrasados: Bellforge PANT (124d), Bellforge SHORT (103d), Bellforge FULL BUTTON (12d).",
  "Close the 8.4pp utilization gap": "Cerrar la brecha de utilización de 8.4pp",
  "YTD at 61.6% vs 70% target. Cap is 12,000 units/wk; we're averaging well below. Either pipeline is thin or factory is constrained on a specific process step.": "YTD en 61.6% vs meta 70%. La capacidad es 12,000 unidades/sem; estamos muy por debajo del promedio. O el pipeline es flojo o la fábrica está limitada en un paso específico del proceso.",
  "Collect the $2,484 in 60+ days A/R": "Cobrar los $2,484 de A/R a más de 60 días",
  "Total A/R $218,290. $2,484 is 60+ days past due. Cost to collect rises ~5x once invoices cross 90 days.": "A/R total $218,290. $2,484 tiene más de 60 días de vencido. El costo de cobrar sube ~5x una vez que las facturas pasan los 90 días.",
  "Customer concentration is the #1 strategic risk": "La concentración de clientes es el riesgo estratégico #1",
  "Granite = 64% of revenue. If they cut orders 20%, that's a 385k revenue hit instantly. No #2 customer can absorb that.": "Granite = 64% de los ingresos. Si recortan órdenes 20%, es un golpe de 385k en ingresos al instante. Ningún cliente #2 puede absorber eso.",
  "Aged inventory sell-through": "Venta de inventario envejecido",
  "$1,148,557 aged >180d (88.2% of total). At any reasonable cost of capital this is a 6-figure annual drag.": "$1,148,557 con más de 180 días (88.2% del total). A cualquier costo de capital razonable esto es un lastre anual de 6 cifras.",
  "Daily floor management": "Gestión diaria de planta",
  "21 programs past req date — 11,736 units / $66,196 tied up. Oldest 124d late.": "21 programas pasados de fecha — 11,736 unidades / $66,196 atrapados. El más viejo 124d de atraso.",
  "Pull the top-3 oldest to the front of the line tomorrow. The rest get a customer call to re-commit a date — silence is worse than honesty here.": "Adelanta los 3 más viejos al frente de la línea mañana. El resto recibe una llamada al cliente para recomprometer una fecha — el silencio es peor que la honestidad aquí.",
  "Sewing line efficiency": "Eficiencia de la línea de costura",
  "Last week 46.5% util; 4-wk avg 43.7%; target 70%. Need ~2823 more units/wk.": "Semana pasada 46.5% util; promedio 4 sem 43.7%; meta 70%. Faltan ~2823 unidades/sem más.",
  "Walk the line on the slowest day of the week. Whichever station has units waiting upstream is the constraint — that's the next $/hour you can capture.": "Recorre la línea el día más lento de la semana. La estación que tenga unidades esperando arriba es la restricción — ahí está el próximo $/hora que puedes capturar.",
  "Operator productivity": "Productividad del operador",
  "No operator-level efficiency data yet (Bihorario Eficiencia file not parsed). Without it we're managing throughput by week, not by operator.": "Aún no hay datos de eficiencia por operador (archivo Bihorario Eficiencia no procesado). Sin eso gestionamos la producción por semana, no por operador.",
  "Drop Bihorario Eficiencia STA Costura into uploads/production/ and we get operator × hours × output. That's where the real efficiency gains hide.": "Sube Bihorario Eficiencia STA Costura a uploads/production/ y obtenemos operador × horas × producción. Ahí se esconden las verdaderas ganancias de eficiencia.",
  "Bottleneck identification": "Identificación de cuellos de botella",
  "Worst shortfall in last 13 weeks: May 15 short 2,725 units. Pattern across 7 weeks suggests constraint isn't capacity — it's mix or sequencing.": "Peor déficit en las últimas 13 semanas: 15 de mayo, faltaron 2,725 unidades. El patrón en 7 semanas sugiere que la restricción no es capacidad — es mezcla o secuencia.",
  "When a week underdelivers by >2k units, document which products were on the floor — patterns reveal whether it's a fabric, a sew operation, or a print bottleneck.": "Cuando una semana entrega menos de >2k unidades, documenta qué productos estaban en planta — los patrones revelan si es un cuello de botella de tela, de costura o de impresión.",
  "Module performance tracking": "Seguimiento de desempeño por módulo",
  "WIP file's Modulo Asignado column is empty. Can't measure per-module efficiency without it.": "La columna Modulo Asignado del archivo WIP está vacía. No se puede medir la eficiencia por módulo sin ella.",
  "Have planning populate Modulo Asignado at order release. Then we can report M1 vs M2 vs M3 utilization weekly.": "Que planificación llene Modulo Asignado al liberar la orden. Entonces podemos reportar la utilización de M1 vs M2 vs M3 semanalmente.",
  "Daily production execution": "Ejecución de producción diaria",
  "Month-to-date: 20,528 actual vs 49,082 forecast = 42%. Day 17/30, expected at-pace 27,813. Behind by 7285 units.": "En lo que va del mes: 20,528 real vs 49,082 pronóstico = 42%. Día 17/30, al ritmo esperado 27,813. Atrasados por 7285 unidades.",
  "Standup at 7am, every module reports prior-day output + today's commit. Catch shortfall same-day, not next Friday.": "Reunión a las 7am, cada módulo reporta la producción del día anterior + el compromiso de hoy. Detecta el déficit el mismo día, no el viernes siguiente.",
  "Line balancing": "Balanceo de línea",
  "Customer attainment laggards: Dance 0%, Zenith 0%, Slugger 3%. Either demand is below forecast or supply is starving them.": "Rezagados de cumplimiento por cliente: Dance 0%, Zenith 0%, Slugger 3%. O la demanda está por debajo del pronóstico o el suministro los está descuidando.",
  "For each laggard, write down: was the order placed? was fabric in stock? was the line scheduled? One question identifies the function that needs to act.": "Para cada rezagado, anota: ¿se colocó la orden? ¿había tela en inventario? ¿se programó la línea? Una pregunta identifica la función que debe actuar.",
  "Operational efficiency": "Eficiencia operativa",
  "Inventory $1,302,657 on hand; $1,148,557 (88.2%) over 6 months. 1 fabric line(s) short of need.": "Inventario $1,302,657 en inventario; $1,148,557 (88.2%) con más de 6 meses. 1 línea(s) de tela por debajo de lo necesario.",
  "Two campaigns: sell-through to customers for their aged fabric (offer a discount), and replenish reorder triggers before they stop the line.": "Dos campañas: venta a los clientes de su tela vieja (ofrece un descuento), y reponer los disparadores de reorden antes de que paren la línea.",
  "Real-time reporting accuracy": "Precisión del reporte en tiempo real",
  "All A/R, A/P, WIP, FABRIC, SHIPPINGREPORT, FORECAST, CAPACITY files current. 1 pending. Cron 15-min.": "Todos los archivos A/R, A/P, WIP, FABRIC, SHIPPINGREPORT, FORECAST, CAPACITY al día. 1 pendiente. Cron de 15 min.",
  "Daily-export discipline keeps this dashboard honest. Friday-only uploads = Friday-only insight.": "La disciplina de exportar a diario mantiene este panel honesto. Cargas solo los viernes = información solo los viernes.",
  "Throughput for complex programs": "Producción de programas complejos",
  "Simple <$15/u: 24 programs · 52,055 units · $318,084 · 8 late | Medium $15-30/u: 20 programs · 9,301 units · $217,918 · 10 late | Complex >$30/u: 10 programs · 916 units · $33,714 · 3 late": "Simple <$15/u: 24 programas · 52,055 unidades · $318,084 · 8 atrasados | Medio $15-30/u: 20 programas · 9,301 unidades · $217,918 · 10 atrasados | Complejo >$30/u: 10 programas · 916 unidades · $33,714 · 3 atrasados",
  "Complex programs need their own slot on the schedule — don't bury them between simple runs. Yield #2 in WIP file tracks the reality.": "Los programas complejos necesitan su propio espacio en el calendario — no los entierres entre corridas simples. Yield #2 en el archivo WIP refleja la realidad.",
  // ----- full-portal pass 2026-06-17 -----
  "0–2 weeks": "0–2 semanas",
  "1–3 months": "1–3 meses",
  "2–4 weeks": "2–4 semanas",
  "3+ months": "3+ meses",
  "1 · Sewn on the floor": "1 · Cosido en planta",
  "2 · Shipped to customers": "2 · Enviado a clientes",
  "3 · Sitting in the warehouse": "3 · En el almacén",
  "Amber 80-94%": "Ámbar 80-94%",
  "Green ≥ 95%": "Verde ≥ 95%",
  "Red < 80%": "Rojo < 80%",
  "65-84 ok": "65-84 ok",
  "≥85 strong": "≥85 fuerte",
  "<65 watch": "<65 vigilar",
  "88-1 — Dishonesty / theft — single fireable": "88-1 — Deshonestidad / robo — despido inmediato",
  "88-2 — Acts of violence — single fireable": "88-2 — Actos de violencia — despido inmediato",
  "88-3 — Intentional property damage — single fireable": "88-3 — Daño intencional a la propiedad — despido inmediato",
  "88-9 — Unjustified absence (2+ in 30d)": "88-9 — Ausencia injustificada (2+ en 30d)",
  "88-11 — Leaving without authorization (repeated)": "88-11 — Ausentarse sin autorización (repetido)",
  "88-12 — Insubordination (3 warnings)": "88-12 — Insubordinación (3 advertencias)",
  "88-13 — Negligence harming production": "88-13 — Negligencia que daña la producción",
  "88-14 — Intoxication / drugs — single fireable": "88-14 — Embriaguez / drogas — despido inmediato",
  "88-15 — Repeated tardiness (3 warnings in 90d)": "88-15 — Tardanzas repetidas (3 advertencias en 90d)",
  "Article 88 grounds tracked by this system:": "Causales del Artículo 88 que rastrea este sistema:",
  "All sections": "Todas las secciones",
  "Active": "Activo",
  "High": "Alto",
  "Low": "Bajo",
  "Normal": "Normal",
  "Needs": "Requiere",
  "Action required.": "Acción requerida.",
  "Admin Notes (chronological)": "Notas de admin (cronológico)",
  "Admin notes": "Notas de admin",
  "A/R Detail Report": "Reporte de detalle de A/R",
  "ACTUAL": "REAL",
  "Actual source:": "Fuente real:",
  "Allocated capacity": "Capacidad asignada",
  "Allocated capacity by customer": "Capacidad asignada por cliente",
  "Attainment to plan": "Cumplimiento del plan",
  "Area / Module": "Área / Módulo",
  "Area:": "Área:",
  "Awaiting Bihorario + SHIPPINGREPORT to compute produced vs shipped.": "Esperando Bihorario + SHIPPINGREPORT para calcular producido vs enviado.",
  "Awaiting FORECAST_VS_ACTUAL.xlsx and WIP.xlsx uploads.": "Esperando cargas de FORECAST_VS_ACTUAL.xlsx y WIP.xlsx.",
  "Awaiting a SHIPPINGREPORT to derive prices.": "Esperando un SHIPPINGREPORT para derivar precios.",
  "Awaiting next loop pass.": "Esperando la próxima pasada del loop.",
  "Base 75 +5/highlight −8/incident": "Base 75 +5/destacado −8/incidente",
  "Briefing · The CEO Read": "Resumen · La lectura del CEO",
  "By date": "Por fecha",
  "CSV": "CSV",
  "DOCX": "DOCX",
  "PNG/JPG": "PNG/JPG",
  "XLSX": "XLSX",
  "Capacity Benchmark": "Referencia de capacidad",
  "Capacity attainment:": "Cumplimiento de capacidad:",
  "Capacity gap:": "Brecha de capacidad:",
  "Cash landing:": "Efectivo entrando:",
  "Click for HR actions": "Clic para acciones de RRHH",
  "Click to add note / view detail": "Clic para agregar nota / ver detalle",
  "Collapse / expand team": "Contraer / expandir equipo",
  "Completed today (programs + units shipped/produced)": "Completado hoy (programas + unidades enviadas/producidas)",
  "Contents: Read and write": "Contenido: Lectura y escritura",
  "Current Month": "Mes actual",
  "Current Week": "Semana actual",
  "Customer total": "Total del cliente",
  "Day total": "Total del día",
  "Decision needed →": "Decisión requerida →",
  "Delete": "Eliminar",
  "Delivered YTD (shipped)": "Entregado YTD (enviado)",
  "Delivery risk:": "Riesgo de entrega:",
  "Dept:": "Depto:",
  "Describe the change or task…": "Describe el cambio o tarea…",
  "Download a formatted Excel of this section": "Descargar un Excel con formato de esta sección",
  "Drop files here": "Suelta los archivos aquí",
  "Error": "Error",
  "Evidence on file:": "Evidencia en archivo:",
  "Factory throughput:": "Producción de fábrica:",
  "Forecast (rest of year)": "Pronóstico (resto del año)",
  "Forecast accuracy:": "Precisión del pronóstico:",
  "Gap": "Brecha",
  "Code:": "Código:",
  "Generated by STA Admin Portal · summitteamapparel.com/admin": "Generado por el Portal Admin de STA · summitteamapparel.com/admin",
  "HR Termination Request": "Solicitud de despido de RRHH",
  "Highlights": "Destacados",
  "Invoices sent per day, receivables, and account status by customer.": "Facturas enviadas por día, cobros y estado de cuenta por cliente.",
  "Key account · prepaid": "Cuenta clave · prepagado",
  "Last 13 weeks": "Últimas 13 semanas",
  "Last 26 weeks": "Últimas 26 semanas",
  "Last 4 weeks": "Últimas 4 semanas",
  "Loading comments…": "Cargando comentarios…",
  "Loading…": "Cargando…",
  "Logged": "Registrado",
  "Made, not shipped": "Hecho, no enviado",
  "Metric": "Métrica",
  "Coreline excluded — paid up front": "Coreline excluido — pagado por adelantado",
  "Money Coming In · Open A/R": "Dinero entrando · A/R abierto",
  "Money Going Out · A/P": "Dinero saliendo · A/P",
  "NOT CAPTURED": "NO CAPTURADO",
  "Next 4 weeks:": "Próximas 4 semanas:",
  "No": "No",
  "No active work areas right now.": "No hay áreas de trabajo activas ahora.",
  "No comments yet. Be the first to drop a note.": "Aún no hay comentarios. Sé el primero en dejar una nota.",
  "No data.": "Sin datos.",
  "No files uploaded yet.": "Aún no se han subido archivos.",
  "No invoices found.": "No se encontraron facturas.",
  "No notes yet. Tap a quick log below or write one.": "Aún no hay notas. Toca un registro rápido abajo o escribe una.",
  "No remaining-to-ship data yet — awaits next loop pass.": "Aún no hay datos de pendiente por enviar — espera la próxima pasada.",
  "No tickets yet.": "Aún no hay tickets.",
  "No uploads yet — go to a section and upload some files first.": "Aún no hay cargas — ve a una sección y sube archivos primero.",
  "No uploads yet.": "Aún no hay cargas.",
  "No weekly revenue yet — upload a SHIPPINGREPORT to populate.": "Aún no hay ingresos semanales — sube un SHIPPINGREPORT para llenar.",
  "None on file. Clean record.": "Nada en archivo. Récord limpio.",
  "Not set": "Sin definir",
  "Notes:": "Notas:",
  "Nothing shipped yet this week.": "Nada enviado aún esta semana.",
  "One-page executive brief — finances, pipeline, cash, inventory, key accounts": "Resumen ejecutivo de una página — finanzas, pipeline, efectivo, inventario, cuentas clave",
  "Open A/R by customer — biggest first. Cash-flow projection. Expenses below.": "A/R abierto por cliente — de mayor a menor. Proyección de flujo de caja. Gastos abajo.",
  "Open Orders": "Órdenes abiertas",
  "Open Settings and paste a GitHub token to see uploads.": "Abre Configuración y pega un token de GitHub para ver las cargas.",
  "Open a print-ready PDF of this section": "Abre un PDF listo para imprimir de esta sección",
  "Overall / site": "General / sitio",
  "Past due:": "Vencido:",
  "Performance score": "Puntaje de desempeño",
  "Plant Manager": "Gerente de Planta",
  "Priority": "Prioridad",
  "Produced is tied to each customer by its share of that product's shipments": "Lo producido se atribuye a cada cliente por su parte de los envíos de ese producto",
  "Produced · Not Shipped": "Producido · No enviado",
  "Programs delayed today (program + reason)": "Programas atrasados hoy (programa + razón)",
  "Pulling latest uploads from GitHub…": "Trayendo las últimas cargas de GitHub…",
  "Quick log — tap one, add detail, save": "Registro rápido — toca uno, agrega detalle, guarda",
  "Re-enter": "Reingresar",
  "Reading the tables below:": "Cómo leer las tablas de abajo:",
  "Reason for termination request": "Razón de la solicitud de despido",
  "Received YTD": "Recibido YTD",
  "Recommended action:": "Acción recomendada:",
  "Reserved for production-line data.": "Reservado para datos de línea de producción.",
  "Rightmost point is the current/most recent week. Window scrolls back from there.": "El punto más a la derecha es la semana actual/más reciente. La ventana retrocede desde ahí.",
  "Section": "Sección",
  "Send a CSV or XLSX with these columns to populate the 500-employee scoreboard:": "Envía un CSV o XLSX con estas columnas para llenar el tablero de 500 empleados:",
  "Sending to Claude…": "Enviando a Claude…",
  "Severity legend:": "Leyenda de severidad:",
  "Shipped YTD = Paid": "Enviado YTD = Pagado",
  "Short summary…": "Resumen corto…",
  "Situation:": "Situación:",
  "Snapshot": "Resumen",
  "Start: 70 (neutral).": "Inicio: 70 (neutral).",
  "Subject": "Asunto",
  "Summary for HR file": "Resumen para el archivo de RRHH",
  "Supervisor name (if not in list)": "Nombre del supervisor (si no está en la lista)",
  "TOTAL OPEN": "TOTAL ABIERTO",
  "TOTAL YTD": "TOTAL YTD",
  "Target": "Meta",
  "The state of the business": "El estado del negocio",
  "The warehouse is clearing": "El almacén se está despejando",
  "The week is just starting.": "La semana apenas comienza.",
  "To fix:": "Para arreglar:",
  "Total (13 wk)": "Total (13 sem)",
  "Total due": "Total a entregar",
  "Total in production": "Total en producción",
  "Total open": "Total abierto",
  "Translation: through this point in the year, the plan said you would ship": "Traducción: hasta este punto del año, el plan decía que enviarías",
  "Type a reply…": "Escribe una respuesta…",
  "Northwind footprint": "Huella de Northwind",
  "Units actual": "Unidades reales",
  "Units forecast": "Unidades pronosticadas",
  "Upload the ON HAND POLYPM file to populate inventory.": "Sube el archivo ON HAND POLYPM para llenar el inventario.",
  "Upload the latest shipping report to populate this matrix.": "Sube el último reporte de envíos para llenar esta matriz.",
  "Uploads will fail until you unlock. Re-enter": "Las cargas fallarán hasta que desbloquees. Reingresa",
  "Verdict": "Veredicto",
  "WEEKLY CLOSE": "CIERRE SEMANAL",
  "Weeks on target": "Semanas en meta",
  "What do you need?": "¿Qué necesitas?",
  "What each customer pays per item.": "Lo que paga cada cliente por artículo.",
  "What this page is:": "Qué es esta página:",
  "What's happening:": "Qué está pasando:",
  "What's on your mind…": "¿Qué tienes en mente…",
  "Who paid:": "Quién pagó:",
  "Window": "Ventana",
  "Working…": "Trabajando…",
  "Written": "Escrito",
  "YES — 1 incident sufficient": "SÍ — 1 incidente suficiente",
  "YTD / All": "YTD / Todo",
  "YTD Scoreboard · Total Business": "Tablero YTD · Negocio total",
  "YTD attainment at": "Cumplimiento YTD en",
  "YTD received vs full-year plan": "Recibido YTD vs plan del año",
  "Year total (actual + forecast)": "Total del año (real + pronóstico)",
  "accumulated in warehouse →": "acumulado en almacén →",
  "actual to date + forecast": "real a la fecha + pronóstico",
  "actual, contemporaneous, witnessed": "real, contemporáneo, atestiguado",
  "capital tied up": "capital inmovilizado",
  "click to browse": "clic para explorar",
  "cut forecast & behind — call them": "recortó pronóstico y atrasado — llámalos",
  "cut their forecast and is behind": "recortó su pronóstico y está atrasado",
  "documentation-gap report": "reporte de brecha de documentación",
  "due today": "vence hoy",
  "expected cash in": "efectivo esperado en",
  "fabric · trim · finished": "tela · avíos · terminado",
  "forecast — not real A/R": "pronóstico — no A/R real",
  "heading to shipping": "rumbo a envío",
  "in progress": "en progreso",
  "in the system, not yet shipped": "en el sistema, aún no enviado",
  "in the warehouse": "en el almacén",
  "in the warehouse = sewn − shipped": "en el almacén = cosido − enviado",
  "incl. on order": "incl. en pedido",
  "is the parent of": "es el padre de",
  "landed value": "valor en sitio",
  "live from AR_Report": "en vivo desde AR_Report",
  "of plan (units). Customers with biggest variance shown above.": "del plan (unidades). Arriba los clientes con mayor variación.",
  "past due · who to chase →": "vencido · a quién perseguir →",
  "past req / due ≤7d": "pasado de fecha / vence ≤7d",
  "plus open WIP orders": "más órdenes WIP abiertas",
  "produced as a share of allocated capacity": "producido como parte de la capacidad asignada",
  "ramping up": "escalando",
  "ramping — ready capacity": "escalando — reservar capacidad",
  "revenue recognized on shipment": "ingreso reconocido al enviar",
  "sewn (Bihorario) − shipped · detail →": "cosido (Bihorario) − enviado · detalle →",
  "sewn ÷ goal": "cosido ÷ meta",
  "their fabric (incl. prepaid NW)": "su tela (incl. NW prepagado)",
  "this week": "esta semana",
  "units / yards": "unidades / yardas",
  "units out the door": "unidades despachadas",
  "units out the door · SHIPPINGREPORT": "unidades despachadas · SHIPPINGREPORT",
  "units owed: plan − shipped": "unidades adeudadas: plan − enviado",
  "units sewn": "unidades cosidas",
  "units sewn · Bihorario floor log": "unidades cosidas · registro de planta Bihorario",
  "units, produced − shipped": "unidades, producido − enviado",
  "units/wk avg plan": "unidades/sem plan promedio",
  "value sitting in the warehouse now": "valor parado en el almacén ahora",
  "vs target:": "vs meta:",
  "warehouse accumulation · units →": "acumulación de almacén · unidades →",
  "we don't log production yet": "aún no registramos producción",
  "when it lands →": "cuándo llega →",
  "whose goods are in the warehouse — usually orders sewn but not yet shipped": "de quién son los bienes — normalmente órdenes cosidas pero no enviadas",
  "with inventory on hand": "con inventario disponible",
  "with prices": "con precios",
  "wk / wk": "sem / sem",
  "your name": "tu nombre",
  "· work down over time": "· reducir con el tiempo",
  "— how much of this section is NW": "— cuánto de esta sección es NW",
  "— select DR Article 88 ground —": "— selecciona la causal del Artículo 88 RD —",
  "— the floor's daily production log, by product.": "— el registro diario de producción de planta, por producto.",
  "ℹ How it's measured:": "ℹ Cómo se mide:",
  "↳ Reply": "↳ Responder",
  "↻ Refresh": "↻ Actualizar",
  "⚖ DR Labor Law Notice:": "⚖ Aviso de Ley Laboral RD:",
  "⚖ DR labor-law note:": "⚖ Nota de ley laboral RD:",
  "⚖ Flag for HR review": "⚖ Marcar para revisión de RRHH",
  "⚖ How DR labor courts work:": "⚖ Cómo funcionan los tribunales laborales RD:",
  "⚠ Incidents (name — what happened — time — witnesses)": "⚠ Incidentes (nombre — qué pasó — hora — testigos)",
  "⚠ No incidents on file yet for this person.": "⚠ Aún no hay incidentes en archivo para esta persona.",
  "⚠ The blind spot:": "⚠ El punto ciego:",
  "⛔ Biggest Problem This Week": "⛔ El mayor problema de esta semana",
  "✉ Open in mail": "✉ Abrir en correo",
  "✓ Mark resolved": "✓ Marcar resuelto",
  "✓ Resolved": "✓ Resuelto",
  "✕ Close": "✕ Cerrar",
  "🎯 Goal:": "🎯 Meta:",
  "👍 Employee highlights (name — what they did well)": "👍 Destacados de empleados (nombre — qué hizo bien)",
  "💾 Save note": "💾 Guardar nota",
  "💾 Send to the AI": "💾 Enviar a la IA",
  "📄 Termination doc": "📄 Documento de despido",
  "📋 Copy": "📋 Copiar",
  "🔍 Search invoice #, customer or date…": "🔍 Buscar factura #, cliente o fecha…",
  "🔍 Search name or role…": "🔍 Buscar nombre o rol…",
  "🖨 Print report": "🖨 Imprimir reporte",
  "🤖 AI Response:": "🤖 Respuesta de IA:",
  "🤖 AI Tracker": "🤖 Rastreador IA",
  "Open positions": "Vacantes",
  "Top performers": "Mejores desempeños",
  "Needs attention": "Requiere atención",
  "Has incidents": "Tiene incidentes",
  "Performance": "Desempeño",
  "Summit Team Apparel · NYSE: vibes only": "Summit Team Apparel · NYSE: solo vibras",
  "Summit Team Apparel, LLC": "Summit Team Apparel, LLC",
  "Money Coming In": "Dinero entrando",
  "🟢 Active": "🟢 Activo",
  "🟢 Growing": "🟢 Creciendo",
  "🟡 Advancing": "🟡 Avanzando",
  "🟠 Developing": "🟠 En desarrollo",
  "⬜ Queued": "⬜ En cola",
  "Actual": "Real",
  "Pending": "Pendiente",
  "In Development": "En desarrollo",
  "In Process": "En proceso",
  "Actual + Process": "Real + En proceso",
  "Band/General Apparel — core production account": "Ropa de banda/general — cuenta de producción principal",
  "Included in Production Plan": "Incluido en el plan de producción",
  "Production slots allocated — pricing TBD": "Espacios de producción asignados — precio por definir",
  "Band Styles — art ready, samples required": "Estilos de banda — arte listo, se requieren muestras",
  "LX Tops, reversible & shorts, Basic T": "Tops LX, reversibles y shorts, camiseta básica",
  "Multi-category, consistent ordering": "Multicategoría, pedidos constantes",
  "Football Jerseys & Basketball — NW branding": "Camisetas de fútbol americano y básquetbol — marca NW",
  "Long Sleeve Qtr. Zip — art in dev": "Manga larga cierre 1/4 — arte en desarrollo",
  "Baseball pants & jersey": "Pantalones y camiseta de béisbol",
  "Basketball Jersey/Short, Basic T — up to 125K ": "Camiseta/short de básquetbol, camiseta básica — hasta 125K ",
  "Smaller consistent account": "Cuenta más pequeña y constante",
  "Sales Tracker → Pipeline Overview. Momentum = confidence/stage (🟢 Active, 🟡 Advancing, 🟠 Developing, ⬜ Queued/Pending). Revenue is a PROJECTION, not booked.": "Rastreador de ventas → Resumen del pipeline. Impulso = confianza/etapa (🟢 Activo, 🟡 Avanzando, 🟠 En desarrollo, ⬜ En cola/Pendiente). Los ingresos son una PROYECCIÓN, no reservados.",
  "Sales pipeline — 2026 outlook by momentum": "Pipeline de ventas — perspectiva 2026 por impulso",
  "Customer": "Cliente",
  "Status": "Estado",
  "2026 units": "Unidades 2026",
  "2026 revenue": "Ingresos 2026",
  "Product notes": "Notas de producto",
  "full NW detail →": "detalle completo de NW →",
  "Shipped this week": "Enviado esta semana",
  "Shipped last week": "Enviado la semana pasada",
  "Owed (prepaid)": "Adeudado (prepagado)",
  "In production": "En producción",
  "heading to shipping": "rumbo a envío",
  "not in latest CAPACITY export": "no está en la última exportación de CAPACIDAD",
  "Fill rate": "Tasa de cumplimiento",
  "shipped vs planned YTD": "enviado vs planeado YTD",
  "Raw materials left ($)": "Materia prima restante ($)",
  "On schedule — nothing past due": "En tiempo — nada vencido",
  "live line status · awaiting data upload": "estado de línea en vivo · esperando carga de datos",
  "what each line is running": "qué está produciendo cada línea",
  "Line": "Línea",
  "Product": "Producto",
  "Units": "Unidades",
  "Administrator": "Administrador",
  "password": "contraseña",
  "enter password": "ingresa la contraseña",
  "unlocking…": "desbloqueando…",
  "wrong password": "contraseña incorrecta",
  "✓ unlocked": "✓ desbloqueado",
  "✓ unlocked, reloading…": "✓ desbloqueado, recargando…",
  "Please sign in again so the file can be decrypted.": "Vuelve a iniciar sesión para poder descifrar el archivo.",
  "This export isn’t generated yet — it refreshes on the next loop pass.": "Esta exportación aún no se ha generado — se actualiza en la próxima pasada.",
  "Could not decrypt the file (wrong password?).": "No se pudo descifrar el archivo (¿contraseña incorrecta?).",
  "Allow pop-ups to open the printable PDF view.": "Permite ventanas emergentes para abrir la vista PDF imprimible.",
  "Pop-up blocked — allow pop-ups to print.": "Ventana emergente bloqueada — permite ventanas emergentes para imprimir.",
  "Leave blank to keep current token": "Deja en blanco para conservar el token actual",
  "Paste a token first.": "Pega un token primero.",
  "Saving locally and encrypting vault for all 5 users…": "Guardando localmente y cifrando la bóveda para los 5 usuarios…",
  "✓ Token saved & vault.json committed. Any user can now sign in from any device with just their password.": "✓ Token guardado y vault.json confirmado. Cualquier usuario puede iniciar sesión desde cualquier dispositivo solo con su contraseña.",
  "A GitHub token is required to commit the vault to the repo.": "Se requiere un token de GitHub para confirmar la bóveda en el repositorio.",
  "Encrypting for all users…": "Cifrando para todos los usuarios…",
  "Committing vault.json to repo…": "Confirmando vault.json en el repositorio…",
  "✓ Saved. All five users can now log in with just their password.": "✓ Guardado. Los cinco usuarios ya pueden iniciar sesión solo con su contraseña.",
  "Save & commit to repo": "Guardar y confirmar en el repositorio",
  "Delete vault.json from the repo? Everyone will need to re-set up keys.": "¿Eliminar vault.json del repositorio? Todos tendrán que reconfigurar sus claves.",
  "No GitHub token in this session — re-paste one in the field above first.": "No hay token de GitHub en esta sesión — vuelve a pegar uno en el campo de arriba primero.",
  "vault.json not found in repo": "vault.json no se encontró en el repositorio",
  "Delete failed": "Error al eliminar",
  "Vault reset. Sign out and back in to re-create.": "Bóveda restablecida. Cierra sesión y vuelve a entrar para recrearla.",
  "If a teammate signs in but their uploads or comments fail, click this and screenshot the output.": "Si un compañero inicia sesión pero sus cargas o comentarios fallan, haz clic aquí y toma una captura del resultado.",
  "Latest close": "Último cierre",
  "Avg / wk": "Prom. / sem",
  "dashed line": "línea punteada",
  "Period high": "Máximo del período",
  "Period low": "Mínimo del período",
  "Since start": "Desde el inicio",
  "Weekly revenue": "Ingresos semanales",
  "Open A/R sorted by when it's due. Overdue = follow up now; the rest is expected cash by its due date.": "A/R abierto ordenado por fecha de vencimiento. Vencido = dar seguimiento ahora; el resto es efectivo esperado en su fecha de vencimiento.",
  "Due ≤ 7 days": "Vence ≤ 7 días",
  "Due 8–30 days": "Vence 8–30 días",
  "Due 31+ days": "Vence 31+ días",
  "Nothing overdue — nice.": "Nada vencido — excelente.",
  "now": "ahora",
  "Nothing upcoming.": "Nada próximo.",
  "Expected pay date = each invoice's due date (from QuickBooks terms). \"Overdue\" = already past due — follow up now. A true average days-to-pay would need a payments-received report (not yet uploaded).": "Fecha de pago esperada = la fecha de vencimiento de cada factura (según los términos de QuickBooks). \"Vencido\" = ya pasó su vencimiento — dar seguimiento ahora. Un verdadero promedio de días para cobrar requeriría un informe de pagos recibidos (aún no cargado).",
  "Where the money goes — A/P by category, top vendors, and capital tied up in materials. Use this to set budgets and find what to cut.": "A dónde va el dinero — A/P por categoría, principales proveedores y capital inmovilizado en materiales. Úsalo para fijar presupuestos y encontrar qué recortar.",
  "Fabric/trims/supplies sitting in the warehouse — over-buying here ties up cash.": "Tela/avíos/suministros en el almacén — comprar de más aquí inmoviliza efectivo.",
  "Open requests": "Solicitudes abiertas",
  "Ask AI for help": "Pide ayuda a la IA",
  "All tickets": "Todos los tickets",
  "Your tickets": "Tus tickets",
  "Anyone on the team can drop a request here — site changes, dashboard tweaks, data corrections, anything. The 15-minute AI loop reads pending tickets and acts on them.": "Cualquier persona del equipo puede dejar una solicitud aquí — cambios al sitio, ajustes de tableros, correcciones de datos, lo que sea. El ciclo de IA de 15 minutos lee los tickets pendientes y actúa sobre ellos.",
  "Need anything done to the site, dashboards or data? Drop a request — the AI will pick it up on its next pass and reply.": "¿Necesitas algo en el sitio, los tableros o los datos? Deja una solicitud — la IA la tomará en su próxima pasada y responderá.",
  "Description can't be empty.": "La descripción no puede estar vacía.",
  "Submitting…": "Enviando…",
  "No support backend configured. Open Settings and paste a GitHub token.": "No hay backend de soporte configurado. Abre Ajustes y pega un token de GitHub.",
  "✓ Submitted. The AI will pick this up on its next pass (within 15 min).": "✓ Enviado. La IA lo recogerá en su próxima pasada (dentro de 15 min).",
  "(no subject)": "(sin asunto)",
  "Notes from the AI tracker about each section. Reply with your goals — the AI uses them to score progress on the dashboards. You can post to any section, view all sections, and the AI will execute your directives.": "Notas del rastreador de IA sobre cada sección. Responde con tus objetivos — la IA los usa para calificar el progreso en los tableros. Puedes publicar en cualquier sección, ver todas las secciones, y la IA ejecutará tus directivas.",
  "What's on your mind…": "¿Qué tienes en mente…",
  "Comment can't be empty.": "El comentario no puede estar vacío.",
  "No upload key on this device. Unlock the token banner at the top of the page first.": "No hay clave de carga en este dispositivo. Desbloquea primero el banner del token en la parte superior de la página.",
  "Posting…": "Publicando…",
  "✓ Posted.": "✓ Publicado.",
  "(you)": "(tú)",
  "👁 Observation": "👁 Observación",
  "Note": "Nota",
  "Cannot post — unlock the token first.": "No se puede publicar — desbloquea el token primero.",
  "✓ Marked resolved": "✓ Marcado como resuelto",
  "✓ Reply posted": "✓ Respuesta publicada",
  " Your session expired — sign in again.": "Tu sesión expiró — inicia sesión de nuevo.",
  "open orders + rest-of-year forecast vs how customers actually deliver — and what it means for production": "órdenes abiertas + pronóstico del resto del año vs cómo entregan realmente los clientes — y qué significa para producción",
  "forecast > capacity": "pronóstico > capacidad",
  "within capacity": "dentro de la capacidad",
  "Open $": "Abierto $",
  "under-delivering": "entregando por debajo",
  "TBD": "Por definir",
  "The state of the business, computed live from the latest uploads — every line links to the detail.": "El estado del negocio, calculado en vivo desde las últimas cargas — cada línea enlaza al detalle.",
  "last full wk": "última sem completa",
  "revenue pace · is business up or down": "ritmo de ingresos · si el negocio sube o baja",
  "forecast": "pronóstico",
  "No production count is logged.": "No se registra un conteo de producción.",
  "Upload a daily production log.": "Sube un registro diario de producción.",
  "Until then, anything cut/sewn/finished but not yet shipped is invisible — it sits between the blue and green boxes above.": "Hasta entonces, todo lo cortado/cosido/terminado pero aún no enviado es invisible — queda entre las cajas azul y verde de arriba.",
  "Open US$": "US$ abiertos",
  "goal vs actual vs attainment, by line · source: SEWING PRODUCTION RESULTS": "meta vs real vs cumplimiento, por línea · fuente: SEWING PRODUCTION RESULTS",
  "how much is scheduled to produce each week, from orders in the system · Monday-start": "cuánto está programado producir cada semana, a partir de las órdenes en el sistema · inicio lunes",
  "At risk": "En riesgo",
  "On track": "En camino",
  "Watch": "Vigilar",
  "Coreline has paid in advance, so these programs carry no receivable risk. They are isolated here so they don't distort attainment %, late-order $ at risk, or capacity pressure on the main view. Manage these as throughput-only — pace the work, don't chase the calendar.": "Coreline pagó por adelantado, así que estos programas no implican riesgo de cobro. Se aíslan aquí para que no distorsionen el % de cumplimiento, los $ en riesgo por órdenes atrasadas, ni la presión de capacidad en la vista principal. Gestiónalos solo por rendimiento — marca el ritmo del trabajo, no persigas el calendario.",
  "Source: AR_Report open invoices with real due dates from QuickBooks. Past-due column = invoices that have already passed their due date but haven't been paid. Each weekly column = amount due that week.": "Fuente: facturas abiertas de AR_Report con fechas de vencimiento reales de QuickBooks. Columna vencido = facturas que ya pasaron su fecha de vencimiento pero no se han pagado. Cada columna semanal = monto que vence esa semana.",
  "$ shipped (YTD)": "$ enviados (YTD)",
  "$ net of discount": "$ neto de descuento",
  "Avg $/unit": "Prom. $/unidad",
  "Projection from forecast file.": "Proyección del archivo de pronóstico.",
  "ACTUAL = invoiced revenue from the Sales report · later months forecast": "REAL = ingresos facturados del informe de ventas · meses posteriores pronóstico",
  "Drop your file — we'll route it to the right section based on the filename.": "Suelta tu archivo — lo dirigiremos a la sección correcta según el nombre del archivo.",
  "or click to browse": "o haz clic para explorar",
  "up to 25 MB per file · multiple files OK": "hasta 25 MB por archivo · varios archivos permitidos",
  "all sections": "todas las secciones",
  "your section": "tu sección",
  "✓ Upload key unlocked — you can now upload.": "✓ Clave de carga desbloqueada — ya puedes subir.",
  "No upload method configured. Open Settings and paste a GitHub token.": "No hay método de carga configurado. Abre Ajustes y pega un token de GitHub.",
  "Delete this file from the repo?": "¿Eliminar este archivo del repositorio?",
  "Permanently delete this upload (blob + GitHub + database row)?": "¿Eliminar permanentemente esta carga (blob + GitHub + fila de base de datos)?",
  " Sign in again.": "Inicia sesión de nuevo.",
  "Live from Azure SQL — admins see every section.": "En vivo desde Azure SQL — los administradores ven todas las secciones.",
  "files": "archivos",
  "Pulls the most recent uploads from GitHub and sends them to Claude for analysis. Stays in your browser — no server in between.": "Toma las cargas más recientes de GitHub y las envía a Claude para análisis. Se queda en tu navegador — sin servidor de por medio.",
  "Claude · just now": "Claude · justo ahora",
  "Claude API error": "Error de la API de Claude",
  "None on file. Highlights appear when a supervisor cites this person positively in a daily report.": "Ninguno en archivo. Los reconocimientos aparecen cuando un supervisor menciona positivamente a esta persona en un reporte diario.",
  "👍 Great work": "👍 Buen trabajo",
  "✅ Quality catch": "✅ Detección de calidad",
  "💪 Extra effort": "💪 Esfuerzo extra",
  "⏰ Late": "⏰ Tarde",
  "🚪 Left early": "🚪 Salió temprano",
  "❌ Absent": "❌ Ausente",
  "🔧 Needs training": "🔧 Necesita capacitación",
  "⚠ Behavior issue": "⚠ Problema de conducta",
  "Tap a quick-log button above (then add the detail), or type a note from scratch. Timestamped and saved to this person's record for the AI to read.": "Toca un botón de registro rápido arriba (luego añade el detalle), o escribe una nota desde cero. Se marca con fecha/hora y se guarda en el expediente de esta persona para que la IA la lea.",
  "Note text required.": "Se requiere el texto de la nota.",
  "No upload key.": "No hay clave de carga.",
  "Saving…": "Guardando…",
  "✓ Saved — appears within 15 min after cron pass.": "✓ Guardado — aparece dentro de 15 min tras la pasada del cron.",
  "Select an Article 88 ground.": "Selecciona una causal del Artículo 88.",
  "Add a summary for the HR file.": "Añade un resumen para el expediente de RRHH.",
  "No upload key — unlock on the upload page first.": "No hay clave de carga — desbloquea primero en la página de carga.",
  "✓ Submitted — agent will process on next loop pass (within 15 min).": "✓ Enviado — el agente lo procesará en la próxima pasada (dentro de 15 min).",
  "Type a note first.": "Escribe una nota primero.",
  "Upload key locked — sign out and back in to unlock.": "Clave de carga bloqueada — cierra sesión y vuelve a entrar para desbloquear.",
  "✓ Saved — the AI reads it on the next pass (~15 min).": "✓ Guardado — la IA lo lee en la próxima pasada (~15 min).",
  "Operation note saved for the AI": "Nota de operación guardada para la IA",
  "Pick an area and a date.": "Elige un área y una fecha.",
  "Fill at least one section before submitting.": "Llena al menos una sección antes de enviar.",
  "No upload key — unlock token on the upload page first.": "No hay clave de carga — desbloquea el token primero en la página de carga.",
  "✓ Submitted — scoreboard will update within 15 min.": "✓ Enviado — el marcador se actualizará dentro de 15 min.",
  "Daily report submitted": "Reporte diario enviado",
  "Email copied to clipboard": "Correo copiado al portapapeles",
  "Copy failed": "Error al copiar",
  "Action Required": "Acción requerida",
  "On Track": "En camino",
  "Needs Data": "Faltan datos",
  "WIP late ($)": "WIP atrasado ($)",
  "⛔ red = act today": "⛔ rojo = actuar hoy",
  "⚠️ amber = watch this week": "⚠️ ámbar = vigilar esta semana",
  "✓ green = on track": "✓ verde = en camino",
  "ℹ️ blue = need more data": "ℹ️ azul = faltan datos",
  "On-time delivery performance by customer, weekly production, plan vs actual, and delay tracking. (Per-customer on-time scoring expands once the delivery-performance file is loaded.)": "Desempeño de entrega a tiempo por cliente, producción semanal, plan vs real, y seguimiento de atrasos. (La puntuación de entrega a tiempo por cliente se amplía cuando se carga el archivo de desempeño de entregas.)",
  "Plan US$": "Plan US$",
  "Actual US$": "Real US$",
  "% US$": "% US$",
  "Produced = shipped (proxy — no separate production-line completion feed yet). Open Balance = running cumulative Planned − Shipped from start of window.": "Producido = enviado (aproximación — aún no hay un feed separado de cierre de línea de producción). Saldo abierto = acumulado corriente Planeado − Enviado desde el inicio de la ventana.",
  "Product still owed (open orders)": "Producto aún adeudado (órdenes abiertas)",
  "Still to deliver (open orders)": "Aún por entregar (órdenes abiertas)",
  "By program: ": "Por programa:",
  "$ value left": "$ valor restante",
  "$ value": "$ valor",
  "inbound": "entrante",
  "US$": "US$",
  "The factory gets paid on shipment. This page follows the work from order to cash — by customer, by week.": "La fábrica cobra al enviar. Esta página sigue el trabajo de la orden al efectivo — por cliente, por semana.",
  "on track": "en camino",
  // ── WIP / sewing stage codes ──
  "MATCHING": "EMPAREJADO",
  "MARK": "MARCADO",
  "SEWING": "COSTURA",
  "MISSING SNAP": "FALTA BROCHE",
  "CUTTING": "CORTE",
  "PULLING PROCESS": "PROCESO DE EXTRACCIÓN",
  "MATCHING/MISSING SNAP": "EMPAREJADO/FALTA BROCHE",
  "NO FABRIC/MISSING ELASTIC": "SIN TELA/FALTA ELÁSTICO",
  "MATCHING/MISSING ZIPPER": "EMPAREJADO/FALTA CIERRE",
  "MATCHING/MISSING VID": "EMPAREJADO/FALTA VID",
  "PRINTING": "IMPRESIÓN",
  "MARKERS": "MARCADORES",
  "DESIGN": "DISEÑO",
  "MEASURED": "MEDIDO",
  "LATE": "ATRASADO",
  "OPEN": "ABIERTA",
  // ── Delay reasons ──
  "Lack of Supervision": "Falta de supervisión",
  "Lack of Work": "Falta de trabajo",
  "Quality Issues": "Problemas de calidad",
  "Absenteeism": "Ausentismo",
  "Machine Failure": "Falla de máquina",
  "Planning Changes": "Cambios de planificación",
  "Lack of Training": "Falta de capacitación",
  "Module Rebalance": "Rebalanceo de módulo",
  "Power Failure": "Falla eléctrica",
  // ── Org-chart titles ──
  "Plant Manager": "Gerente de Planta",
  "Data Analyst": "Analista de Datos",
  "HR Manager": "Gerente de RRHH",
  "Finance Manager": "Gerente de Finanzas",
  "Planning Manager": "Gerente de Planificación",
  "Product Development Manager": "Gerente de Desarrollo de Producto",
  "Quality Manager": "Gerente de Calidad",
  "Industrial Engineering Manager": "Gerente de Ingeniería Industrial",
  "Maintenance Manager": "Gerente de Mantenimiento",
  "Sublimation Manager": "Gerente de Sublimación",
  "Production / Sewing Manager": "Gerente de Producción / Costura",
  "HR Coordinator": "Coordinador de RRHH",
  "Safety & Health Coordinator": "Coordinador de Seguridad y Salud",
  "Buyer": "Comprador",
  "Import/Export Coordinator": "Coordinador de Importación/Exportación",
  "Building Coordinator": "Coordinador de Edificio",
  "Product Development Coordinator": "Coordinador de Desarrollo de Producto",
  "Graphic Design Supervisor": "Supervisor de Diseño Gráfico",
  "Quality Coordinator": "Coordinador de Calidad",
  "IE Coordinator": "Coordinador de IE",
  "Building Maintenance Coordinator": "Coordinador de Mantenimiento de Edificio",
  "Mechanics Supervisor": "Supervisor de Mecánica",
  "Sublimation Print Coordinator": "Coordinador de Impresión de Sublimación",
  "Warehouse Coordinator": "Coordinador de Almacén",
  "Packing Coordinator": "Coordinador de Empaque",
  "Sewing Coordinator": "Coordinador de Costura",
  "Cutting Coordinator": "Coordinador de Corte",
  "Cutting Supervisors": "Supervisores de Corte",
  "Sewing Supervisors": "Supervisores de Costura",
  "Embroidery Supervisors": "Supervisores de Bordado",
  // ── Account identity / methodology notes (NW + Granite) ──
  "NW = the brand; Coreline = the entity that orders + prepaid. Shipping data is filed under \"NW\", orders/production/forecast under \"Coreline\". This section merges both.": "NW = la marca; Coreline = la entidad que ordena + prepaga. Los datos de envío se archivan bajo \"NW\", las órdenes/producción/pronóstico bajo \"Coreline\". Esta sección fusiona ambos.",
  "What NW is demanding: committed weekly run-rate + required completion date per product, compared against our open order book. \"LATE\" = at the committed weekly rate we cannot clear the open units by the due date. Targets are entered manually for now and will be replaced when a target file is uploaded.": "Lo que NW exige: ritmo semanal comprometido + fecha de finalización requerida por producto, comparado con nuestro libro de órdenes abierto. \"ATRASADO\" = al ritmo semanal comprometido no podemos liquidar las unidades abiertas para la fecha de vencimiento. Las metas se ingresan manualmente por ahora y se reemplazarán cuando se cargue un archivo de metas.",
  "What Granite is demanding: committed weekly run-rate + required completion date per product, compared against our open order book. \"LATE\" = at the committed weekly rate we cannot clear the open units by the due date. Targets are entered manually for now and will be replaced when a target file is uploaded.": "Lo que Granite exige: ritmo semanal comprometido + fecha de finalización requerida por producto, comparado con nuestro libro de órdenes abierto. \"ATRASADO\" = al ritmo semanal comprometido no podemos liquidar las unidades abiertas para la fecha de vencimiento. Las metas se ingresan manualmente por ahora y se reemplazarán cuando se cargue un archivo de metas.",
  "Coreline (NW) prepaid, so shipping draws down what STA owes rather than booking new revenue. What STA still owes Coreline = the open order book: product ordered and paid for but not yet delivered. This number shrinks automatically each week as orders ship.": "Coreline (NW) prepagó, así que enviar reduce lo que STA debe en vez de registrar nuevos ingresos. Lo que STA aún le debe a Coreline = el libro de órdenes abierto: producto ordenado y pagado pero aún no entregado. Este número se reduce automáticamente cada semana a medida que se envían las órdenes.",
  "Granite — core program. The Granite RTT (Raglan Tee retail) program is tracked separately and is not included here.": "Granite — programa principal. El programa Granite RTT (Raglan Tee retail) se rastrea por separado y no se incluye aquí.",
  "Granite is invoiced on shipment (not prepaid). \"Still to deliver\" = the open order book — product ordered but not yet shipped; \"delivered\" = units shipped YTD. The bar shows how much of the committed book has shipped.": "Granite se factura al enviar (no prepagado). \"Aún por entregar\" = el libro de órdenes abierto — producto ordenado pero aún no enviado; \"entregado\" = unidades enviadas YTD. La barra muestra cuánto del libro comprometido se ha enviado.",
  "Granite' Raglan Tee (t-shirt) retail program — scheduled separately from the core Granite program.": "Programa retail Raglan Tee (camiseta) de Granite — programado por separado del programa principal de Granite.",
  "Dollar value of raw materials STA holds for NW orders, by category. Also counted in the general inventory totals.": "Valor en dólares de la materia prima que STA tiene para las órdenes de NW, por categoría. También contado en los totales generales de inventario.",
  "Dollar value of raw materials STA holds for Granite orders, by category. Also counted in the general inventory totals.": "Valor en dólares de la materia prima que STA tiene para las órdenes de Granite, por categoría. También contado en los totales generales de inventario.",
  "★ Owner's Brief": "★ Resumen del Dueño",
};
const I18N_RULES = [
  [/^([\d,\.\$%]+) units shipped YTD$/,'$1 unidades enviadas YTD'],
  [/^([\d,\.\$]+) units$/,'$1 unidades'],
  [/^([\d,\.]+) customers?$/,(m,n)=>`${n} cliente${n==='1'?'':'s'}`],
  [/^([\d,\.]+) programs?$/,(m,n)=>`${n} programa${n==='1'?'':'s'}`],
  [/^([\d,\.]+) invoices?$/,(m,n)=>`${n} factura${n==='1'?'':'s'}`],
  [/^([\d,\.\$]+) planned$/,'$1 planificado'],
  [/^wk of (.+)$/,'sem del $1'],
  [/^average (.+)\/wk$/,'promedio $1/sem'],
  [/^due in 7 days$/i,'vence en 7 días'],
  [/^([\d,\.]+) units past required date — recovery in production$/,'$1 unidades vencidas de la fecha requerida — recuperación en producción'],
  [/^([\d,\.]+) units past required date — how late$/,'$1 unidades vencidas de la fecha requerida — qué tan tarde'],
  [/^Delivered ([\d,\.]+) units$/,'Entregadas $1 unidades'],
  [/^([\d,\.]+) still owed$/,'$1 aún adeudadas'],
  [/^([\d,\.]+)% of the ([\d,\.]+)-unit prepaid program delivered$/,'$1% del programa prepagado de $2 unidades entregado'],
  [/^of ([\d,\.]+) planned$/,'de $1 planeadas'],
  [/^([\d,\.]+) on hand$/,'$1 disponibles'],
  // ── Account hero / NW + Granite sections (SHORT = NW|Granite, kept) ──
  [/^Where (NW|Granite) stands · (.+)$/, 'Dónde está $1 · $2'],
  [/^([\d,\.]+) units on open order · ([\d,\.]+) in production · ([\d,\.]+) planned this week · (.+) fill rate YTD$/, '$1 unidades en orden abierta · $2 en producción · $3 planeadas esta semana · $4 de cumplimiento YTD'],
  [/^(\d+) (?:program is|programs are) tracking behind (NW|Granite)'s dates — ([\d,\.]+) units at risk\. We know it and the lines are running to recover\.$/, (m,n,s,u)=>`${n} ${n==='1'?'programa atrasado':'programas atrasados'} respecto a las fechas de ${s} — ${u} unidades en riesgo. Lo sabemos y las líneas están corriendo para recuperarse.`],
  [/^([\d,\.]+) units are past their required date\. ([\d,\.]+) units in production now\.$/, '$1 unidades están vencidas de su fecha requerida. $2 unidades en producción ahora.'],
  [/^On track — every program is pacing to its committed date\. ([\d,\.]+) units in production\.$/, 'En camino — cada programa avanza hacia su fecha comprometida. $1 unidades en producción.'],
  [/^([\d,\.]+) still to ship$/, '$1 aún por enviar'],
  [/^([\d,\.]+)% of the committed program \(([\d,\.]+) units\) delivered to date · (prepaid, drawing down|invoiced on shipment)$/, (m,p,u,t)=>`${p}% del programa comprometido (${u} unidades) entregado a la fecha · ${t==='prepaid, drawing down'?'prepagado, reduciéndose':'facturado al enviar'}`],
  [/^What (NW|Granite) is demanding — vs our pace$/, 'Lo que $1 exige — vs nuestro ritmo'],
  [/^committed weekly rate \+ completion date per product · ([\d,\.]+) tracking late · ([\d,\.]+) units at risk$/, 'ritmo semanal comprometido + fecha de finalización por producto · $1 atrasados · $2 unidades en riesgo'],
  [/^(NW|Granite) weekly target$/, 'meta semanal de $1'],
  [/^([\d,\.]+)\/wk$/, '$1/sem'],
  [/^LATE · ~(\d+) wk$/, 'ATRASADO · ~$1 sem'],
  [/^([\d,\.]+) units short by date$/, '$1 unidades faltantes para la fecha'],
  [/^([\d,\.]+) at risk$/, '$1 en riesgo'],
  [/^What we owe (NW|Granite) · they prepaid for production$/, 'Lo que le debemos a $1 · prepagaron la producción'],
  [/^(NW|Granite) order book · still to deliver$/, 'libro de órdenes de $1 · aún por entregar'],
  [/^([\d,\.]+) units · (\$.+)$/, '$1 unidades · $2'],
  [/^(\$[\d,\.KMB]+) · (\d+) programs?$/, (m,d,n)=>`${d} · ${n} programa${n==='1'?'':'s'}`],
  [/^(\$[\d,\.KMB]+) \(prepaid\)$/, '$1 (prepagado)'],
  [/^the metrics a brand like (NW|Granite) runs on you$/, 'las métricas con las que una marca como $1 te mide'],
  [/^([\d,\.]+) \/ ([\d,\.]+) planned$/, '$1 / $2 planeadas'],
  [/^(\d+) of (\d+) weeks ≥95%$/, '$1 de $2 semanas ≥95%'],
  [/^([\d,\.]+)% of order book$/, '$1% del libro de órdenes'],
  [/^what's committed to ship each week, next (\d+) weeks$/, 'lo comprometido a enviar cada semana, próximas $1 semanas'],
  [/^(NW|Granite) in production — by sewing stage$/, 'producción de $1 — por etapa de costura'],
  [/^([\d,\.]+) units \/ (.+) on the floor · from WIP order book$/, '$1 unidades / $2 en planta · del libro de órdenes WIP'],
  [/^(NW|Granite) production plan — by week$/, 'plan de producción de $1 — por semana'],
  [/^how much we're set to produce each week · (.+)$/, 'cuánto estamos por producir cada semana · $1'],
  [/^(NW|Granite) WIP report — open orders by program$/, 'informe WIP de $1 — órdenes abiertas por programa'],
  [/^the order book (NW|Granite) cares about · (.+)$/, 'el libro de órdenes que le importa a $1 · $2'],
  [/^(NW|Granite) shipped vs plan — by week$/, 'enviado vs plan de $1 — por semana'],
  [/^what actually went out the door · (.+)$/, 'lo que realmente salió · $1'],
  [/^Forecast value: (.+)$/, 'Valor de pronóstico: $1'],
  [/^read before sending to (NW|Granite)$/, 'leer antes de enviar a $1'],
  [/^Raw materials we hold for (NW|Granite) — \$ left$/, 'Materia prima que tenemos para $1 — $ restante'],
  [/^fabric, trims & supplies STA is holding for (NW|Granite) · (.+)$/, 'tela, avíos y suministros que STA tiene para $1 · $2'],
  [/^on-hand value · (\d+) materials$/, 'valor disponible · $1 materiales'],
  [/^top (\d+) of (\d+)$/, 'top $1 de $2'],
  [/^Awaiting next loop pass to build the (NW|Granite) section\.$/, 'Esperando la próxima pasada para construir la sección de $1.'],
  [/^Key Account( · Prepaid)?$/, (m,p)=>`Cuenta clave${p?' · Prepagada':''}`],
  // ── execOps / coaching / sales dynamic ──
  [/^([\d,\.]+) \/ ([\d,\.]+) units \(YTD\)$/, '$1 / $2 unidades (YTD)'],
  [/^([\d,\.]+) units past req date$/, '$1 unidades vencidas de la fecha req.'],
  [/^target (\d+)%$/, 'meta $1%'],
  [/^(\d+) customers? · forecast = ASA_Sales_Tracker · actual = SHIPPINGREPORT$/, (m,n)=>`${n} cliente${n==='1'?'':'s'} · pronóstico = ASA_Sales_Tracker · real = SHIPPINGREPORT`],
  [/^Capacity = ([\d,\.]+) units\/wk · Target (\d+)% = ([\d,\.]+) units\/wk$/, 'Capacidad = $1 unidades/sem · Meta $2% = $3 unidades/sem'],
  [/^(\d+) late · ([\d,\.]+) units overdue · (\d+) total open programs$/, '$1 atrasados · $2 unidades vencidas · $3 programas abiertos en total'],
  [/^(\d+)d late$/, '$1d atrasado'],
  [/^(\d+)d remain$/, '$1d restantes'],
  [/^(\d+) decisions? needing CEO\/owner attention$/, (m,n)=>`${n} ${n==='1'?'decisión que requiere':'decisiones que requieren'} atención del CEO/dueño`],
  [/^week ending (.+)$/, 'semana que termina $1'],
  [/^Theme (\d+)$/, 'Tema $1'],
  [/^of (\d+) total$/, 'de $1 en total'],
  [/^([\d,\.]+) invoices · (.+) total · newest first$/, '$1 facturas · $2 en total · más recientes primero'],
  [/^(.+) — invoice detail \((\d+) open\)$/, '$1 — detalle de factura ($2 abiertas)'],
  [/^Printed: (.+)$/, 'Impreso: $1'],
  // ── WIP / capacity / benchmark dynamic ──
  [/^\+ ([\d,\.]+) Coreline separate$/, '+ $1 Coreline aparte'],
  [/^(\d+) programs? · (\d+) at risk · (\d+) watch · Coreline shown separately below$/, (m,a,b,c)=>`${a} programa${a==='1'?'':'s'} · ${b} en riesgo · ${c} en vigilancia · Coreline se muestra por separado abajo`],
  [/^(\d+) programs · ([\d,\.]+) units · no \$ at risk · work down over time$/, '$1 programas · $2 unidades · sin $ en riesgo · reducir con el tiempo'],
  [/^([\d,\.]+) units past required date — recovery in production$/, '$1 unidades vencidas de la fecha requerida — recuperación en producción'],
];
function _i18nText(t){
  const norm = t.replace(/\u00a0/g,' ');   // normalize &nbsp; so button labels match
  const k = norm.trim(); if (!k) return null;
  if (I18N_DICT[k] != null) return norm.replace(k, I18N_DICT[k]);
  for (const [re, rep] of I18N_RULES){ if (re.test(k)) return norm.replace(k, k.replace(re, rep)); }
  return null;
}
function translateTree(rootEl){
  if (!rootEl) return;
  const w = document.createTreeWalker(rootEl, NodeFilter.SHOW_TEXT, {
    acceptNode:(n)=> n.nodeValue && n.nodeValue.trim() && !/^(SCRIPT|STYLE|CANVAS)$/.test(n.parentNode && n.parentNode.nodeName)
      ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT });
  const nodes=[]; let c; while((c=w.nextNode())) nodes.push(c);
  nodes.forEach(n=>{ const o=_i18nText(n.nodeValue); if (o!=null) n.nodeValue=o; });
  rootEl.querySelectorAll('[placeholder],[title]').forEach(el=>{
    ['placeholder','title'].forEach(a=>{ const v=el.getAttribute(a); if(!v) return; const o=_i18nText(v); if(o!=null) el.setAttribute(a,o); });
  });
}
function ensureLangToggle(){
  if (document.getElementById('asaLangToggle')) { _langToggleActive(); return; }
  const av = document.getElementById('appView'); if (!av || av.hidden) return;
  const d = document.createElement('div'); d.id='asaLangToggle';
  d.style.cssText='position:fixed;top:12px;right:16px;z-index:99999;display:flex;background:#fff;border:1px solid #d7dde3;border-radius:999px;overflow:hidden;font-size:12px;font-weight:700;box-shadow:0 1px 4px rgba(0,0,0,.1)';
  d.innerHTML = `<button data-l="en" style="border:0;padding:6px 13px;cursor:pointer">EN</button><button data-l="es" style="border:0;padding:6px 13px;cursor:pointer">ES</button>`;
  d.querySelectorAll('button').forEach(b=> b.addEventListener('click', ()=> setLang(b.dataset.l)));
  document.body.appendChild(d); _langToggleActive();
}
function _langToggleActive(){
  const d=document.getElementById('asaLangToggle'); if(!d) return;
  d.querySelectorAll('button').forEach(b=>{ const on=b.dataset.l===LANG;
    b.style.background=on?'#0a3d62':'#fff'; b.style.color=on?'#fff':'#5f6b76'; });
}
function applyLang(){
  try { ensureLangToggle(); } catch {}
  if (LANG !== 'es') return;
  try { translateTree(document.getElementById('content')); translateTree(document.getElementById('sidebarNav')); } catch {}
}
function setLang(code){
  LANG = code; try { localStorage.setItem('asa_lang', code); } catch {}
  document.documentElement.lang = code; _langToggleActive();
  try {
    const cur = document.querySelector('#sidebarNav button.active');
    const view = cur ? cur.dataset.view : (typeof SESSION!=='undefined' && SESSION ? (firstAllowedView(SESSION)||'overview') : 'overview');
    if (typeof SESSION !== 'undefined' && SESSION) buildSidebar(SESSION);  // reset nav to EN source
    navigate(view);
  } catch {}
}
window.__asaSetLang = setLang;
