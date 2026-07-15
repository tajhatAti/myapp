/* =========================================
   AHAD CO - COMPLETE FUNCTIONALITY
   All Save/Update/Delete Features Working
   ========================================= */

const API = "";
let signupUsername = "";
let authToken = localStorage.getItem("ahad_token") || null;
let resendTimerInterval = null;
let currentTab = 'overview';

// Screen Navigation
function showScreen(id) {
  // Hide all sections
  document.querySelectorAll(".hero, .features, .pricing, .footer, .auth-container, .dashboard").forEach(el => {
    el.classList.add("hidden");
    el.style.display = "";
  });
  
  // Handle landing page
  const landing = document.getElementById("screen-landing");
  if (id === "screen-landing") {
    if (landing) {
      landing.style.display = "";
      document.querySelector(".features").style.display = "";
      document.querySelector(".pricing").style.display = "";
      document.querySelector(".footer").style.display = "";
    }
    return;
  }
  
  // Show auth or dashboard
  const target = document.getElementById(id);
  if (target) {
    target.style.display = "";
    target.classList.remove("hidden");
  }
}

// Tab Navigation (Dashboard)
function switchTab(tabId) {
  currentTab = tabId;
  
  // Update tab buttons
  document.querySelectorAll(".dash-tab").forEach(tab => {
    tab.classList.remove("active");
    if (tab.dataset.tab === tabId) {
      tab.classList.add("active");
    }
  });
  
  // Update tab content
  document.querySelectorAll(".dash-tab-content").forEach(content => {
    content.classList.remove("active");
  });
  
  const tabContent = document.getElementById(`tab-${tabId}`);
  if (tabContent) {
    tabContent.classList.add("active");
  }
}

// Toast Notifications
function toast(message, type = "success") {
  const container = document.getElementById("toastContainer");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  
  const icons = { success: "✓", error: "✕", warning: "⚠" };
  el.innerHTML = `<span>${icons[type] || ""}</span> ${message}`;
  
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// API Helper
async function api(path, method = "POST", body = null, auth = false) {
  const headers = { "Content-Type": "application/json" };
  if (auth && authToken) headers["Authorization"] = "Bearer " + authToken;
  
  const res = await fetch(API + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null
  });
  
  if (res.status === 401 && auth) {
    localStorage.removeItem("ahad_token");
    localStorage.removeItem("ahad_auth_token");
    localStorage.removeItem("ahad_user");
    localStorage.removeItem("ahad_auth_user");
    toast("Session expired. Please sign in again.", "error");
    setTimeout(() => window.location.reload(), 1500);
    throw new Error("Session expired.");
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "Something went wrong");
  return data;
}

// Loading State
function setLoading(btn, loading) {
  if (!btn) return;
  btn.classList.toggle("loading", loading);
  btn.disabled = loading;
}

// Password Strength
function checkStrength(password, fillEl, labelEl) {
  let score = 0;
  if (password.length >= 6) score++;
  if (password.length >= 10) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  
  let pct = (score / 5) * 100;
  let color = "#ef4444", label = "Weak";
  if (score >= 4) { color = "#10b981"; label = "Strong"; }
  else if (score >= 2) { color = "#f59e0b"; label = "Good"; }
  
  if (fillEl) {
    fillEl.style.width = pct + "%";
    fillEl.style.background = color;
  }
  if (labelEl) labelEl.textContent = password ? label : "";
}

// OTP Setup
function setupOtpBoxes(containerId, onComplete) {
  const boxes = document.querySelectorAll(`#${containerId} input`);
  boxes.forEach((box, i) => {
    box.addEventListener("input", () => {
      box.value = box.value.replace(/[^0-9]/g, "");
      if (box.value && i < boxes.length - 1) boxes[i + 1].focus();
      if (getOtpValue(containerId).length === 6) onComplete();
    });
    box.addEventListener("keydown", e => {
      if (e.key === "Backspace" && !box.value && i > 0) boxes[i - 1].focus();
    });
    box.addEventListener("paste", e => {
      e.preventDefault();
      const pasted = (e.clipboardData.getData("text") || "").replace(/[^0-9]/g, "").slice(0, 6);
      pasted.split("").forEach((ch, idx) => { if (boxes[idx]) boxes[idx].value = ch; });
      if (pasted.length === 6) { boxes[5].focus(); onComplete(); }
    });
  });
}

function getOtpValue(containerId) {
  return Array.from(document.querySelectorAll(`#${containerId} input`)).map(i => i.value).join("");
}

function clearOtpBoxes(containerId) {
  document.querySelectorAll(`#${containerId} input`).forEach(i => i.value = "");
}

function startResendTimer(seconds = 45) {
  const timerEl = document.getElementById("resendTimer");
  const linkEl = document.getElementById("resendLink");
  if (!timerEl || !linkEl) return;
  
  linkEl.classList.add("disabled");
  clearInterval(resendTimerInterval);
  let remaining = seconds;
  resendTimerInterval = setInterval(() => {
    remaining--;
    const m = String(Math.floor(remaining / 60)).padStart(2, "0");
    const s = String(remaining % 60).padStart(2, "0");
    timerEl.textContent = `Resend in ${m}:${s}`;
    if (remaining <= 0) {
      clearInterval(resendTimerInterval);
      timerEl.textContent = "";
      linkEl.classList.remove("disabled");
    }
  }, 1000);
}

// ==================== SIGN UP ====================
document.getElementById("formSignup").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = document.getElementById("btnSignup");
  const username = document.getElementById("su_username").value.trim();
  const email = document.getElementById("su_email").value.trim();
  const password = document.getElementById("su_password").value;
  
  if (username.length < 3) {
    toast("Username must be at least 3 characters", "error");
    return;
  }
  
  setLoading(btn, true);
  try {
    await api("/signup", "POST", { username, email, password });
    signupUsername = username;
    localStorage.setItem('ahad_signup_username', username);
    clearOtpBoxes("otpBoxesSignup");
    document.getElementById("otpEmailNote").textContent = `Code sent to ${email}`;
    showScreen("screen-otp");
    startResendTimer(45);
    toast("Verification code sent! Check your email.", "success");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setLoading(btn, false);
  }
});

// ==================== OTP VERIFY (DIRECT TO DASHBOARD) ====================
setupOtpBoxes("otpBoxesSignup", () => document.getElementById("btnVerify").click());
setupOtpBoxes("otpBoxesForgot", () => document.getElementById("btnForgot2").click());

document.getElementById("btnVerify").addEventListener("click", async () => {
  const btn = document.getElementById("btnVerify");
  const otp = getOtpValue("otpBoxesSignup");
  let username = signupUsername || localStorage.getItem('ahad_signup_username');
  
  if (!username) {
    toast("Username not found. Please sign up again.", "error");
    showScreen("screen-signup");
    return;
  }
  
  if (otp.length !== 6) { toast("Enter the 6-digit code", "error"); return; }
  
  setLoading(btn, true);
  try {
    const data = await api("/verify", "POST", { username, otp });
    
    // ✅ VERIFY হলে সরাসরি DASHBOARD এ যাবে!
    authToken = data.token;
    localStorage.setItem("ahad_token", authToken);
    localStorage.removeItem('ahad_signup_username');
    
    toast("Email verified! Welcome! 🎉", "success");
    
    // Dashboard load করো
    await loadDashboard();
    showScreen("screen-dashboard");
    
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById("resendLink").addEventListener("click", async () => {
  const username = signupUsername || localStorage.getItem('ahad_signup_username');
  if (!username) {
    toast("Username not found. Please sign up again.", "error");
    showScreen("screen-signup");
    return;
  }
  
  try {
    await api("/resend-otp", "POST", { username });
    toast("New code sent!", "success");
    startResendTimer(45);
  } catch (err) {
    toast(err.message, "error");
  }
});

// ==================== SIGN IN ====================
document.getElementById("formSignin").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = document.getElementById("btnSignin");
  const username = document.getElementById("si_username").value.trim();
  const password = document.getElementById("si_password").value;
  
  setLoading(btn, true);
  try {
    const data = await api("/login", "POST", { username, password });
    authToken = data.token;
    localStorage.setItem("ahad_token", authToken);
    toast("Welcome back!", "success");
    await loadDashboard();
    showScreen("screen-dashboard");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setLoading(btn, false);
  }
});

// ==================== FORGOT PASSWORD ====================
let forgotEmail = "";
let forgotOtp = "";

document.getElementById("formForgot1").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = document.getElementById("btnForgot1");
  forgotEmail = document.getElementById("fp_email").value.trim();
  setLoading(btn, true);
  try {
    await api("/forgot-password", "POST", { email: forgotEmail });
    toast("If this email exists, a code has been sent", "success");
    clearOtpBoxes("otpBoxesForgot");
    showScreen("screen-forgot2");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById("btnForgot2").addEventListener("click", async () => {
  const btn = document.getElementById("btnForgot2");
  forgotOtp = getOtpValue("otpBoxesForgot");
  if (forgotOtp.length !== 6) { toast("Enter the 6-digit code", "error"); return; }
  setLoading(btn, true);
  try {
    await api("/verify-reset-otp", "POST", { email: forgotEmail, otp: forgotOtp });
    toast("Code verified!", "success");
    showScreen("screen-forgot3");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById("formForgot3").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = document.getElementById("btnForgot3");
  const p1 = document.getElementById("fp_newpass").value;
  const p2 = document.getElementById("fp_confirmpass").value;
  if (p1 !== p2) {
    toast("Passwords do not match", "error");
    return;
  }
  setLoading(btn, true);
  try {
    await api("/reset-password", "POST", { email: forgotEmail, otp: forgotOtp, new_password: p1 });
    showScreen("screen-forgot-success");
    let count = 3;
    const countdownEl = document.getElementById("successCountdown");
    const iv = setInterval(() => {
      count--;
      countdownEl.textContent = count;
      if (count <= 0) {
        clearInterval(iv);
        showScreen("screen-signin");
      }
    }, 1000);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setLoading(btn, false);
  }
});

// ==================== DASHBOARD LOADER ====================
async function loadDashboard() {
  try {
    // Load profile
    const profile = await api("/profile", "GET", null, true);
    
    // Update profile tab
    document.getElementById("dashUsername").textContent = profile.username;
    document.getElementById("dashUsername2").textContent = profile.username;
    document.getElementById("profileUsername").value = profile.username;
    document.getElementById("profileEmail").value = profile.email;
    document.getElementById("profilePhone").value = profile.phone || "";
    document.getElementById("profileCode").value = profile.custom_code || "";
    
    // Calculate days
    if (profile.created_at) {
      const created = new Date(profile.created_at);
      const now = new Date();
      const days = Math.floor((now - created) / (1000 * 60 * 60 * 24));
      document.getElementById("statDays").textContent = days || 1;
    }
    
    // Load vault
    await loadVault();
    
    // Load notes
    await loadNotes();
    
    // Load bookmarks
    await loadBookmarks();
    
    // Load stats
    const vaultData = await api("/vault", "GET", null, true);
    document.getElementById("statVault").textContent = (vaultData.entries || []).length;
    
  } catch (err) {
    console.error("Dashboard load error:", err);
    toast("Session expired. Please login again.", "error");
    authToken = null;
    localStorage.removeItem("ahad_token");
    showScreen("screen-signin");
  }
}

// ==================== VAULT FUNCTIONS ====================
function showVaultForm() {
  document.getElementById("vaultForm").classList.remove("hidden");
  document.getElementById("btnAddVault").textContent = "➖ Hide Form";
  document.getElementById("btnAddVault").onclick = hideVaultForm;
}

function hideVaultForm() {
  document.getElementById("vaultForm").classList.add("hidden");
  document.getElementById("btnAddVault").textContent = "➕ Add New";
  document.getElementById("btnAddVault").onclick = showVaultForm;
  // Clear form
  document.getElementById("vaultLabel").value = "";
  document.getElementById("vaultValue").value = "";
}

async function saveVault() {
  const type = document.getElementById("vaultType").value;
  const label = document.getElementById("vaultLabel").value.trim();
  const value = document.getElementById("vaultValue").value.trim();
  
  if (!label || !value) {
    toast("Label and Value are required!", "error");
    return;
  }
  
  try {
    await api("/vault/add", "POST", { type, label, value }, true);
    toast("Vault item saved! 🔐", "success");
    hideVaultForm();
    await loadVault();
    await loadStats();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function loadVault() {
  try {
    const data = await api("/vault", "GET", null, true);
    const list = document.getElementById("vaultList");
    
    if (!data.entries || data.entries.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🔐</div>
          <p>Your vault is empty</p>
          <small>Click "Add New" to save your first item</small>
        </div>
      `;
      return;
    }
    
    const icons = {
      phone: "📱", email: "📧", code: "🔑", link: "🔗", 
      note: "📝", password: "🔐", secret_file: "📁", file: "📁"
    };
    
    list.innerHTML = data.entries.map(item => `
      <div class="vault-item" data-id="${item.id}">
        <div class="vault-info">
          <div class="vault-icon">${icons[item.type] || "📄"}</div>
          <div class="vault-details">
            <h4>${escapeHtml(item.label)}</h4>
            <p>${escapeHtml(item.value)}</p>
          </div>
        </div>
        <div class="vault-actions">
          <button class="vault-btn" onclick="copyVault('${item.id}', '${escapeHtml(item.value)}')">📋 Copy</button>
          <button class="vault-btn delete" onclick="deleteVault(${item.id})">🗑️</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error("Load vault error:", err);
  }
}

async function deleteVault(id) {
  if (!confirm("Delete this vault item?")) return;
  try {
    await api("/vault/delete", "POST", { id }, true);
    toast("Vault item deleted!", "success");
    await loadVault();
    await loadStats();
  } catch (err) {
    toast(err.message, "error");
  }
}

function copyVault(id, value) {
  navigator.clipboard.writeText(value);
  toast("Copied to clipboard! 📋", "success");
}

// ==================== NOTES FUNCTIONS ====================
let selectedNoteColor = "#6366f1";

function showNoteForm() {
  document.getElementById("noteForm").classList.remove("hidden");
  document.getElementById("btnAddNote").textContent = "➖ Hide Form";
  document.getElementById("btnAddNote").onclick = hideNoteForm;
}

function hideNoteForm() {
  document.getElementById("noteForm").classList.add("hidden");
  document.getElementById("btnAddNote").textContent = "➕ New Note";
  document.getElementById("btnAddNote").onclick = showNoteForm;
  document.getElementById("noteTitle").value = "";
  document.getElementById("noteContent").value = "";
}

async function saveNote() {
  const title = document.getElementById("noteTitle").value.trim();
  const content = document.getElementById("noteContent").value.trim();
  
  if (!title || !content) {
    toast("Title and Content are required!", "error");
    return;
  }
  
  try {
    await api("/notes", "POST", { title, content, color: selectedNoteColor }, true);
    toast("Note saved! 📝", "success");
    hideNoteForm();
    await loadNotes();
    await loadStats();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function loadNotes() {
  try {
    const data = await api("/notes", "GET", null, true);
    const list = document.getElementById("notesList");
    
    if (!data.notes || data.notes.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">📝</div>
          <p>No notes yet</p>
          <small>Create your first note</small>
        </div>
      `;
      return;
    }
    
    list.innerHTML = data.notes.map(note => `
      <div class="note-card" style="border-top: 4px solid ${note.color || '#6366f1'}">
        <div class="note-header">
          <div class="note-title">${escapeHtml(note.title)}</div>
        </div>
        <div class="note-content">${escapeHtml(note.content.substring(0, 100))}${note.content.length > 100 ? '...' : ''}</div>
        <div class="note-date">${new Date(note.created_at).toLocaleDateString()}</div>
        <div class="note-actions">
          <button class="vault-btn" onclick="deleteNote(${note.id})">🗑️</button>
        </div>
      </div>
    `).join('');
    
    document.getElementById("statNotes").textContent = data.notes.length;
  } catch (err) {
    console.error("Load notes error:", err);
  }
}

async function deleteNote(id) {
  if (!confirm("Delete this note?")) return;
  try {
    await api("/notes", "DELETE", { id }, true);
    toast("Note deleted!", "success");
    await loadNotes();
    await loadStats();
  } catch (err) {
    toast(err.message, "error");
  }
}

// ==================== BOOKMARKS FUNCTIONS ====================
function showBookmarkForm() {
  document.getElementById("bookmarkForm").classList.remove("hidden");
  document.getElementById("btnAddBookmark").textContent = "➖ Hide Form";
  document.getElementById("btnAddBookmark").onclick = hideBookmarkForm;
}

function hideBookmarkForm() {
  document.getElementById("bookmarkForm").classList.add("hidden");
  document.getElementById("btnAddBookmark").textContent = "➕ Add Bookmark";
  document.getElementById("btnAddBookmark").onclick = showBookmarkForm;
  document.getElementById("bookmarkTitle").value = "";
  document.getElementById("bookmarkUrl").value = "";
  document.getElementById("bookmarkDesc").value = "";
}

async function saveBookmark() {
  const title = document.getElementById("bookmarkTitle").value.trim();
  const url = document.getElementById("bookmarkUrl").value.trim();
  const description = document.getElementById("bookmarkDesc").value.trim();
  
  if (!title || !url) {
    toast("Title and URL are required!", "error");
    return;
  }
  
  try {
    await api("/bookmarks", "POST", { title, url, description }, true);
    toast("Bookmark saved! 🔖", "success");
    hideBookmarkForm();
    await loadBookmarks();
    await loadStats();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function loadBookmarks() {
  try {
    const data = await api("/bookmarks", "GET", null, true);
    const list = document.getElementById("bookmarksList");
    
    if (!data.bookmarks || data.bookmarks.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🔖</div>
          <p>No bookmarks yet</p>
          <small>Save your favorite links</small>
        </div>
      `;
      return;
    }
    
    list.innerHTML = data.bookmarks.map(bm => `
      <div class="bookmark-item">
        <div class="bookmark-info">
          <div class="bookmark-icon">🌐</div>
          <div class="bookmark-details">
            <h4>${escapeHtml(bm.title)}</h4>
            <a href="${escapeHtml(bm.url)}" target="_blank">${escapeHtml(bm.url)}</a>
            ${bm.description ? `<p>${escapeHtml(bm.description)}</p>` : ''}
          </div>
        </div>
        <div class="vault-actions">
          <button class="vault-btn" onclick="window.open('${escapeHtml(bm.url)}', '_blank')">🔗 Open</button>
          <button class="vault-btn delete" onclick="deleteBookmark(${bm.id})">🗑️</button>
        </div>
      </div>
    `).join('');
    
    document.getElementById("statBookmarks").textContent = data.bookmarks.length;
  } catch (err) {
    console.error("Load bookmarks error:", err);
  }
}

async function deleteBookmark(id) {
  if (!confirm("Delete this bookmark?")) return;
  try {
    await api("/bookmarks", "DELETE", { id }, true);
    toast("Bookmark deleted!", "success");
    await loadBookmarks();
    await loadStats();
  } catch (err) {
    toast(err.message, "error");
  }
}

// ==================== PROFILE FUNCTIONS ====================
async function saveProfile() {
  const phone = document.getElementById("profilePhone").value.trim();
  const custom_code = document.getElementById("profileCode").value.trim();
  
  try {
    await api("/profile/update", "POST", { phone, custom_code }, true);
    toast("Profile saved! ✅", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function exportData() {
  try {
    const data = await api("/export-data", "GET", null, true);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ahad-co-export-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast("Data exported! 📤", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

// ==================== STATS ====================
async function loadStats() {
  try {
    const data = await api("/stats", "GET", null, true);
    document.getElementById("statVault").textContent = data.vault_entries || 0;
    document.getElementById("statNotes").textContent = data.notes || 0;
    document.getElementById("statBookmarks").textContent = data.bookmarks || 0;
  } catch (err) {
    console.error("Load stats error:", err);
  }
}

// ==================== LOGOUT ====================
document.getElementById("btnLogout").addEventListener("click", async () => {
  try { await api("/logout", "POST", null, true); } catch (e) {}
  authToken = null;
  localStorage.removeItem("ahad_token");
  toast("Logged out", "success");
  showScreen("screen-landing");
});

// ==================== UTILITY ====================
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Color picker
document.querySelectorAll('.color-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.color-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    selectedNoteColor = btn.dataset.color;
  });
});

// Tab click handlers
document.querySelectorAll('.dash-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    switchTab(tab.dataset.tab);
  });
});

// Password strength
document.getElementById("su_password").addEventListener("input", e => {
  checkStrength(e.target.value, document.getElementById("strengthFill"), document.getElementById("strengthLabel"));
});

// ==================== INIT ====================
document.addEventListener("DOMContentLoaded", () => {
  if (authToken) {
    loadDashboard().then(() => showScreen("screen-dashboard")).catch(() => {
      showScreen("screen-landing");
    });
  } else {
    showScreen("screen-landing");
  }
});
