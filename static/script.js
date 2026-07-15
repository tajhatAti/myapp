const API = "";
let signupUsername = "";
let authToken = localStorage.getItem("ahad_token") || null;
let resendTimerInterval = null;

function showScreen(id) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById(id).classList.add("active");
}

function toast(message, type = "success") {
  const container = document.getElementById("toastContainer");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

async function api(path, method = "POST", body = null, auth = false) {
  const headers = { "Content-Type": "application/json" };
  if (auth && authToken) headers["Authorization"] = "Bearer " + authToken;
  const res = await fetch(API + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null
  });
  if (res.status === 401 && auth) {
    localStorage.removeItem("ahad_auth_token");
    localStorage.removeItem("ahad_auth_user");
    showToast("Session expired. Please sign in again.");
    setTimeout(() => window.location.reload(), 1500);
    throw new Error("Session expired.");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "Something went wrong. Please try again.");
  return data;
}

function setLoading(btn, loading) {
  btn.classList.toggle("loading", loading);
  btn.disabled = loading;
}

function shakeField(inputEl) {
  const field = inputEl.closest(".field");
  field.classList.add("shake");
  setTimeout(() => field.classList.remove("shake"), 300);
}

document.querySelectorAll(".eye").forEach(eye => {
  eye.addEventListener("click", () => {
    const input = document.getElementById(eye.dataset.target);
    input.type = input.type === "password" ? "text" : "password";
  });
});

function checkStrength(password, fillEl, labelEl) {
  let score = 0;
  if (password.length >= 6) score++;
  if (password.length >= 10) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  let pct = (score / 5) * 100;
  let color = "#FF6B6B", label = "Weak";
  if (score >= 4) { color = "#3ADB8F"; label = "Strong"; }
  else if (score >= 2) { color = "#FFB347"; label = "Good"; }

  fillEl.style.width = pct + "%";
  fillEl.style.background = color;
  if (labelEl) labelEl.textContent = password ? label : "";
}

document.getElementById("su_password").addEventListener("input", e => {
  checkStrength(e.target.value, document.getElementById("strengthFill"), document.getElementById("strengthLabel"));
});
document.getElementById("fp_newpass").addEventListener("input", e => {
  checkStrength(e.target.value, document.getElementById("strengthFill2"), null);
});

// ---------- OTP boxes: auto-advance + auto-submit + paste support ----------
function setupOtpBoxes(containerId, onComplete) {
  const boxes = document.querySelectorAll(`#${containerId} input`);
  boxes.forEach((box, i) => {
    box.addEventListener("input", () => {
      box.value = box.value.replace(/[^0-9]/g, "");
      if (box.value && i < boxes.length - 1) boxes[i + 1].focus();
      const val = getOtpValue(containerId);
      if (val.length === 6) onComplete();
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

// Store username in localStorage for persistence
function setSignupUsername(username) {
  signupUsername = username;
  localStorage.setItem('ahad_signup_username', username);
  console.log('Signup username stored:', username);
}

function getStoredSignupUsername() {
  return localStorage.getItem('ahad_signup_username') || '';
}

setupOtpBoxes("otpBoxesSignup", () => document.getElementById("btnVerify").click());
setupOtpBoxes("otpBoxesForgot", () => document.getElementById("btnForgot2").click());

function startResendTimer(seconds = 45) {
  const timerEl = document.getElementById("resendTimer");
  const linkEl = document.getElementById("resendLink");
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

// ---------- SIGN UP ----------
document.getElementById("formSignup").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = document.getElementById("btnSignup");
  const username = document.getElementById("su_username").value.trim();
  const email = document.getElementById("su_email").value.trim();
  const password = document.getElementById("su_password").value;

  setLoading(btn, true);
  try {
    await api("/signup", "POST", { username, email, password });
    setSignupUsername(username); // Store for persistence
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

document.getElementById("btnVerify").addEventListener("click", async () => {
  const btn = document.getElementById("btnVerify");
  const otp = getOtpValue("otpBoxesSignup");
  
  // Use stored username or fall back to input
  let username = signupUsername || getStoredSignupUsername();
  
  if (!username) {
    toast("Username not found. Please sign up again.", "error");
    showScreen("screen-signup");
    return;
  }
  
  if (otp.length !== 6) { toast("Enter the 6-digit code", "error"); return; }

  setLoading(btn, true);
  try {
    const result = await api("/verify", "POST", { username: username, otp });
    toast("Email verified!", "success");
    localStorage.removeItem('ahad_signup_username'); // Clean up
    setTimeout(() => showScreen("screen-signin"), 1000);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setLoading(btn, false);
  }
});

document.getElementById("resendLink").addEventListener("click", async () => {
  const username = signupUsername || getStoredSignupUsername();
  if (!username) {
    toast("Username not found. Please sign up again.", "error");
    showScreen("screen-signup");
    return;
  }
  
  try {
    await api("/resend-otp", "POST", { username: username });
    toast("New code sent!", "success");
    startResendTimer(45);
  } catch (err) {
    toast(err.message, "error");
  }
});

// ---------- SIGN IN ----------
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

// ---------- FORGOT PASSWORD ----------
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
    shakeField(document.getElementById("fp_confirmpass"));
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
      countdownEl.textContent = `Redirecting in ${count}...`;
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

// ---------- DASHBOARD ----------
async function loadDashboard() {
  try {
    const data = await api("/profile", "GET", null, true);
    document.getElementById("dashUsername").textContent = data.username;
    document.getElementById("dashEmail").value = data.email;
    document.getElementById("dashPhone").value = data.phone || "";
    document.getElementById("dashCode").value = data.custom_code || "";
    document.getElementById("dashMemberSince").textContent =
      "Member since " + new Date(data.created_at).toLocaleDateString();
    renderLinks(data.links || []);
  } catch (err) {
    toast(err.message, "error");
    authToken = null;
    localStorage.removeItem("ahad_token");
    showScreen("screen-signin");
  }
}

document.querySelectorAll(".tab").forEach((tab, idx) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tabIndicator").style.transform = `translateX(${idx * 100}%)`;
    document.querySelectorAll(".dash-card").forEach(c => c.classList.add("hidden"));
    document.getElementById(`tab-${tab.dataset.tab}`).classList.remove("hidden");
  });
});

["dashPhone", "dashCode"].forEach(id => {
  document.getElementById(id).addEventListener("input", () => {
    document.getElementById("btnSaveProfile").classList.add("show");
  });
});

document.getElementById("btnSaveProfile").addEventListener("click", async () => {
  const btn = document.getElementById("btnSaveProfile");
  const phone = document.getElementById("dashPhone").value.trim();
  const custom_code = document.getElementById("dashCode").value.trim();
  const links = Array.from(document.querySelectorAll(".link-row")).map(row => ({
    label: row.querySelector(".link-label").value.trim(),
    url: row.querySelector(".link-url").value.trim()
  })).filter(l => l.label && l.url);

  try {
    await api("/profile/update", "POST", { phone, custom_code, links }, true);
    toast("Profile saved!", "success");
    btn.classList.remove("show");
  } catch (err) {
    toast(err.message, "error");
  }
});

function renderLinks(links) {
  const list = document.getElementById("linksList");
  list.innerHTML = "";
  links.forEach(link => addLinkRow(link.label, link.url));
}
function addLinkRow(label = "", url = "") {
  const row = document.createElement("div");
  row.className = "link-row";
  row.innerHTML = `
    <input class="link-label" placeholder="Label" value="${label}">
    <input class="link-url" placeholder="https://..." value="${url}">
    <button class="link-remove">✕</button>
  `;
  row.querySelector(".link-remove").addEventListener("click", () => {
    row.remove();
    document.getElementById("btnSaveProfile").classList.add("show");
  });
  row.querySelectorAll("input").forEach(inp =>
    inp.addEventListener("input", () => document.getElementById("btnSaveProfile").classList.add("show"))
  );
  document.getElementById("linksList").appendChild(row);
}
document.getElementById("btnAddLink").addEventListener("click", () => addLinkRow());

document.getElementById("btnLogout").addEventListener("click", () => {
  document.getElementById("logoutModal").classList.remove("hidden");
});
document.getElementById("cancelLogout").addEventListener("click", () => {
  document.getElementById("logoutModal").classList.add("hidden");
});
document.getElementById("confirmLogout").addEventListener("click", async () => {
  try { await api("/logout", "POST", null, true); } catch (e) {}
  authToken = null;
  localStorage.removeItem("ahad_token");
  document.getElementById("logoutModal").classList.add("hidden");
  showScreen("screen-signin");
  toast("Logged out", "success");
});

// Auto login if a session token already exists
if (authToken) {
  loadDashboard().then(() => showScreen("screen-dashboard")).catch(() => {});
        }
