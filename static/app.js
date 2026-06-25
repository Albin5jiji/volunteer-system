const state = {
  template: "",
  templateFormat: "ISO",
  quality: null,
  deviceName: "SecuGen Hamster",
  lastClear: false,
  secugenConfig: null,
};

const el = {
  scanButton: document.querySelector("#scanButton"),
  manualButton: document.querySelector("#manualButton"),
  manualBox: document.querySelector("#manualBox"),
  manualTemplate: document.querySelector("#manualTemplate"),
  useManualTemplate: document.querySelector("#useManualTemplate"),
  resultBox: document.querySelector("#resultBox"),
  scanTitle: document.querySelector("#scanTitle"),
  scanSubtitle: document.querySelector("#scanSubtitle"),
  scanStage: document.querySelector("#scanStage"),
  threshold: document.querySelector("#threshold"),
  registerForm: document.querySelector("#registerForm"),
  registerButton: document.querySelector("#registerButton"),
  registerState: document.querySelector("#registerState"),
  activityList: document.querySelector("#activityList"),
  donorList: document.querySelector("#donorList"),
  searchInput: document.querySelector("#searchInput"),
  searchButton: document.querySelector("#searchButton"),
  refreshButton: document.querySelector("#refreshButton"),
  stats: document.querySelector("#stats"),
  deviceState: document.querySelector("#deviceState"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      "X-App-Origin": window.location.origin,
      ...(options.headers || {}),
    },
    ...options,
  });
  const body = await response.json();
  if (!response.ok) {
    const error = new Error(body.message || body.error || "Request failed");
    error.body = body;
    error.status = response.status;
    throw error;
  }
  return body;
}

function secugenErrorMessage(code) {
  const messages = {
    54: "Fingerprint capture timed out. Place your finger on the scanner before clicking Scan.",
    100: "SecuGen rejected a stored fingerprint template. Re-scan and re-register affected donors if this continues.",
    10002: `SecuGen license does not cover ${window.location.origin}. Open this app with the same host name used by the working SecuGen demo, then refresh and scan again.`,
    10003: "SecuGen license expired. Request a new license key from SecuGen.",
    10004: "SecuGen did not receive the browser origin. Refresh the page and try again.",
  };
  return messages[Number(code)] || messages[String(code)] || `SecuGen error ${code}. Check that SgiBioSrv is running and the scanner is connected.`;
}

async function loadSecugenConfig() {
  if (state.secugenConfig) {
    return state.secugenConfig;
  }
  state.secugenConfig = await api("/api/secugen-config");
  return state.secugenConfig;
}

function setResult(type, title, message, details = "") {
  el.resultBox.className = `result ${type || ""}`.trim();
  el.resultBox.innerHTML = `
    <h3>${escapeHtml(title)}</h3>
    <p>${escapeHtml(message)}</p>
    ${details ? `<span class="meta">${details}</span>` : ""}
  `;
}

function setClearReady(isReady) {
  state.lastClear = isReady;
  el.registerButton.disabled = !isReady || !state.template;
  el.registerState.textContent = isReady
    ? "Fingerprint clear, registration enabled"
    : "Waiting for a clear fingerprint";
}

function normalizeTemplate(template) {
  return String(template || "").replace(/\s+/g, "");
}

function parseCaptureResponse(payload) {
  const template =
    payload.TemplateBase64 ||
    payload.ISOTemplateBase64 ||
    payload.ANSITemplateBase64 ||
    payload.Template ||
    payload.template ||
    payload.templateBase64 ||
    payload.FingerprintTemplate ||
    "";

  return {
    template: String(template || "").trim(),
    quality: Number(payload.ImageQuality || payload.Quality || payload.quality || 0) || null,
    deviceName: payload.DeviceName || payload.deviceName || "SecuGen Hamster",
    templateFormat: payload.TemplateFormat || payload.templateFormat || "ISO",
  };
}

async function captureFromServer() {
  const config = await loadSecugenConfig();
  const data = await api("/api/capture", {
    method: "POST",
    body: JSON.stringify({
      timeout: config.timeout || 15000,
      quality: config.quality || 50,
      templateFormat: "ISO",
    }),
  });
  const parsed = parseCaptureResponse(data);
  if (!parsed.template) {
    throw new Error(data.message || "No template returned");
  }
  return parsed;
}

async function captureFromSecugen() {
  return captureFromServer();
}

function parseMatchScore(payload) {
  const raw =
    payload.MatchingScore ??
    payload.matchingScore ??
    payload.matchScore ??
    payload.Score ??
    payload.score;
  if (raw === undefined || raw === null || raw === "") {
    return null;
  }
  const score = Number(raw);
  return Number.isFinite(score) ? score : null;
}

async function identify(templateData) {
  state.template = templateData.template;
  state.quality = templateData.quality;
  state.deviceName = templateData.deviceName;
  state.templateFormat = String(templateData.templateFormat || "ISO").toUpperCase();

  el.scanTitle.textContent = "Checking database";
  el.scanSubtitle.textContent = "Comparing fingerprints via SecuGen";
  el.deviceState.textContent = "Checking";
  setClearReady(false);

  try {
    const result = await api("/api/identify", {
      method: "POST",
      body: JSON.stringify({
        template: state.template,
        templateFormat: state.templateFormat,
        quality: state.quality,
        deviceName: state.deviceName,
        threshold: Number(el.threshold.value || 80),
      }),
    });

    if (result.matched) {
      const donor = result.donor || {};
      setResult(
        "blocked",
        "Duplicate found",
        `${donor.full_name || "This donor"} is already registered.`,
        `Code: ${donor.donor_code || "-"} | Score: ${result.score ?? "-"} | Status: ${result.matcherStatus}`
      );
      el.scanTitle.textContent = "Do not accept";
      el.scanSubtitle.textContent = "Existing donor matched";
      el.deviceState.textContent = "Duplicate";
      setClearReady(false);
    } else {
      if (result.needsReview) {
        setResult(
          "warning",
          "Manual review needed",
          result.message || "Fingerprint result is not confident enough to clear.",
          `Best score: ${result.score ?? "none"} | Status: ${result.matcherStatus}`
        );
        el.scanTitle.textContent = "Review";
        el.scanSubtitle.textContent = "Do not register until reviewed";
        el.deviceState.textContent = "Review";
        setClearReady(false);
      } else {
        setResult(
          "clear",
          "No previous record found",
          "Candidate can be registered for this donation.",
          `Best score: ${result.score ?? "none"} | Status: ${result.matcherStatus}`
        );
        el.scanTitle.textContent = "Clear";
        el.scanSubtitle.textContent = "Registration enabled";
        el.deviceState.textContent = "Clear";
        setClearReady(true);
      }
    }
  } catch (error) {
    const body = error.body || {};
    setResult(
      body.needsReview ? "warning" : "blocked",
      body.needsReview ? "Manual review needed" : "Check failed",
      body.message || error.message,
      body.matcherStatus || ""
    );
    el.scanTitle.textContent = "Review";
    el.scanSubtitle.textContent = "Cannot safely clear this candidate";
    el.deviceState.textContent = "Review";
    setClearReady(false);
  } finally {
    await refreshAll();
  }
}

async function scanAndIdentify() {
  el.scanButton.disabled = true;
  el.scanTitle.textContent = "Waiting for finger";
  el.scanSubtitle.textContent = "Reading from SecuGen WebAPI";
  el.deviceState.textContent = "Scanning";
  setResult("", "Scanning", "Place your finger flat on the scanner now and keep it still until capture completes.");

  try {
    const captured = await captureFromSecugen();
    await identify(captured);
  } catch (error) {
    setResult(
      "warning",
      "Scanner did not capture",
      error.message || "Start the SecuGen WebAPI service, then scan again.",
      String(error.message || error)
    );
    el.scanTitle.textContent = "Scanner offline";
    el.scanSubtitle.textContent = "Use paste mode for testing";
    el.deviceState.textContent = "Offline";
  } finally {
    el.scanButton.disabled = false;
  }
}

async function registerDonor(event) {
  event.preventDefault();
  if (!state.lastClear || !state.template) {
    setResult("warning", "Scan required", "Register only after a clear fingerprint check.");
    return;
  }

  const form = new FormData(el.registerForm);
  const payload = Object.fromEntries(form.entries());
  payload.template = state.template;
  payload.templateFormat = state.templateFormat;
  payload.quality = state.quality;
  payload.deviceName = state.deviceName;
  payload.threshold = Number(el.threshold.value || 80);

  el.registerButton.disabled = true;
  try {
    const result = await api("/api/register", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setResult(
      "clear",
      "Donor registered",
      `${result.donor.full_name} saved as ${result.donor.donor_code}.`
    );
    el.registerForm.reset();
    state.template = "";
    setClearReady(false);
    await refreshAll();
  } catch (error) {
    const body = error.body || {};
    if (body.donor) {
      setResult(
        "blocked",
        "Duplicate found",
        `${body.donor.full_name} is already registered.`,
        `Code: ${body.donor.donor_code || "-"} | Score: ${body.score ?? "-"}`
      );
    } else {
      setResult(
        "warning",
        "Registration stopped",
        body.message || error.message,
        body.matcherStatus || ""
      );
    }
  } finally {
    el.registerButton.disabled = !state.lastClear || !state.template;
  }
}

function renderStats(stats) {
  el.stats.innerHTML = `
    <span>Donors <strong>${stats.donor_count || 0}</strong></span>
    <span>Fingerprints <strong>${stats.fingerprint_count || 0}</strong></span>
    <span>Open alerts <strong>${stats.open_alerts || 0}</strong></span>
  `;
}

function renderActivity(data) {
  const alerts = data.alerts || [];
  const checks = data.checks || [];
  const items = [
    ...alerts.slice(0, 5).map((alert) => ({
      type: alert.severity,
      title: alert.message,
      meta: `${alert.full_name || "No donor"} | ${alert.created_at}`,
    })),
    ...checks.slice(0, 8).map((check) => ({
      type: check.outcome === "duplicate_alert" ? "danger" : check.outcome === "matcher_unavailable" ? "warning" : "",
      title: check.outcome.replaceAll("_", " "),
      meta: `${check.full_name || "Candidate"} | score ${check.match_score ?? "-"} | ${check.created_at}`,
    })),
  ].slice(0, 10);

  el.activityList.innerHTML = items.length
    ? items.map((item) => `
        <div class="activity-item ${escapeHtml(item.type)}">
          <strong>${escapeHtml(item.title)}</strong>
          <span class="meta">${escapeHtml(item.meta)}</span>
        </div>
      `).join("")
    : `<div class="activity-item"><strong>No activity yet</strong><span class="meta">Scans will appear here</span></div>`;
}

function renderDonors(donors) {
  el.donorList.innerHTML = donors.length
    ? donors.map((donor) => `
      <div class="donor-item">
        <div class="donor-main">
          <div>
            <strong>${escapeHtml(donor.full_name)}</strong>
            <span class="meta">${escapeHtml(donor.donor_code)} | ${escapeHtml(donor.phone || "No phone")} | ${escapeHtml(donor.blood_group || "Blood group unknown")}</span>
            <span class="meta">Visits: ${donor.visit_count || 0} | Last: ${escapeHtml(donor.last_visit || "No visit")}</span>
          </div>
          <button class="danger-button" type="button" data-delete-donor="${escapeHtml(donor.id)}" data-donor-name="${escapeHtml(donor.full_name)}">Delete</button>
        </div>
      </div>
    `).join("")
    : `<div class="donor-item"><strong>No donors found</strong><span class="meta">Register clear candidates to build the database</span></div>`;
}

async function deleteDonor(donorId, donorName) {
  const confirmed = window.confirm(
    `Delete ${donorName || "this donor"} and their stored fingerprint? This cannot be undone.`
  );
  if (!confirmed) {
    return;
  }
  await api(`/api/donors/${encodeURIComponent(donorId)}`, { method: "DELETE" });
  setResult("warning", "Donor deleted", `${donorName || "Donor"} was removed from the database.`);
  await refreshAll();
}

async function refreshAll() {
  const [stats, recent, donors] = await Promise.all([
    api("/api/stats"),
    api("/api/recent"),
    api(`/api/donors?search=${encodeURIComponent(el.searchInput.value.trim())}`),
  ]);
  renderStats(stats.stats || {});
  renderActivity(recent);
  renderDonors(donors.donors || []);
}

el.scanButton.addEventListener("click", scanAndIdentify);
el.manualButton.addEventListener("click", () => {
  el.manualBox.hidden = !el.manualBox.hidden;
});
el.useManualTemplate.addEventListener("click", async () => {
  const template = el.manualTemplate.value.trim();
  if (!template) {
    setResult("warning", "Template required", "Paste a fingerprint template first.");
    return;
  }
  await identify({
    template,
    quality: null,
    deviceName: "Manual test",
    templateFormat: "ISO",
  });
});
el.registerForm.addEventListener("submit", registerDonor);
el.searchButton.addEventListener("click", refreshAll);
el.searchInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    refreshAll();
  }
});
el.refreshButton.addEventListener("click", refreshAll);
el.donorList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-delete-donor]");
  if (!button) {
    return;
  }
  button.disabled = true;
  try {
    await deleteDonor(button.dataset.deleteDonor, button.dataset.donorName);
  } catch (error) {
    button.disabled = false;
    setResult("warning", "Delete failed", error.message || "Could not delete donor.");
  }
});

refreshAll().catch((error) => {
  setResult("warning", "Server not ready", error.message);
});
