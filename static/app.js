// IAM Copilot — vanilla JS glue. All rendering of catalog/detail/activity
// content is done server-side (Jinja fragments); this file only fetches
// those fragments and swaps them into the DOM, plus drives the copilot chat
// widget's client-side state (message list, loading, retry).

document.addEventListener("DOMContentLoaded", () => {
  // ---------------------------------------------------------------- tabs --
  // Only "Catalog" and "Daily activity log" are tabs now — the copilot lives
  // in its own floating chat panel (see "copilot panel" below), opened from
  // the dragon launcher button rather than a third tab.
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanels = document.querySelectorAll("[data-tab-panel]");

  function switchToTab(tabName) {
    tabButtons.forEach((b) => b.classList.toggle("active", b.dataset.tab === tabName));
    tabPanels.forEach((p) => {
      p.hidden = p.dataset.tabPanel !== tabName;
    });
    if (tabName === "activity") refreshActivity();
  }

  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => switchToTab(btn.dataset.tab));
  });

  // -------------------------------------------------------- copilot panel --
  // Floating chat window, toggled open/closed by the dragon launcher button
  // (and opened by the teaser card's CTA). Independent of the tab bar.
  const copilotPanel = document.getElementById("copilot-panel");
  const copilotLauncher = document.getElementById("copilot-launcher");
  const copilotPanelClose = document.getElementById("copilot-panel-close");

  function isPanelOpen() {
    return copilotPanel && !copilotPanel.hidden;
  }

  function openCopilotPanel() {
    if (!copilotPanel) return;
    hideTeaser();
    copilotPanel.hidden = false;
    document.getElementById("copilot-input")?.focus();
  }

  function closeCopilotPanel() {
    if (copilotPanel) copilotPanel.hidden = true;
  }

  function toggleCopilotPanel() {
    if (isPanelOpen()) {
      closeCopilotPanel();
    } else {
      openCopilotPanel();
    }
  }

  copilotLauncher?.addEventListener("click", toggleCopilotPanel);
  copilotPanelClose?.addEventListener("click", closeCopilotPanel);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && isPanelOpen()) closeCopilotPanel();
  });

  // ------------------------------------------------------------- teaser --
  // A proactive greeting bubble next to the launcher (dismissible, shown
  // once per browser session) — opens straight into the copilot chat panel.
  const copilotTeaser = document.getElementById("copilot-teaser");
  const teaserClose = document.getElementById("copilot-teaser-close");
  const teaserCta = document.getElementById("copilot-teaser-cta");

  function teaserDismissed() {
    try {
      return sessionStorage.getItem("iam-copilot-teaser-dismissed") === "1";
    } catch (e) {
      return false;
    }
  }

  function hideTeaser() {
    if (copilotTeaser) copilotTeaser.hidden = true;
  }

  function dismissTeaser() {
    hideTeaser();
    try {
      sessionStorage.setItem("iam-copilot-teaser-dismissed", "1");
    } catch (e) {
      /* private browsing or storage disabled — fine, just won't persist */
    }
  }

  if (copilotTeaser && !teaserDismissed()) {
    setTimeout(() => {
      if (!isPanelOpen()) copilotTeaser.hidden = false;
    }, 1200);

    teaserClose?.addEventListener("click", (e) => {
      e.stopPropagation();
      dismissTeaser();
    });
    teaserCta?.addEventListener("click", () => {
      dismissTeaser();
      openCopilotPanel();
    });
  }

  // -------------------------------------------------------------- search --
  const searchInput = document.getElementById("search-input");
  const catalogResults = document.getElementById("catalog-results");
  let activeCategory = "";
  let searchLogTimer = null;

  function buildParams(logSearch) {
    const params = new URLSearchParams();
    const q = searchInput.value.trim();
    if (q) params.set("q", q);
    if (activeCategory) params.set("category", activeCategory);
    if (logSearch) params.set("logSearch", "true");
    return params;
  }

  async function fetchCatalog(logSearch) {
    const res = await fetch(`/api/features/fragment?${buildParams(logSearch).toString()}`);
    catalogResults.innerHTML = await res.text();
  }

  function onSearchOrCategoryChange() {
    fetchCatalog(false);

    if (searchLogTimer) clearTimeout(searchLogTimer);
    if (searchInput.value.trim().length > 1) {
      searchLogTimer = setTimeout(async () => {
        await fetchCatalog(true);
        refreshActivity();
      }, 900);
    }
  }

  searchInput.addEventListener("input", onSearchOrCategoryChange);

  // Category chips + feature cards + detail-panel actions are all inside
  // elements that get replaced by fragment swaps, so everything is wired via
  // delegation on document.body rather than re-binding after every fetch.

  document.body.addEventListener("click", async (e) => {
    const chip = e.target.closest(".category-chip");
    if (chip) {
      activeCategory = chip.dataset.category || "";
      onSearchOrCategoryChange();
      return;
    }

    const card = e.target.closest(".feature-card");
    if (card) {
      await openFeature(card.dataset.featureId);
      return;
    }

    if (e.target.closest('[data-action="close-detail"]')) {
      closeDetail();
      return;
    }

    const statusBtn = e.target.closest('[data-action="set-status"]');
    if (statusBtn) {
      await setStatus(statusBtn.dataset.featureId, statusBtn.dataset.status);
      return;
    }

    const exampleBtn = e.target.closest(".example-btn");
    if (exampleBtn) {
      sendChat(exampleBtn.textContent);
      return;
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDetail();
  });

  // ------------------------------------------------------------- detail --
  const detailOverlay = document.getElementById("detail-overlay");
  const detailContent = document.getElementById("detail-panel-content");

  async function openFeature(featureId) {
    const res = await fetch(`/api/features/${featureId}/fragment?logView=true`);
    detailContent.innerHTML = await res.text();
    detailOverlay.hidden = false;
    refreshActivity();
  }

  function closeDetail() {
    detailOverlay.hidden = true;
    detailContent.innerHTML = "";
  }

  async function setStatus(featureId, status) {
    const res = await fetch(`/api/features/${featureId}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    if (res.ok) {
      detailContent.innerHTML = await res.text();
    }
    fetchCatalog(false); // refresh the card's status badge in the grid
    refreshActivity();
  }

  // ------------------------------------------------------------ activity --
  const activityResults = document.getElementById("activity-results");

  async function refreshActivity() {
    const res = await fetch("/api/activity/fragment?limit=200");
    activityResults.innerHTML = await res.text();
  }

  // -------------------------------------------------------------- copilot --
  const copilotMessages = document.getElementById("copilot-messages");
  const copilotForm = document.getElementById("copilot-form");
  const copilotInput = document.getElementById("copilot-input");
  const copilotSend = document.getElementById("copilot-send");
  const copilotErrorBox = document.getElementById("copilot-error");
  const copilotErrorText = document.getElementById("copilot-error-text");
  const copilotRetryBtn = document.getElementById("copilot-retry");

  let messages = [];
  let loading = false;
  let lastFailedTurn = null;

  function renderMessages() {
    if (messages.length === 0 && !loading) {
      copilotMessages.innerHTML = `
        <div class="copilot-examples" id="copilot-examples">
          <p class="examples-label">Try asking:</p>
          <button type="button" class="example-btn">What is the difference between SAML and OIDC?</button>
          <button type="button" class="example-btn">When should I use SCIM vs Okta Workflows for provisioning?</button>
          <button type="button" class="example-btn">Why don't I have access to Salesforce?</button>
          <button type="button" class="example-btn">How does adaptive MFA decide when to challenge me?</button>
        </div>`;
      return;
    }

    const badge = '<img src="/static/img/dragon-badge.png" alt="" class="msg-avatar" width="28" height="28">';
    const items = messages
      .map((m) =>
        m.role === "user"
          ? `<li class="from-user">
              <div class="msg-bubble user">${escapeHtml(m.content)}</div>
            </li>`
          : `<li class="from-model">
              ${badge}
              <div class="msg-bubble model">${escapeHtml(m.content)}</div>
            </li>`
      )
      .join("");
    const thinking = loading
      ? `<li class="from-model">${badge}<div class="msg-bubble thinking">Thinking…</div></li>`
      : "";

    copilotMessages.innerHTML = `<ul class="copilot-message-list">${items}${thinking}</ul>`;
    copilotMessages.scrollTop = copilotMessages.scrollHeight;
  }

  function escapeHtml(s) {
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
  }

  function setLoading(v) {
    loading = v;
    copilotSend.disabled = v || !copilotInput.value.trim();
    renderMessages();
  }

  async function sendTurn(turn) {
    copilotErrorBox.hidden = true;
    setLoading(true);
    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: turn }),
      });
      const data = await res.json();
      if (!res.ok) {
        showError(data.error || `Request failed (${res.status}).`, turn);
      } else {
        messages.push({ role: "model", content: data.reply });
        lastFailedTurn = null;
        refreshActivity();
      }
    } catch {
      showError("Network error — is the dev server still running?", turn);
    } finally {
      setLoading(false);
    }
  }

  function showError(text, turn) {
    copilotErrorText.textContent = text;
    lastFailedTurn = turn;
    copilotRetryBtn.hidden = false;
    copilotErrorBox.hidden = false;
  }

  async function sendChat(text) {
    const trimmed = (text || "").trim();
    if (!trimmed || loading) return;
    messages.push({ role: "user", content: trimmed });
    copilotInput.value = "";
    renderMessages();
    await sendTurn(messages);
  }

  copilotForm.addEventListener("submit", (e) => {
    e.preventDefault();
    sendChat(copilotInput.value);
  });

  copilotInput.addEventListener("input", () => {
    copilotSend.disabled = loading || !copilotInput.value.trim();
  });

  copilotRetryBtn.addEventListener("click", async () => {
    if (!lastFailedTurn || loading) return;
    await sendTurn(lastFailedTurn);
  });

  renderMessages();
});
