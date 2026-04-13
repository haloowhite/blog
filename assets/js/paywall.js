/**
 * Paywall client-side logic
 * Handles premium content gating, Stripe checkout, and access restoration.
 *
 * Note: innerHTML is used intentionally to render trusted HTML from our own
 * first-party API (pay.haloowhite.com). The API returns pre-sanitized content.
 */
(function () {
  'use strict';

  const API_URL = 'https://pay.haloowhite.com';
  const TOKEN_KEY = 'paywall_token';

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function isTokenValid(token) {
    try {
      const payload = JSON.parse(
        atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))
      );
      return payload.exp > Date.now() / 1000;
    } catch {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Premium content fetching
  // ---------------------------------------------------------------------------

  async function fetchPremiumContent(slug, token) {
    try {
      const resp = await fetch(`${API_URL}/api/content/${slug}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!resp.ok) {
        if (resp.status === 403) {
          localStorage.removeItem(TOKEN_KEY);
          return; // Show paywall
        }
        throw new Error('Failed to load content');
      }

      const data = await resp.json();

      // Hide paywall, show premium content
      document.querySelector('.paywall-gate').style.display = 'none';
      const container = document.querySelector('.premium-content');
      // Trusted HTML from our own first-party API (pay.haloowhite.com)
      container.innerHTML = data.html;
      container.style.display = 'block';
    } catch (e) {
      console.error('Paywall error:', e);
    }
  }

  // ---------------------------------------------------------------------------
  // Modal helpers
  // ---------------------------------------------------------------------------

  function openModal() {
    const modal = document.querySelector('.paywall-modal');
    if (modal) modal.style.display = 'flex';
  }

  function closeModal() {
    const modal = document.querySelector('.paywall-modal');
    if (!modal) return;
    modal.style.display = 'none';

    // Reset state
    const errorEl = modal.querySelector('.paywall-modal-error');
    if (errorEl) {
      errorEl.style.display = 'none';
      errorEl.textContent = '';
    }
    const emailStep = modal.querySelector('.paywall-step-email');
    const codeStep = modal.querySelector('.paywall-step-code');
    if (emailStep) emailStep.style.display = 'flex';
    if (codeStep) codeStep.style.display = 'none';
  }

  function showModalError(msg) {
    const el = document.querySelector('.paywall-modal-error');
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
  }

  // ---------------------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------------------

  document.addEventListener('DOMContentLoaded', function () {
    const gate = document.querySelector('.paywall-gate');
    if (!gate) return;

    const slug = gate.dataset.slug;

    // 1. Check URL hash for token returned from Stripe redirect
    if (window.location.hash.startsWith('#token=')) {
      const token = window.location.hash.slice('#token='.length);
      if (token) {
        localStorage.setItem(TOKEN_KEY, token);
      }
      // Clean up the URL
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }

    // 2. Check localStorage for existing token
    const storedToken = localStorage.getItem(TOKEN_KEY);
    if (storedToken && isTokenValid(storedToken)) {
      fetchPremiumContent(slug, storedToken);
    }
    // If no valid token the paywall UI is already visible

    // -------------------------------------------------------------------------
    // Buy button handlers
    // -------------------------------------------------------------------------

    document.querySelectorAll('.paywall-btn-article, .paywall-btn-sub').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        const type = btn.dataset.type;
        const priceId = btn.dataset.priceId || '';

        btn.disabled = true;
        btn.textContent = '\u8DF3\u8F6C\u4E2D\u2026'; // 跳转中...

        try {
          const resp = await fetch(`${API_URL}/api/checkout`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ slug: slug, type: type, priceId: priceId }),
          });
          const data = await resp.json();
          if (data.url) {
            window.location.href = data.url;
          }
        } catch (e) {
          console.error('Checkout error:', e);
          btn.disabled = false;
          btn.textContent =
            type === 'article' ? '\u89E3\u9501\u672C\u6587' : '\u6708\u5EA6\u8BA2\u9605'; // 解锁本文 / 月度订阅
        }
      });
    });

    // -------------------------------------------------------------------------
    // Restore access flow
    // -------------------------------------------------------------------------

    var restoreEmail = ''; // track email across steps

    var restoreLink = document.querySelector('.paywall-restore-link');
    if (restoreLink) {
      restoreLink.addEventListener('click', function (e) {
        e.preventDefault();
        openModal();
      });
    }

    // Close modal
    var modalClose = document.querySelector('.paywall-modal-close');
    if (modalClose) {
      modalClose.addEventListener('click', closeModal);
    }

    var backdrop = document.querySelector('.paywall-modal-backdrop');
    if (backdrop) {
      backdrop.addEventListener('click', closeModal);
    }

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeModal();
    });

    // Send verification code
    var sendBtn = document.querySelector('.paywall-btn-send');
    if (sendBtn) {
      sendBtn.addEventListener('click', async function () {
        var emailInput = document.querySelector('.paywall-step-email .paywall-input');
        var email = emailInput ? emailInput.value.trim() : '';
        if (!email) {
          showModalError('\u8BF7\u8F93\u5165\u90AE\u7BB1\u5730\u5740'); // 请输入邮箱地址
          return;
        }

        sendBtn.disabled = true;
        sendBtn.textContent = '\u53D1\u9001\u4E2D\u2026'; // 发送中...

        try {
          var resp = await fetch(`${API_URL}/api/restore`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, slug: slug }),
          });

          if (!resp.ok) {
            var errData = await resp.json().catch(function () { return {}; });
            throw new Error(errData.error || '\u53D1\u9001\u5931\u8D25'); // 发送失败
          }

          restoreEmail = email;

          // Switch to code input step
          document.querySelector('.paywall-step-email').style.display = 'none';
          document.querySelector('.paywall-step-code').style.display = 'flex';
          document.querySelector('.paywall-modal-error').style.display = 'none';
        } catch (e) {
          showModalError(e.message);
        } finally {
          sendBtn.disabled = false;
          sendBtn.textContent = '\u53D1\u9001\u9A8C\u8BC1\u7801'; // 发送验证码
        }
      });
    }

    // Verify code
    var verifyBtn = document.querySelector('.paywall-btn-verify');
    if (verifyBtn) {
      verifyBtn.addEventListener('click', async function () {
        var codeInput = document.querySelector('.paywall-code-input');
        var code = codeInput ? codeInput.value.trim() : '';
        if (!code) {
          showModalError('\u8BF7\u8F93\u5165\u9A8C\u8BC1\u7801'); // 请输入验证码
          return;
        }

        verifyBtn.disabled = true;
        verifyBtn.textContent = '\u9A8C\u8BC1\u4E2D\u2026'; // 验证中...

        try {
          var resp = await fetch(`${API_URL}/api/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: restoreEmail, code: code, slug: slug }),
          });

          if (!resp.ok) {
            var errData = await resp.json().catch(function () { return {}; });
            throw new Error(errData.error || '\u9A8C\u8BC1\u5931\u8D25'); // 验证失败
          }

          var data = await resp.json();
          if (data.token) {
            localStorage.setItem(TOKEN_KEY, data.token);
            closeModal();
            window.location.reload();
          }
        } catch (e) {
          showModalError(e.message);
        } finally {
          verifyBtn.disabled = false;
          verifyBtn.textContent = '\u9A8C\u8BC1'; // 验证
        }
      });
    }
  });
})();
