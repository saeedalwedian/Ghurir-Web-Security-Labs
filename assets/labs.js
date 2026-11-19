const securityLabs = (() => {
  function makeRequest({ method, path, query = {}, session = null, body = null, ...context }) {
    return { method, path, query, session, body, ...context };
  }

  function makeResponse(status, body, headers = {}) {
    return { status, headers: { "Content-Type": "application/json", ...headers }, body };
  }

  function statusLabel(status) {
    return ({ 200: "OK", 302: "Found", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 409: "Conflict" })[status] || "Response";
  }

  function dollars(value) {
    return "$" + value.toFixed(2);
  }

  // ---------------------------------------------------------------------------
  // Lab 1 · IDOR (CWE-639)
  // ---------------------------------------------------------------------------
  const viewerId = "U-01";

  // A fresh copy of the sample data is built for every run.
  function createInvoiceStore() {
    const rows = [
      { id: 101, ownerId: "U-01", customer: "Lina Haddad", item: "Desk lamp", total: 24, deliveryNote: "Standard delivery" },
      { id: 102, ownerId: "U-02", customer: "Omar Nasser", item: "Cable tray", total: 18, deliveryNote: "Standard delivery" },
      { id: 103, ownerId: "U-03", customer: "Sara Khalil", item: "Monitor stand", total: 42, deliveryNote: "Standard delivery" },
    ];
    return {
      async findById(id) {
        const row = rows.find((record) => record.id === id);
        return row ? { ...row } : null;
      },
      async updateDeliveryNote(id, deliveryNote) {
        const row = rows.find((record) => record.id === id);
        row.deliveryNote = deliveryNote;
        return { ...row };
      },
    };
  }

  async function viewInvoiceVulnerable(req, invoices, steps) {
    const id = Number(req.resourceId);
    steps.push("Read invoice ID from the request.");
    if (!Number.isInteger(id)) return makeResponse(400, { error: "Invalid invoice ID." });
    const invoice = await invoices.findById(id);
    if (!invoice) return makeResponse(404, { error: "Invoice not found." });
    steps.push("Return the invoice without checking its owner.");
    return makeResponse(200, invoice);
  }

  async function viewInvoiceFixed(req, invoices, steps) {
    const id = Number(req.resourceId);
    steps.push("Read invoice ID from the request.");
    if (!Number.isInteger(id)) return makeResponse(400, { error: "Invalid invoice ID." });
    const invoice = await invoices.findById(id);
    if (!invoice) return makeResponse(404, { error: "Invoice not found." });
    if (invoice.ownerId !== req.session.userId) {
      steps.push("Reject request: invoice belongs to " + invoice.ownerId + ".");
      return makeResponse(403, { error: "Forbidden: invoice belongs to another user." });
    }
    steps.push("Owner matches; return the invoice.");
    return makeResponse(200, invoice);
  }

  async function updateInvoiceVulnerable(req, invoices, steps) {
    const id = Number(req.resourceId);
    if (!Number.isInteger(id)) return makeResponse(400, { error: "Invalid invoice ID." });
    const invoice = await invoices.findById(id);
    if (!invoice) return makeResponse(404, { error: "Invoice not found." });
    const note = req.body.deliveryNote;
    if (typeof note !== "string") return makeResponse(400, { error: "Invalid delivery note." });
    steps.push("Update the delivery note without checking ownership.");
    const updated = await invoices.updateDeliveryNote(id, note);
    return makeResponse(200, updated);
  }

  async function updateInvoiceFixed(req, invoices, steps) {
    const id = Number(req.resourceId);
    if (!Number.isInteger(id)) return makeResponse(400, { error: "Invalid invoice ID." });
    const invoice = await invoices.findById(id);
    if (!invoice) return makeResponse(404, { error: "Invoice not found." });
    if (invoice.ownerId !== req.session.userId) return makeResponse(403, { error: "Forbidden: invoice belongs to another user." });
    const note = req.body.deliveryNote;
    if (typeof note !== "string") return makeResponse(400, { error: "Invalid delivery note." });
    steps.push("Ownership verified; update the delivery note.");
    const updated = await invoices.updateDeliveryNote(id, note);
    return makeResponse(200, updated);
  }

  const invoiceUpdateCode = {
    vulnerable: {
      source: updateInvoiceVulnerable.toString(),
      highlightLine: 9,
      caption: "Line 9 writes a new delivery note without verifying who owns the invoice.",
    },
    fixed: {
      source: updateInvoiceFixed.toString(),
      highlightLine: 6,
      caption: "Line 6 rejects the change when the invoice belongs to another user.",
    },
  };

  async function viewInvoice(mode, payload) {
    const updating = payload === "update-102";
    const resourceId = updating ? "102" : String(payload);
    const request = makeRequest({
      method: updating ? "PATCH" : "GET",
      path: "/invoices/" + resourceId,
      session: { userId: viewerId },
      body: updating ? { deliveryNote: "Collect at reception" } : null,
      resourceId,
    });
    const handlers = updating
      ? { vulnerable: updateInvoiceVulnerable, fixed: updateInvoiceFixed }
      : { vulnerable: viewInvoiceVulnerable, fixed: viewInvoiceFixed };
    const steps = [];
    const response = await handlers[mode](request, createInvoiceStore(), steps);
    const invoice = response.status === 200 ? response.body : null;
    const ownInvoice = Boolean(invoice && invoice.ownerId === request.session.userId);
    const exposed = Boolean(invoice && !ownInvoice);

    return {
      request,
      response,
      events: steps,
      codeView: updating ? invoiceUpdateCode : undefined,
      facts: updating && response.status === 200
        ? [["Invoice owner", invoice.ownerId], ["Note before", "Standard delivery"], ["Note after", invoice.deliveryNote]]
        : undefined,
      tone: exposed ? "exposed" : response.status === 403 ? "blocked" : ownInvoice ? "allowed" : "neutral",
      status: response.status + " " + statusLabel(response.status),
      title: response.status === 200
        ? "Invoice #" + invoice.id + (updating ? " changed" : " returned")
        : statusLabel(response.status),
      detail: exposed
        ? updating
          ? "The request changed another user's delivery note because ownership was never checked."
          : "The response contains an invoice owned by another user because this handler skipped the ownership check."
        : response.status === 403
          ? "The ownership check rejected the request; no invoice data was returned."
          : ownInvoice
            ? "The response contains the authenticated viewer's own invoice."
            : response.status === 404
              ? "No invoice exists with this resource ID."
              : "The path contains an invalid invoice ID.",
    };
  }

  const invoiceCodeSamples = {
    vulnerable: viewInvoiceVulnerable.toString(),
    fixed: viewInvoiceFixed.toString(),
  };

  // ---------------------------------------------------------------------------
  // Lab 2 · Open Redirect (CWE-601)
  // ---------------------------------------------------------------------------
  const redirectOrigin = "https://portal.example";

  function parseRedirectDestination(value) {
    try {
      const destination = new URL(value, redirectOrigin);
      if (destination.protocol !== "http:" && destination.protocol !== "https:") return null;
      return destination;
    } catch {
      return null;
    }
  }

  function continueToVulnerable(req) {
    const next = req.query.next;
    const destination = parseRedirectDestination(next);
    if (!destination) {
      return makeResponse(400, { error: "Invalid redirect destination." }, { "Cache-Control": "no-store" });
    }
    return makeResponse(302, { message: "Redirect decision recorded; no navigation occurred." }, {
      "Cache-Control": "no-store",
      Location: next,
    });
  }

  const allowedDestinations = new Set(["/account", "/help"]);
  function continueToFixed(req) {
    const next = req.query.next;
    if (!allowedDestinations.has(next)) {
      return makeResponse(400, { error: "Destination is not in the internal-route allowlist." }, {
        "Cache-Control": "no-store",
      });
    }
    return makeResponse(302, { message: "Allowed internal redirect; no navigation occurred." }, {
      "Cache-Control": "no-store",
      Location: next,
    });
  }

  const redirectCodeSamples = {
    vulnerable: continueToVulnerable.toString(),
    fixed: continueToFixed.toString(),
  };

  function simulateRedirect(mode, payload) {
    const next = String(payload);
    const request = makeRequest({ method: "GET", path: "/continue", query: { next } });
    const handler = mode === "fixed" ? continueToFixed : continueToVulnerable;
    const response = handler(request);
    const location = response.headers.Location;
    const destination = location ? parseRedirectDestination(location) : null;
    const external = Boolean(destination && destination.origin !== redirectOrigin);

    return {
      request,
      response,
      events: response.status === 400
        ? ["Read the next query parameter.", "Reject destination."]
        : ["Read the next query parameter.", "Return simulated Location: " + location + "; no navigation occurs."],
      tone: external ? "exposed" : response.status === 400 ? "blocked" : "allowed",
      status: external ? "External redirect" : response.status === 302 ? "Internal redirect" : "Redirect blocked",
      title: external ? "External redirect returned" : response.status === 302 ? "Internal redirect returned" : "Redirect rejected",
      detail: external
        ? destination.username
          ? destination.username + " is user info before @. The destination host is " + destination.hostname + "."
          : "The destination host is " + destination.hostname + ". The lab reports the Location header."
        : response.status === 302
          ? "The Location header names an explicitly allowed internal route; the lab does not navigate."
          : response.body.error + " The browser would remain on the lab page.",
      facts: destination ? [["Destination host", destination.hostname]] : undefined,
    };
  }

  // ---------------------------------------------------------------------------
  // Lab 3 · Race Condition (CWE-362)
  //
  // Browser-based concurrency simulation. A browser tab cannot reproduce real
  // database concurrency, so every store call goes through a deterministic
  // scheduler. Each call is queued, and the scheduler runs queued calls one at
  // a time, oldest first. Requests that start together therefore interleave
  // step by step: every request finishes step N before any request starts N+1.
  // ---------------------------------------------------------------------------
  const startingTotal = 100;
  const discount = 10;
  const couponCode = "LAB10";

  function createLabStore() {
    const cart = { id: "cart-1", subtotal: startingTotal, discount: 0, couponUsed: false };
    const wallet = { balance: 20 };
    const coupons = { [couponCode]: { valid: true } };
    const queue = [];
    const log = [];
    let step = 0;

    function note(request, text) {
      log.push(request + " · " + text);
    }

    // Queue one store call. Each state operation runs as one scheduler step.
    function io(request, name, work) {
      return new Promise((resolve) => queue.push({ request, name, work, resolve }));
    }

    async function run() {
      while (queue.length > 0) {
        const op = queue.shift();
        step += 1;
        const outcome = op.work();
        log.push("Step " + step + " · " + op.request + " · " + op.name + " → " + outcome.text);
        op.resolve(outcome.value);
        // Let the request that just resumed queue its next call before the
        // scheduler picks the next one.
        await new Promise((done) => setTimeout(done, 0));
      }
    }

    function forRequest(request) {
      return {
        note(text) {
          note(request, text);
        },
        getCart(cartId) {
          return io(request, "getCart()", () => ({
            value: { ...cart },
            text: "read couponUsed=" + cart.couponUsed + ", discount " + dollars(cart.discount),
          }));
        },
        findCoupon(code) {
          return io(request, "findCoupon()", () => ({
            value: coupons[code] ? { ...coupons[code] } : null,
            text: "coupon " + code + " is valid",
          }));
        },
        addDiscount(cartId, amount) {
          return io(request, "addDiscount(" + amount + ")", () => {
            const before = cart.discount;
            cart.discount += amount;
            return {
              value: true,
              text: "discount " + dollars(before) + " → " + dollars(cart.discount),
            };
          });
        },
        markCouponUsed(cartId) {
          return io(request, "markCouponUsed()", () => {
            const before = cart.couponUsed;
            cart.couponUsed = true;
            return { value: true, text: "couponUsed " + before + " → true" };
          });
        },
        // One conditional update. The check and the write happen inside the
        // same scheduler step, like
        //   UPDATE carts SET coupon_used = true, discount = discount + 10
        //   WHERE id = ? AND coupon_used = false
        // so no other request can run between them.
        claimCouponAndDiscount(cartId, amount) {
          return io(request, "claimCouponAndDiscount(" + amount + ")", () => {
            if (cart.couponUsed) {
              return { value: false, text: "0 rows matched (couponUsed is already true), nothing changed" };
            }
            cart.couponUsed = true;
            const before = cart.discount;
            cart.discount += amount;
            return {
              value: true,
              text: "1 row matched: couponUsed false → true, discount " + dollars(before) + " → " + dollars(cart.discount),
            };
          });
        },
        getWallet() {
          return io(request, "getWallet()", () => ({
            value: { ...wallet },
            text: "read available credit " + dollars(wallet.balance),
          }));
        },
        debitWallet(amount) {
          return io(request, "debitWallet(" + amount + ")", () => {
            wallet.balance -= amount;
            return { value: true, text: "remaining credit " + dollars(wallet.balance) };
          });
        },
        spendIfAvailable(amount) {
          return io(request, "spendIfAvailable(" + amount + ")", () => {
            if (wallet.balance < amount) {
              return { value: false, text: "insufficient credit; balance stays " + dollars(wallet.balance) };
            }
            wallet.balance -= amount;
            return { value: true, text: "credit checked and debited; balance " + dollars(wallet.balance) };
          });
        },
      };
    }

    return { cart, wallet, log, run, forRequest };
  }

  function createCouponHandlers(store) {
    async function isValidCoupon(code) {
      const coupon = await store.findCoupon(code);
      return Boolean(coupon && coupon.valid);
    }

    const vulnerable = async function applyCoupon(cartId, code) {
      const cart = await store.getCart(cartId);
      if (cart.couponUsed) {
        return { applied: false, status: 409 };
      }
      if (!(await isValidCoupon(code))) {
        return { applied: false, status: 400 };
      }
      await store.addDiscount(cartId, discount);
      await store.markCouponUsed(cartId);
      return { applied: true, status: 200, discount };
    };

    const fixed = async function applyCoupon(cartId, code) {
      if (!(await isValidCoupon(code))) {
        return { applied: false, status: 400 };
      }
      const claimed = await store.claimCouponAndDiscount(cartId, discount);
      if (!claimed) {
        return { applied: false, status: 409 };
      }
      return { applied: true, status: 200, discount };
    };

    return { vulnerable, fixed };
  }

  const raceConditionCodeSamples = (() => {
    const handlers = createCouponHandlers(null);
    return {
      vulnerable: handlers.vulnerable.toString(),
      fixed: handlers.fixed.toString(),
    };
  })();

  const couponAttempts = { normal: 1, pair: 2, triple: 3 };

  function createWalletHandlers(store) {
    const vulnerable = async function spendCredit(amount) {
      if (!Number.isInteger(amount) || amount <= 0) return { spent: false, status: 400 };
      const wallet = await store.getWallet();
      if (wallet.balance < amount) {
        return { spent: false, status: 409 };
      }
      await store.debitWallet(amount);
      return { spent: true, status: 200, amount };
    };

    const fixed = async function spendCredit(amount) {
      if (!Number.isInteger(amount) || amount <= 0) return { spent: false, status: 400 };
      const spent = await store.spendIfAvailable(amount);
      if (!spent) {
        return { spent: false, status: 409 };
      }
      return { spent: true, status: 200, amount };
    };

    return { vulnerable, fixed };
  }

  const walletCodeView = (() => {
    const handlers = createWalletHandlers(null);
    return {
      vulnerable: {
        source: handlers.vulnerable.toString(),
        highlightLine: 7,
        caption: "Line 7 debits a balance checked earlier. Both requests can approve spending the same credit.",
      },
      fixed: {
        source: handlers.fixed.toString(),
        highlightLine: 3,
        caption: "Line 3 checks the balance and spends the credit in one atomic operation.",
      },
    };
  })();

  async function spendWallet(mode) {
    const store = createLabStore();
    const amount = 15;
    const requests = ["Request A", "Request B"].map((requestId) => {
      const request = makeRequest({
        method: "POST",
        path: "/wallet/spend",
        body: { amount },
        session: { userId: viewerId },
        requestId,
      });
      store.log.push(requestId + " · request created for POST /wallet/spend");
      const handlers = createWalletHandlers(store.forRequest(requestId));
      return handlers[mode](amount).then((outcome) => ({
        request,
        response: makeResponse(outcome.status, {
          spent: outcome.spent,
          amount: outcome.spent ? dollars(amount) : "$0.00",
        }),
      }));
    });
    await store.run();
    const results = await Promise.all(requests);
    const succeeded = results.filter((item) => item.response.body.spent).length;
    const overspent = store.wallet.balance < 0;

    return {
      request: {
        method: "POST",
        path: "/wallet/spend",
        query: {},
        body: { amount },
        session: { userId: viewerId },
        concurrentRequests: 2,
        model: "Deterministic client-side concurrency model.",
      },
      response: makeResponse(200, {
        requests: results.map(({ request, response }) => ({
          requestId: request.requestId,
          status: response.status,
          body: response.body,
        })),
        initialBalance: "$20.00",
        finalBalance: dollars(store.wallet.balance),
        totalSpent: dollars(succeeded * amount),
        succeeded,
        rejected: 2 - succeeded,
      }),
      tone: overspent ? "exposed" : "blocked",
      status: overspent ? "Credit overspent" : "Overspend blocked",
      title: overspent ? "$30 spent from $20 credit" : "Second spend rejected",
      detail: overspent
        ? "Both requests checked the original $20 balance. Spending $15 twice left a negative balance."
        : "The first request spent $15. The remaining $5 was insufficient for the second request.",
      facts: [["Credit before", "$20.00"], ["Credit after", dollars(store.wallet.balance)]],
      events: store.log,
      codeView: walletCodeView,
      outcomeLabels: { success: "Credit spent", blocked: "Insufficient credit" },
    };
  }

  async function redeemCoupon(mode, payload) {
    const count = couponAttempts[payload];
    const store = createLabStore();

    // Start every request before the scheduler runs anything, so they are
    // genuinely in flight at the same time.
    const requests = Array.from({ length: count }, (_, index) => {
      const name = "Request " + String.fromCharCode(65 + index);
      const request = makeRequest({
        method: "POST",
        path: "/cart/coupon",
        session: { userId: viewerId },
        body: { code: couponCode },
        requestId: name,
      });
      store.log.push(name + " · request created for POST /cart/coupon");
      const handlers = createCouponHandlers(store.forRequest(name));
      const handler = mode === "fixed" ? handlers.fixed : handlers.vulnerable;
      return handler("cart-1", request.body.code).then((outcome) => {
        const error = outcome.status === 409
          ? "Coupon has already been used."
          : outcome.status === 400
            ? "Invalid coupon."
            : undefined;
        const body = outcome.applied
          ? { applied: true, discount: dollars(outcome.discount) }
          : { applied: false, error };
        const result = makeResponse(outcome.status, body);
        store.log.push(name + " · response " + result.status + " " + statusLabel(result.status));
        return { request, response: result };
      });
    });
    await store.run();
    const results = await Promise.all(requests);

    const applied = results.filter((result) => result.response.body.applied).length;
    const duplicate = applied > 1;
    const rejected = count - applied;
    const cartTotal = store.cart.subtotal - store.cart.discount;

    const response = makeResponse(200, {
      requests: results.map(({ request, response: itemResponse }) => ({
        requestId: request.requestId,
        status: itemResponse.status,
        body: itemResponse.body,
      })),
      initialCartTotal: dollars(startingTotal),
      finalCartTotal: dollars(cartTotal),
      totalDiscount: dollars(store.cart.discount),
      succeeded: applied,
      rejected,
      couponUsed: store.cart.couponUsed,
    });

    return {
      request: {
        method: "POST",
        path: "/cart/coupon",
        query: {},
        session: { userId: viewerId },
        body: { code: couponCode },
        concurrentRequests: count,
        model: "Deterministic client-side concurrency model; not real database concurrency.",
      },
      response,
      tone: duplicate ? "exposed" : rejected > 0 ? "blocked" : "allowed",
      status: duplicate ? "Coupon reused" : rejected > 0 ? "Extra attempts blocked" : "Coupon applied",
      title: applied + (applied === 1 ? " discount applied" : " discounts applied"),
      detail: duplicate
        ? "Several requests read the coupon as unused before any request recorded it as used."
        : rejected > 0
          ? "Only one request claimed the coupon. The conditional update matched no rows for the others."
          : "The one-use coupon was applied exactly once.",
      events: store.log,
    };
  }

  function runRaceScenario(mode, payload) {
    return payload === "credit" ? spendWallet(mode) : redeemCoupon(mode, payload);
  }

  return {
    idor: viewInvoice,
    "open-redirect": simulateRedirect,
    "race-condition": runRaceScenario,
    codeSamples: {
      idor: invoiceCodeSamples,
      "open-redirect": redirectCodeSamples,
      "race-condition": raceConditionCodeSamples,
    },
  };
})();
