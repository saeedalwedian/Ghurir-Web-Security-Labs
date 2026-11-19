const sandbox = document.querySelector("[data-sandbox]");
const modeButtons = [...sandbox.querySelectorAll("[data-mode-button]")];
const actionButtons = [...sandbox.querySelectorAll("[data-payload], [data-normal]")];
const response = sandbox.querySelector("[data-response]");
const request = sandbox.querySelector("[data-request]");
const requestLabel = sandbox.querySelector("[data-request-label]");
const requestText = sandbox.querySelector("[data-request-text]");
const statusBadge = sandbox.querySelector("[data-status]");
const resultTitle = sandbox.querySelector("[data-result-title]");
const resultDetail = sandbox.querySelector("[data-result-detail]");
const resultData = sandbox.querySelector("[data-result-data]");
const runScenario = securityLabs[sandbox.dataset.sandbox];

let mode = "vulnerable";
let currentRun = 0;
let selectedAction = null;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

const codeViews = [...document.querySelectorAll("[data-executable-code]")].map((code) => {
  const explanation = code.closest("figure").querySelector("figcaption p");
  return {
    code,
    explanation,
    source: securityLabs.codeSamples[sandbox.dataset.sandbox][code.dataset.executableCode],
    highlightLine: Number(code.dataset.highlightLine),
    caption: explanation.textContent,
  };
});

function renderExecutableCode(overrides) {
  for (const initial of codeViews) {
    const code = initial.code;
    const view = overrides?.[code.dataset.executableCode] ?? initial;
    const source = view.source;
    if (typeof source !== "string") throw new Error("Missing executable code sample.");
    const highlightedLine = view.highlightLine;
    code.dataset.highlightLine = String(highlightedLine);
    initial.explanation.textContent = view.caption;
    code.replaceChildren();
    for (const [index, line] of source.split("\n").entries()) {
      const lineNode = element("span", undefined, "code-line");
      const lineNumber = element("span", String(index + 1), "line-number");
      lineNumber.setAttribute("aria-hidden", "true");
      if (index + 1 === highlightedLine) lineNode.classList.add("highlighted");
      lineNode.append(
        lineNumber,
        element("span", line),
      );
      code.append(lineNode);
    }
  }
}

renderExecutableCode();

function renderFacts(facts) {
  const list = element("dl", undefined, "facts");
  for (const [label, value] of facts) {
    const item = element("div");
    item.append(element("dt", label), element("dd", value));
    list.append(item);
  }
  return list;
}

function renderEvents(events) {
  const timeline = element("div", undefined, "event-log");
  const list = element("ol");
  for (const event of events) list.append(element("li", event));
  timeline.append(element("h4", "Execution order"), list);
  return timeline;
}

function renderExchange(result) {
  const exchange = element("section", undefined, "response-exchange");
  const responseView = result.response;
  const responsePanel = element("div", undefined, "exchange-block");
  const responses = responseView.body.requests;
  if (Array.isArray(responses)) {
    const outcomes = element("ul", undefined, "request-outcomes");
    for (const item of responses) {
      const outcome = element("li");
      const applied = item.body.applied ?? item.body.spent;
      const labels = result.outcomeLabels ?? { success: "Coupon applied", blocked: "Repeated use rejected" };
      outcome.dataset.tone = applied ? "allowed" : "blocked";
      outcome.append(
        element("strong", item.requestId),
        element("span", item.status + " " + statusLabel(item.status)),
        element("span", applied ? labels.success : labels.blocked),
      );
      outcomes.append(outcome);
    }
    exchange.append(element("h4", "Request outcomes"), outcomes);
  }
  const heading = Array.isArray(responses)
    ? "Batch summary"
    : "Simulated response · " + responseView.status + " " + statusLabel(responseView.status);
  responsePanel.append(element("h4", heading));
  const headersPre = element("pre");
  headersPre.append(element("code", "Headers\n" + JSON.stringify(responseView.headers, null, 2)));
  const bodyPre = element("pre");
  bodyPre.append(element("code", "Body\n" + JSON.stringify(responseView.body, null, 2)));
  responsePanel.append(headersPre, bodyPre);
  exchange.append(responsePanel);
  return exchange;
}

function statusLabel(status) {
  return ({ 200: "OK", 302: "Found", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 409: "Conflict" })[status] || "Response";
}

function showStatus(tone, status, title, detail) {
  statusBadge.dataset.tone = tone;
  statusBadge.textContent = status;
  resultTitle.textContent = title;
  resultDetail.textContent = detail;
}

function resetResponse(keepSelection = false) {
  response.setAttribute("aria-busy", "false");
  request.hidden = true;
  resultData.replaceChildren();
  const replay = keepSelection && selectedAction;
  showStatus(
    "neutral",
    "Ready",
    replay ? "Run the selected request again" : "Run a payload",
    replay
      ? "Press the selected button to compare its result in " + (mode === "fixed" ? "Fixed" : "Vulnerable") + " mode."
      : "The request and its outcome will appear here.",
  );
  if (!keepSelection) {
    renderExecutableCode();
    selectedAction = null;
    for (const button of actionButtons) {
      button.dataset.selected = "false";
      button.setAttribute("aria-pressed", "false");
    }
  }
}

for (const button of modeButtons) {
  button.addEventListener("click", () => {
    if (mode === button.dataset.modeButton) return;
    mode = button.dataset.modeButton;
    currentRun += 1;
    sandbox.dataset.mode = mode;
    for (const option of modeButtons) {
      option.setAttribute("aria-pressed", String(option === button));
    }
    resetResponse(true);
  });
}

const resetButton = sandbox.querySelector("[data-reset]");
if (resetButton) {
  resetButton.addEventListener("click", () => {
    currentRun += 1;
    resetResponse();
  });
}

for (const button of actionButtons) {
  button.addEventListener("click", async () => {
    const run = ++currentRun;
    selectedAction = button;
    for (const option of actionButtons) {
      option.dataset.selected = String(option === button);
      option.setAttribute("aria-pressed", String(option === button));
    }

    response.setAttribute("aria-busy", "true");
    resultData.replaceChildren();
    request.hidden = true;
    showStatus("neutral", "Running", "Running the simulation", "Waiting for the result.");

    try {
      const payload = button.dataset.payload ?? button.dataset.normal;
      const result = await runScenario(mode, payload);
      if (run !== currentRun) return;

      const query = new URLSearchParams(result.request.query || {}).toString();
      const requestTarget = result.request.path + (query ? "?" + query : "");
      const requestLines = [result.request.method + " " + requestTarget];
      if (result.request.resourceId) requestLines.push("Resource ID: " + result.request.resourceId);
      if (result.request.session) requestLines.push("Session: " + JSON.stringify(result.request.session));
      if (result.request.concurrentRequests) requestLines.push("Concurrent requests: " + result.request.concurrentRequests);
      if (result.request.model) requestLines.push("Model: " + result.request.model);
      if (result.request.body !== null && result.request.body !== undefined) {
        requestLines.push("Body: " + JSON.stringify(result.request.body));
      }
      requestLabel.textContent = "Simulated request";
      requestText.textContent = requestLines.join("\n");
      request.hidden = false;
      renderExecutableCode(result.codeView);
      showStatus(result.tone, result.status || result.response.status + " " + statusLabel(result.response.status), result.title, result.detail);
      resultData.append(renderExchange(result));
      if (result.facts) resultData.append(renderFacts(result.facts));
      if (result.events) resultData.append(renderEvents(result.events));
    } catch (error) {
      if (run !== currentRun) return;
      console.error(error);
      showStatus("neutral", "Error", "Simulation interrupted", "Choose a payload to try again.");
    } finally {
      if (run === currentRun) response.setAttribute("aria-busy", "false");
    }
  });
}
