const providerSelect = document.getElementById('gp');
const modelSelect = document.getElementById('gm');
const statusMessage = document.getElementById('gs');
const progress = document.getElementById('prog');

async function readJsonResponse(response) {
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`Server returned an invalid response (HTTP ${response.status}).`);
  }
  if (!response.ok || data.ok === false) {
    throw new Error(data.error || `Request failed (HTTP ${response.status}).`);
  }
  return data;
}

function setStatus(message, className = 'mt-3 text-secondary') {
  statusMessage.textContent = message;
  statusMessage.className = className;
}

async function checkStatus() {
  setStatus('Checking...');
  try {
    const url = `/api/llama-guard/status/${providerSelect.value}?model=${encodeURIComponent(modelSelect.value)}`;
    const data = await readJsonResponse(await fetch(url));
    setStatus(
      data.installed ? `Installed: ${data.model}` : `Not installed: ${data.model}`,
      `mt-3 text-${data.installed ? 'success' : 'warning'}`,
    );
  } catch (error) {
    setStatus(error.message, 'mt-3 text-danger');
  }
}

document.getElementById('gc')?.addEventListener('click', checkStatus);

document.getElementById('gw')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  progress.classList.remove('d-none');
  setStatus('Warming model...');
  try {
    const data = await readJsonResponse(await sf(`/api/llama-guard/warm/${providerSelect.value}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: modelSelect.value,
        timeout_seconds: Number(document.getElementById('gtimeout').value || 600),
      }),
    }));
    setStatus(`${data.model} warmed in ${Math.round(data.latency_ms)} ms.`, 'mt-3 text-success');
  } catch (error) {
    setStatus(error.message, 'mt-3 text-danger');
  } finally {
    progress.classList.add('d-none');
    button.disabled = false;
  }
});

document.getElementById('gi')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  progress.classList.remove('d-none');
  setStatus('Downloading through Ollama...');
  try {
    const data = await readJsonResponse(await sf(`/api/llama-guard/install/${providerSelect.value}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: modelSelect.value }),
    }));
    setStatus(`${data.model} installed and wired.`, 'mt-3 text-success');
  } catch (error) {
    setStatus(error.message, 'mt-3 text-danger');
  } finally {
    progress.classList.add('d-none');
    button.disabled = false;
  }
});

function renderClassificationResult(result) {
  const output = document.getElementById('lgTestResult');
  const card = document.createElement('div');
  card.className = 'alert alert-info';

  const heading = document.createElement('div');
  heading.className = 'fw-semibold mb-2';
  heading.textContent = `${result.model} classification`;
  card.append(heading);

  for (const stage of ['input', 'output']) {
    const verdict = result[stage];
    if (!verdict) continue;
    const details = [];
    if (verdict.label === 'unsafe') details.push('safe: false');
    if (verdict.categories?.length) details.push(`categories: ${verdict.categories.join(', ')}`);
    const line = document.createElement('div');
    line.textContent = `${stage === 'input' ? 'Prompt' : 'Response'}: ${String(verdict.label || 'unknown').toUpperCase()}${details.length ? ` · ${details.join(' · ')}` : ''}`;
    card.append(line);
  }
  output.replaceChildren(card);
}

document.getElementById('lgTestBtn')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const output = document.getElementById('lgTestResult');
  const mode = document.getElementById('lgTestMode').value;
  button.disabled = true;
  button.textContent = 'Testing...';
  output.textContent = 'Classifying with Llama Guard...';
  output.className = 'mt-3 text-secondary';
  try {
    const data = await readJsonResponse(await sf(`/api/llama-guard/test/${providerSelect.value}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: modelSelect.value,
        mode,
        text: document.getElementById('lgTestInput').value,
        response: document.getElementById('lgTestOutput').value,
        timeout_seconds: Number(document.getElementById('gtimeout').value || 600),
      }),
    }));
    renderClassificationResult(data.result);
  } catch (error) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-danger';
    alert.textContent = error.message;
    output.replaceChildren(alert);
  } finally {
    button.disabled = false;
    button.textContent = 'Run test';
  }
});

if (providerSelect) checkStatus();
