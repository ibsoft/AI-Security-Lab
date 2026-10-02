function renderDetectorResult(result) {
  const output = document.getElementById('pgTestResult');
  const alert = document.createElement('div');
  alert.className = `alert alert-${result.verdict === 'malicious' ? 'danger' : 'success'}`;

  const details = [
    [`Verdict: ${String(result.verdict || 'unknown').toUpperCase()}`, 'fw-semibold'],
    [`Malicious confidence: ${(100 * Number(result.malicious_score || 0)).toFixed(2)}%`],
    [`Threshold: ${(100 * Number(result.threshold || 0)).toFixed(0)}%`],
    [`Chunks: ${Number(result.chunks || 0)}`],
    [`Latency: ${Math.round(Number(result.latency_ms || 0))} ms`],
  ];
  for (const [text, className = ''] of details) {
    const line = document.createElement('div');
    line.textContent = text;
    if (className) line.className = className;
    alert.append(line);
  }
  output.replaceChildren(alert);
}

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

document.querySelectorAll('.pgDownload').forEach((button) => {
  button.addEventListener('click', async () => {
    const progress = document.getElementById('pgDownloadProgress');
    const message = document.getElementById('pgDownloadMessage');
    button.disabled = true;
    progress.classList.remove('d-none');
    message.textContent = `Downloading ${button.dataset.model} from Hugging Face...`;
    try {
      const response = await sf('/api/prompt-guard/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model_id: button.dataset.model }),
      });
      const data = await readJsonResponse(response);
      const status = document.getElementById(button.dataset.status);
      status.textContent = 'Installed';
      status.className = 'badge text-bg-success';
      message.textContent = `${data.model_id} installed successfully.`;
    } catch (error) {
      message.textContent = error.message;
      showModalMessage('Prompt Guard download failed', error.message);
    } finally {
      progress.classList.add('d-none');
      button.disabled = false;
    }
  });
});

const diagnosticsButton = document.getElementById('pgDiagBtn');
diagnosticsButton?.addEventListener('click', async () => {
  try {
    const response = await fetch('/api/prompt-guard/diagnostics');
    const data = await readJsonResponse(response);
    const lines = [
      `Python: ${data.python || 'unknown'}`,
      `Transformers: ${data.transformers || data.transformers_error || 'unknown'}`,
      `Tokenizers: ${data.tokenizers || data.tokenizers_error || 'unknown'}`,
      `PyTorch: ${data.torch || data.torch_error || 'unknown'}`,
      `CUDA available: ${data.cuda_available === true ? 'yes' : 'no'}`,
      `CUDA device: ${data.cuda_device || '—'}`,
      `Configured model: ${data.configured_model || '—'}`,
      `Model installed: ${data.model_installed ? 'yes' : 'no'}`,
      `Transformers 4.x compatible: ${data.transformers_compatible ? 'yes' : 'NO — reinstall requirements'}`,
    ];
    showModalMessage('Prompt Guard runtime diagnostics', lines.join('\n'));
  } catch (error) {
    showModalMessage('Diagnostics failed', error.message);
  }
});

const detectorButton = document.getElementById('pgTestBtn');
detectorButton?.addEventListener('click', async () => {
  const output = document.getElementById('pgTestResult');
  const originalLabel = detectorButton.textContent;
  detectorButton.disabled = true;
  detectorButton.textContent = 'Running...';
  output.textContent = 'Classifying...';
  output.className = 'mt-3 text-secondary';
  try {
    const response = await sf('/api/prompt-guard/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: document.getElementById('pgTestText').value,
        model_id: document.getElementById('pgModel').value,
      }),
    });
    const data = await readJsonResponse(response);
    renderDetectorResult(data.result);
  } catch (error) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-danger';
    alert.textContent = error.message;
    output.replaceChildren(alert);
  } finally {
    detectorButton.disabled = false;
    detectorButton.textContent = originalLabel;
  }
});
