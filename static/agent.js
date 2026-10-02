const targetProvider = document.getElementById('provider');
const targetModel = document.getElementById('model');
const judgeProvider = document.getElementById('judgeProvider');
const judgeModel = document.getElementById('judgeModel');
const conversationBox = document.getElementById('chat');
const sendButton = document.getElementById('send');
let messages = [];

function targetModelOptional() {
  return targetProvider.selectedOptions[0]?.dataset.modelOptional === 'true';
}

async function loadProviderModels(providerId, select, preferred = '') {
  select.replaceChildren();
  const optional = select === targetModel && targetModelOptional();
  if (select === targetModel) {
    document.getElementById('targetModelLabel').textContent = optional ? 'Target model (optional)' : 'Target model';
  }
  if (optional) select.append(new Option('Use provider default', ''));
  if (!providerId) return;
  const response = await fetch(`/api/provider/${providerId}/models`);
  const models = await response.json();
  if (!response.ok) throw new Error(models.error || `Could not load models (${response.status}).`);
  for (const modelName of models) {
    const option = document.createElement('option');
    option.value = modelName;
    option.textContent = modelName;
    option.selected = modelName === preferred;
    select.append(option);
  }
  if (optional && !preferred) select.value = '';
}

function appendMessage(role, text, report) {
  const row = document.createElement('div');
  row.className = `d-flex mb-3 ${role === 'user' ? 'justify-content-end' : 'justify-content-start'}`;
  const bubble = document.createElement('div');
  bubble.className = `bubble ${role}`;
  bubble.textContent = text;
  row.append(bubble);
  conversationBox.append(row);

  if (report) {
    const result = document.createElement('section');
    result.className = 'card panel mb-3';
    const header = document.createElement('div');
    header.className = 'card-header d-flex justify-content-between flex-wrap gap-2';
    header.textContent = `Security report · final Judge verdict: ${report.final_verdict.decision.toUpperCase()}`;
    result.append(header);

    const body = document.createElement('div');
    body.className = 'card-body py-2';
    const judge = document.createElement('div');
    judge.className = `fw-semibold mb-2 text-${report.judge.verdict === 'allow' ? 'success' : 'danger'}`;
    judge.textContent = `Final input Judge: ${report.judge.verdict.toUpperCase()} · ${report.judge.reason}`;
    body.append(judge);

    for (const stage of report.stages) {
      const line = document.createElement('div');
      line.className = 'small border-top border-secondary-subtle py-1';
      line.textContent = `${stage.name}: ${stage.status}${stage.summary ? ` · ${stage.summary}` : ''}`;
      body.append(line);
    }

    const details = document.createElement('details');
    details.className = 'mt-2';
    const summary = document.createElement('summary');
    summary.className = 'small text-info';
    summary.textContent = 'Normalized report and raw detector data';
    const raw = document.createElement('pre');
    raw.className = 'run-log-raw small mt-2';
    raw.textContent = JSON.stringify(report, null, 2);
    details.append(summary, raw);
    body.append(details);
    result.append(body);
    conversationBox.append(result);
  }
  conversationBox.scrollTop = conversationBox.scrollHeight;
}

async function initializeModels() {
  try {
    await loadProviderModels(targetProvider.value, targetModel);
    await loadProviderModels(judgeProvider.value, judgeModel);
  } catch (error) {
    document.getElementById('tel').textContent = error.message;
  }
}

targetProvider.addEventListener('change', () => loadProviderModels(targetProvider.value, targetModel));
judgeProvider.addEventListener('change', () => loadProviderModels(judgeProvider.value, judgeModel));
document.getElementById('clear').addEventListener('click', () => {
  messages = [];
  conversationBox.replaceChildren();
});

sendButton.addEventListener('click', async () => {
  const input = document.getElementById('msg');
  const text = input.value.trim();
  if (!text || !targetProvider.value || (!targetModel.value && !targetModelOptional()) || !judgeModel.value) return;
  messages.push({ role: 'user', content: text });
  appendMessage('user', text);
  input.value = '';
  sendButton.disabled = true;
  sendButton.textContent = 'Checking...';
  document.getElementById('tel').textContent = 'Running security pipeline';
  try {
    const response = await sf('/api/agent/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider_id: targetProvider.value,
        model: targetModel.value,
        messages,
        system_prompt: document.getElementById('system').value,
        temperature: document.getElementById('temp').value,
        max_tokens: document.getElementById('max').value,
        use_prompt_guard: document.getElementById('enablePromptGuard').checked,
        prompt_guard_model: document.getElementById('promptGuardModel').value,
        use_llama_guard: document.getElementById('enableLlamaGuard').checked,
        llama_guard_provider_profile_id: document.getElementById('llamaProvider').value,
        llama_guard_model: document.getElementById('llamaModel').value,
        llama_guard_timeout_seconds: document.getElementById('llamaTimeout').value,
        judge_provider_id: judgeProvider.value,
        judge_model: judgeModel.value,
      }),
    });
    const data = await response.json();
    if (!response.ok || !data.ok) {
      if (data.security_report) {
        appendMessage('assistant', data.error || data.text || 'The request could not be completed.', data.security_report);
        if (messages.at(-1)?.role === 'user' && messages.at(-1)?.content === text) messages.pop();
        document.getElementById('tel').textContent = 'Pipeline failed';
        return;
      }
      throw new Error(data.error || `Request failed (${response.status}).`);
    }
    appendMessage('assistant', data.text, data.security_report);
    if (data.security_report.final_verdict.decision === 'allow') {
      messages.push({ role: 'assistant', content: data.text });
    } else if (messages.at(-1)?.role === 'user' && messages.at(-1)?.content === text) {
      messages.pop();
    }
    const judgeUsage = data.security_report.judge.usage || {};
    document.getElementById('tel').textContent = `${data.latency_ms ?? '—'} ms · target in ${data.input_tokens ?? '—'} / out ${data.output_tokens ?? '—'} · judge in ${judgeUsage.input_tokens ?? '—'} / out ${judgeUsage.output_tokens ?? '—'}`;
  } catch (error) {
    appendMessage('assistant', `Pipeline error: ${error.message}`);
    if (messages.at(-1)?.role === 'user' && messages.at(-1)?.content === text) messages.pop();
    document.getElementById('tel').textContent = 'Pipeline failed';
  } finally {
    sendButton.disabled = false;
    sendButton.textContent = 'Run pipeline';
  }
});

initializeModels();
