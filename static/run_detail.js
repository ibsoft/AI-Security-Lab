const logPanel = document.getElementById('runLogsPanel');

if (logPanel) {
  const runId = logPanel.dataset.runId;
  const searchField = document.getElementById('runLogSearch');
  const levelField = document.getElementById('runLogLevel');
  const rawField = document.getElementById('runLogRaw');
  const countLabel = document.getElementById('runLogCount');
  const eventList = document.getElementById('runLogEvents');
  let searchTimer;
  let refreshTimer;

  function appendLogEvent(event) {
    const item = document.createElement('article');
    item.className = 'run-log-event border-bottom border-secondary-subtle py-2';

    const heading = document.createElement('div');
    heading.className = 'd-flex flex-wrap align-items-center gap-2';

    const level = document.createElement('span');
    const levelName = String(event.level || 'info').toLowerCase();
    const levelClass = ['error', 'critical'].includes(levelName)
      ? 'danger'
      : levelName === 'warning'
        ? 'warning'
        : levelName === 'debug'
          ? 'secondary'
          : 'success';
    level.className = `badge text-bg-${levelClass}`;
    level.textContent = levelName.toUpperCase();

    const timestamp = document.createElement('time');
    timestamp.className = 'small text-secondary';
    timestamp.textContent = event.timestamp || '';
    if (event.timestamp) timestamp.dateTime = event.timestamp;

    const name = document.createElement('span');
    name.className = 'small fw-semibold';
    name.textContent = event.event || event.logger || 'event';

    heading.append(level, timestamp, name);
    item.append(heading);

    const message = document.createElement('div');
    message.className = 'small mt-1 wrap';
    message.textContent = event.message || '';
    item.append(message);

    if (rawField.checked && event.raw !== undefined) {
      const details = document.createElement('details');
      details.className = 'mt-2';
      const summary = document.createElement('summary');
      summary.className = 'small text-info';
      summary.textContent = 'Raw details';
      const raw = document.createElement('pre');
      raw.className = 'run-log-raw small mt-2';
      raw.textContent = JSON.stringify(event.raw, null, 2);
      details.append(summary, raw);
      item.append(details);
    }
    eventList.append(item);
  }

  async function refreshLogs() {
    const params = new URLSearchParams({
      level: levelField.value,
      q: searchField.value,
      raw: rawField.checked ? '1' : '0',
    });
    try {
      const response = await fetch(`/api/runs/${runId}/logs?${params}`);
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || `Log request failed (${response.status}).`);
      eventList.replaceChildren();
      countLabel.textContent = `${data.count} event${data.count === 1 ? '' : 's'}`;
      if (!data.events.length) {
        const empty = document.createElement('div');
        empty.className = 'small text-secondary py-2';
        empty.textContent = 'No events match these filters.';
        eventList.append(empty);
        return;
      }
      for (const event of data.events) appendLogEvent(event);
    } catch (error) {
      countLabel.textContent = 'Could not load logs';
      eventList.textContent = error.message;
    }
  }

  searchField.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(refreshLogs, 200);
  });
  levelField.addEventListener('change', refreshLogs);
  rawField.addEventListener('change', refreshLogs);
  refreshLogs();
  refreshTimer = setInterval(refreshLogs, 4000);
  window.addEventListener('beforeunload', () => clearInterval(refreshTimer), { once: true });
}
