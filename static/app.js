window.csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

if (window.Chart) {
  Chart.register({
    id: 'scoreBarColors',
    beforeUpdate(chart) {
      if (chart.config.type !== 'bar') return;
      for (const dataset of chart.data.datasets) {
        if (dataset.label !== 'Score') continue;
        dataset.backgroundColor = dataset.data.map((value) => {
          const score = Number(value);
          if (!Number.isFinite(score)) return '#6c757d';
          if (score < 30) return '#dc3545';
          if (score < 70) return '#ffc107';
          return '#198754';
        });
      }
    },
  });
}

window.sf = async function (url, options = {}) {
  options.headers = Object.assign({}, options.headers || {}, {
    'X-CSRFToken': window.csrfToken,
  });
  return fetch(url, options);
};

window.showModalMessage = function (title, message) {
  const modal = document.getElementById('appModal');
  if (!modal || !window.bootstrap) return;
  document.getElementById('appModalTitle').textContent = title || 'Message';
  document.getElementById('appModalBody').textContent = message || '';
  bootstrap.Modal.getOrCreateInstance(modal).show();
};

window.showConfirmModal = function (message, onConfirm, options = {}) {
  const modal = document.getElementById('confirmModal');
  if (!modal || !window.bootstrap) return;
  document.getElementById('confirmModalTitle').textContent = options.title || 'Confirm action';
  document.getElementById('confirmModalBody').textContent = message || 'Are you sure?';

  const oldButton = document.getElementById('confirmModalAccept');
  const button = oldButton.cloneNode(true);
  oldButton.parentNode.replaceChild(button, oldButton);
  button.textContent = options.confirmText || 'Confirm';
  button.className = 'btn ' + (options.confirmClass || 'btn-danger');
  button.addEventListener('click', () => {
    bootstrap.Modal.getOrCreateInstance(modal).hide();
    onConfirm();
  }, { once: true });

  bootstrap.Modal.getOrCreateInstance(modal).show();
};

document.addEventListener('submit', (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  const message = form.getAttribute('data-confirm-message');
  if (!message) return;
  event.preventDefault();
  window.showConfirmModal(message, () => {
    form.removeAttribute('data-confirm-message');
    form.submit();
  }, {
    title: form.getAttribute('data-confirm-title') || 'Confirm action',
    confirmText: form.getAttribute('data-confirm-text') || 'Confirm',
    confirmClass: form.getAttribute('data-confirm-class') || 'btn-danger',
  });
});
