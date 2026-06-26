// Общие скрипты ДворPay

// --- Оверлей обработки платежа ---
const PAYMENT_STEPS = [
  'Обработка платежа...',
  'Проверка получателя...',
  'Подтверждение суммы...',
  'Списание дублей...',
  'Завершение операции...',
];

let paymentSubmitting = false;

function showPaymentProcessing() {
  const overlay = document.getElementById('payment-processing');
  if (!overlay) return;
  const text = document.getElementById('payment-step-text');
  overlay.classList.remove('hidden');
  overlay.classList.add('flex');
  document.body.style.overflow = 'hidden';

  let step = 0;
  if (text) text.textContent = PAYMENT_STEPS[0];

  const timer = setInterval(() => {
    step += 1;
    if (step < PAYMENT_STEPS.length && text) {
      text.textContent = PAYMENT_STEPS[step];
    }
  }, 650);

  overlay.dataset.timer = String(timer);
}

function hidePaymentProcessing() {
  const overlay = document.getElementById('payment-processing');
  if (!overlay) return;
  const timer = overlay.dataset.timer;
  if (timer) clearInterval(Number(timer));
  overlay.classList.add('hidden');
  overlay.classList.remove('flex');
  document.body.style.overflow = '';
}

function bindPaymentForm(formId) {
  const form = document.getElementById(formId);
  if (!form) return;

  form.addEventListener('submit', (e) => {
    if (paymentSubmitting) return;
    e.preventDefault();
    paymentSubmitting = true;

    const btn = form.querySelector('[type="submit"]');
    if (btn) {
      btn.disabled = true;
      btn.classList.add('opacity-60', 'cursor-not-allowed');
    }

    showPaymentProcessing();
    setTimeout(() => {
      paymentSubmitting = true;
      form.submit();
    }, 2800);
  });
}

// --- Поиск по транзакциям ---
function bindTransactionSearch(inputId, listId) {
  const input = document.getElementById(inputId);
  const list = document.getElementById(listId);
  if (!input || !list) return;

  input.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase();
    list.querySelectorAll('[data-search]').forEach((row) => {
      const hay = (row.dataset.search || '').toLowerCase();
      row.classList.toggle('hidden', q.length > 0 && !hay.includes(q));
    });
  });
}

// --- Модальные окна (перевод, QR, оплата) ---
function openSheet(sheetId, overlayId) {
  const sheet = document.getElementById(sheetId);
  const overlay = document.getElementById(overlayId);
  if (overlay) overlay.classList.remove('hidden');
  if (sheet) sheet.classList.remove('translate-y-full');
  document.body.style.overflow = 'hidden';
}

function closeSheet(sheetId, overlayId) {
  const sheet = document.getElementById(sheetId);
  const overlay = document.getElementById(overlayId);
  if (overlay) overlay.classList.add('hidden');
  if (sheet) sheet.classList.add('translate-y-full');
  document.body.style.overflow = '';
}

function openTransfer(prefillRecipient) {
  openSheet('transfer-sheet', 'transfer-overlay');
  const recipient = document.getElementById('recipient');
  if (recipient && prefillRecipient) {
    recipient.value = prefillRecipient;
    recipient.dispatchEvent(new Event('input'));
  }
}

function closeTransfer() {
  closeSheet('transfer-sheet', 'transfer-overlay');
}

function openQuickPay() {
  openSheet('quickpay-sheet', 'quickpay-overlay');
}

function closeQuickPay() {
  closeSheet('quickpay-sheet', 'quickpay-overlay');
}

// --- Скрытие баланса ---
function initBalanceToggle(balance) {
  const toggle = document.getElementById('toggle-balance');
  const balanceEl = document.getElementById('balance-value');
  const balanceDubl = document.getElementById('balance-dubl');
  const eyeOpen = document.getElementById('eye-open');
  const eyeClosed = document.getElementById('eye-closed');
  if (!toggle || !balanceEl) return;

  let visible = true;
  toggle.addEventListener('click', () => {
    visible = !visible;
    if (visible) {
      balanceEl.textContent = balance.toFixed(2);
      if (balanceDubl) balanceDubl.textContent = balance.toFixed(2);
      eyeOpen?.classList.remove('hidden');
      eyeClosed?.classList.add('hidden');
    } else {
      balanceEl.textContent = '••••••';
      if (balanceDubl) balanceDubl.textContent = '••••';
      eyeOpen?.classList.add('hidden');
      eyeClosed?.classList.remove('hidden');
    }
  });
}

// --- ПИН для business ---
function initTransferPin(businessAccounts) {
  const recipientInput = document.getElementById('recipient');
  const pinBlock = document.getElementById('pin-block');
  const pinInput = document.getElementById('pin');
  const commercialCheckbox = document.getElementById('commercial');
  if (!recipientInput) return;

  function updatePinVisibility() {
    const login = recipientInput.value.trim().toLowerCase();
    const isBusiness = businessAccounts.includes(login);
    const showPin = isBusiness || (commercialCheckbox && commercialCheckbox.checked);
    if (pinBlock) pinBlock.classList.toggle('hidden', !showPin);
    if (pinInput) pinInput.required = isBusiness;
  }

  recipientInput.addEventListener('input', updatePinVisibility);
  commercialCheckbox?.addEventListener('change', updatePinVisibility);
  updatePinVisibility();
}

// --- QR: разбор ссылки dvorpay://pay/login ---
function parsePayLink(raw) {
  const text = raw.trim();
  const match = text.match(/dvorpay:\/\/pay\/([a-zA-Z0-9_]+)/i);
  if (match) return match[1];
  if (/^[a-zA-Z0-9_]+$/.test(text)) return text;
  return null;
}

function payFromQrInput() {
  const input = document.getElementById('qr-parse-input');
  if (!input) return;
  const login = parsePayLink(input.value);
  if (!login) {
    alert('Не удалось распознать логин. Формат: dvorpay://pay/логин');
    return;
  }
  window.location.href = `/dashboard?pay=${encodeURIComponent(login)}`;
}

// Глобальные функции для onclick в HTML-шаблонах
window.openTransfer = openTransfer;
window.closeTransfer = closeTransfer;
window.openQuickPay = openQuickPay;
window.closeQuickPay = closeQuickPay;
window.payFromQrInput = payFromQrInput;
