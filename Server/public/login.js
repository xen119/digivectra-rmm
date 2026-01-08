const form = document.getElementById('loginForm');
const errorEl = document.getElementById('error');

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorEl.textContent = '';

  const username = document.getElementById('username')?.value.trim();
  const password = document.getElementById('password')?.value;
  const totp = document.getElementById('totp')?.value;

  if (!username || !password || !totp) {
    errorEl.textContent = 'Fill in all fields.';
    return;
  }

  try {
    const response = await fetch('/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password, totp })
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      errorEl.textContent = payload.error || 'Authentication failed.';
      return;
    }

    window.location.href = '/';
  } catch (error) {
    errorEl.textContent = 'Unable to reach the server.';
  }
});
