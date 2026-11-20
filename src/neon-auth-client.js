import { createAuthClient } from '@neon/auth';
import { BetterAuthVanillaAdapter } from '@neon/auth/vanilla/adapters';

window.NUUAuthReady = (async () => {
  const response = await fetch('/api/auth/config', { credentials: 'same-origin' });
  const config = await response.json();
  if (!response.ok) {
    throw new Error(config.error || 'Could not load Neon Auth configuration.');
  }
  if (!config.auth_url) {
    throw new Error('Neon Auth is not configured on this server.');
  }
  return createAuthClient(config.auth_url, {
    adapter: BetterAuthVanillaAdapter({
      fetchOptions: { credentials: 'include' },
    }),
  });
})();
