import { expect, test } from '@playwright/test';

const uniqueId = () => Date.now().toString(36) + Math.random().toString(16).slice(2, 6);

test('user can register, set alias, post and see activity', async ({ page, request }) => {
  const boardId = `e2e-${uniqueId()}`;
  const pseudonym = `Playwright${uniqueId()}`.slice(0, 18);
  const alias = `Alias${uniqueId()}`;
  const workerBaseUrl = process.env.WORKER_BASE_URL ?? 'http://localhost:8788';

  const health = await request.get(`${workerBaseUrl}/_health`, { timeout: 5_000 }).catch(() => null);
  test.skip(!health || !health.ok(), 'Worker must be running for identity flow test');

  const registerResponse = await request.post(`${workerBaseUrl}/identity/register`, {
    headers: { 'content-type': 'application/json' },
    data: JSON.stringify({ pseudonym })
  });
  expect(registerResponse.ok()).toBeTruthy();
  const registerPayload = await registerResponse.json();
  const session = registerPayload.session as { token: string };
  const user = registerPayload.user as { id: string; pseudonym: string };

  await page.addInitScript(
    ({ storedIdentity, storedSession, sessionCookieName }) => {
      window.localStorage.setItem('boardapp:identity', JSON.stringify(storedIdentity));
      window.localStorage.setItem('boardapp:session', JSON.stringify(storedSession));
      document.cookie = `${sessionCookieName}=${encodeURIComponent(JSON.stringify(storedSession))};path=/;samesite=lax`;
    },
    { storedIdentity: user, storedSession: session, sessionCookieName: 'boardapp_session_0' }
  );

  const aliasResponse = await request.post(
    `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/aliases`,
    {
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${session.token}`
      },
      data: JSON.stringify({ userId: user.id, alias })
    }
  );
  expect(aliasResponse.ok()).toBeTruthy();

  const postResponse = await request.post(
    `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts`,
    {
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${session.token}`
      },
      data: JSON.stringify({ body: 'Playwright UI post', userId: user.id })
    }
  );
  expect(postResponse.ok()).toBeTruthy();

  await page.goto(`/boards/${boardId}`);
  await page.waitForResponse(res => res.url().includes(`/boards/${encodeURIComponent(boardId)}/feed`) && res.ok());
  const postLocator = page.locator('article').filter({ hasText: 'Playwright UI post' }).first();
  await expect(postLocator).toBeVisible();
  await expect(postLocator.filter({ hasText: alias })).toBeVisible();

  const feedResponse = await request.get(
    `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/feed?limit=1`
  );
  expect(feedResponse.ok()).toBeTruthy();
  const feed = await feedResponse.json();
  const first = feed.posts[0];
  expect(first.alias).toBe(alias);
  expect(first.body).toBe('Playwright UI post');
});
