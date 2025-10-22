import { expect, test } from '@playwright/test';

const uniqueId = () => Date.now().toString(36) + Math.random().toString(16).slice(2, 6);

async function jsonRequest(request: any, url: string, body: Record<string, unknown>, expectedStatus: number) {
  const response = await request.post(url, {
    headers: { 'content-type': 'application/json' },
    data: JSON.stringify(body)
  });
  const payload = await response.json();
  expect(response.status(), url).toBe(expectedStatus);
  return payload;
}

test('identity + alias flow surfaces in feed', async ({ request, baseURL }) => {
  const workerBaseUrl = baseURL ?? 'http://localhost:8788';
  const boardId = `e2e-${uniqueId()}`;
  const pseudonym = `Playwright${uniqueId()}`.slice(0, 18);
  const alias = `Alias${uniqueId()}`;

  const identity = await jsonRequest(request, `${workerBaseUrl}/identity/register`, { pseudonym }, 201);
  const userId = identity.user.id as string;
  expect(userId).toBeTruthy();

  const aliasResponse = await jsonRequest(
    request,
    `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/aliases`,
    { userId, alias },
    201
  );
  expect(aliasResponse.alias.alias).toBe(alias);

  const postResponse = await jsonRequest(
    request,
    `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/posts`,
    { body: 'Playwright smoke post', userId },
    201
  );
  expect(postResponse.post.author).toBe(alias);

  const feedResponse = await request.get(
    `${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/feed?limit=1`
  );
  expect(feedResponse.ok()).toBeTruthy();
  const feed = await feedResponse.json();
  expect(Array.isArray(feed.posts)).toBeTruthy();
  const first = feed.posts[0];
  expect(first.author).toBe(alias);
  expect(first.body).toBe('Playwright smoke post');
});
