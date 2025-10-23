import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';

const workerBaseUrl = process.env.WORKER_BASE_URL ?? 'http://localhost:8788';
const boardId = process.argv[2] ?? 'smoke-board';

async function request(path: string, init?: RequestInit) {
  const url = `${workerBaseUrl}${path}`;
  const res = await fetch(url, init);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${init?.method ?? 'GET'} ${url} failed (${res.status}): ${body}`);
  }
  return res.json();
}

async function main() {
  console.info('[smoke] registering identity');
  const pseudonym = `Smoke${Date.now()}`.slice(0, 18);
  const identityRes = await request('/identity/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pseudonym })
  });

  const userId = identityRes.user.id as string;
  assert.ok(userId, 'user id missing');
  const token = identityRes.session?.token as string;
  assert.ok(token, 'session token missing');

  console.info('[smoke] upserting alias');
  const aliasName = `Smoky${Date.now().toString().slice(-4)}`;
  const aliasRes = await request(`/boards/${boardId}/aliases`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ userId, alias: aliasName })
  });
  assert.equal(aliasRes.alias.alias, aliasName);

  console.info('[smoke] creating post');
  const postRes = await request(`/boards/${boardId}/posts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ body: 'Smoke test post', userId })
  });
  assert.equal(postRes.post.alias, aliasName);

  console.info('[smoke] waiting for write to settle');
  await delay(100);

  console.info('[smoke] fetching feed');
  const feedRes = await request(`/boards/${boardId}/feed?limit=1`);
  const [first] = feedRes.posts as Array<{ author: string; body: string; alias: string }>;
  assert(first, 'no posts returned');
  assert.equal(first.alias, aliasName);
  assert.equal(first.body, 'Smoke test post');

  console.info('[smoke] flow verified');
}

main().catch(error => {
  console.error('[smoke] failed', error);
  process.exitCode = 1;
});
