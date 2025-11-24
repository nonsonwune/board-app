'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ProfileSummary } from '@board-app/shared';
import { statusMessages } from '@board-app/shared';
import { Loader2 } from 'lucide-react';
import IdentityPanel from '../../components/identity-panel';
import PostCard from '../../components/feed/post-card';
import { PageShell, PageHeader } from '../../components/page-shell';
import { useIdentityContext } from '../../context/identity-context';
import { formatBoardName } from '../../lib/board';
import { useRouter } from 'next/navigation';

function StatTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-border/60 bg-surface px-4 py-3 text-center">
      <p className="text-xs uppercase tracking-[2px] text-text-tertiary">{label}</p>
      <p className="mt-1 text-lg font-semibold text-text-primary">{value}</p>
    </div>
  );
}

function InfluenceMeter({ value }: { value: number }) {
  const clamped = Math.min(1, Math.max(0, value));
  const percent = Math.round(clamped * 100);
  return (
    <div>
      <div className="flex items-center justify-between text-xs text-text-secondary">
        <span>Influence</span>
        <span>{percent}%</span>
      </div>
      <div className="mt-2 h-2 w-full rounded-full bg-border/60">
        <div
          className="h-full rounded-full bg-primary transition-all"
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}

type HttpError = Error & { status?: number };

function createHttpError(message: string, status?: number): HttpError {
  const error = new Error(message) as HttpError;
  error.status = status;
  return error;
}

export default function ProfilePage() {
  const [workerBaseUrl] = useState(() => process.env.NEXT_PUBLIC_WORKER_BASE_URL ?? 'http://localhost:8788');
  const { identity, session, refreshSession, setSession } = useIdentityContext();
  const router = useRouter();
  const sessionCopy = statusMessages.session;

  const [profile, setProfile] = useState<ProfileSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const buildHeaders = useCallback(() => {
    const headers = new Headers();
    if (session?.token) {
      headers.set('Authorization', `Bearer ${session.token}`);
    }
    return headers;
  }, [session?.token]);

  const fetchProfile = useCallback(
    async (retryCount = 0) => {
      if (!identity?.id || !session?.token) {
        setProfile(null);
        return;
      }
      setLoading(true);
      try {
        const res = await fetch(`${workerBaseUrl}/profiles/${identity.id}`, {
          method: 'GET',
          headers: buildHeaders()
        });

        if (res.status === 401 && retryCount < 1) {
          const refreshed = await refreshSession(workerBaseUrl);
          if (refreshed) {
            return fetchProfile(retryCount + 1);
          }
          setSession(null);
          throw createHttpError(sessionCopy.expired, 401);
        }

        const payload = (await res.json().catch(() => ({}))) as ProfileSummary & { error?: string };
        if (!res.ok || !payload?.ok) {
          throw createHttpError(payload?.error ?? `Failed to load profile (${res.status})`, res.status);
        }

        setProfile(payload);
        setError(null);
      } catch (err) {
        const message = (err as Error).message ?? 'Unable to load profile right now.';
        setError(message);
      } finally {
        setLoading(false);
      }
    },
    [buildHeaders, identity?.id, refreshSession, session?.token, setSession, workerBaseUrl, sessionCopy]
  );

  useEffect(() => {
    if (!identity?.id || !session?.token) {
      setProfile(null);
      return;
    }
    fetchProfile();
  }, [identity?.id, session?.token, fetchProfile]);

  const canManageProfile = Boolean(identity?.id && session?.token);
  const memberSince = useMemo(() => {
    if (!profile) return null;
    const formatter = new Intl.DateTimeFormat(undefined, { month: 'short', year: 'numeric' });
    return formatter.format(new Date(profile.user.createdAt));
  }, [profile]);

  const handleRefresh = () => fetchProfile();

  return (
    <PageShell>
      <div className="space-y-8">
        <PageHeader
          eyebrow="Profile"
          title={profile ? `@${profile.user.pseudonym}` : 'Your profile'}
          description="Manage your pseudonym, aliases, and recent activity across boards."
          actions={
            canManageProfile ? (
              <button
                type="button"
                onClick={handleRefresh}
                className="inline-flex items-center gap-2 rounded-full border border-border/60 px-3 py-1.5 text-xs font-semibold uppercase tracking-[2px] text-text-secondary transition hover:border-primary/50 hover:text-text-primary"
                disabled={loading}
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Refresh
              </button>
            ) : null
          }
        />

        {!canManageProfile ? (
          <div className="rounded-2xl border border-primary/30 bg-primary/5 p-6 text-sm">
            <p className="text-lg font-semibold text-text-primary">Welcome to Board Rooms!</p>
            <p className="mt-2 text-text-secondary">Create your campus identity to get started. It takes less than 30 seconds.</p>
            <div className="mt-4 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => {
                  const identitySection = document.getElementById('identity');
                  if (identitySection) {
                    identitySection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    // Add a subtle highlight animation
                    identitySection.classList.add('ring-2', 'ring-primary', 'ring-offset-2', 'ring-offset-background');
                    setTimeout(() => {
                      identitySection.classList.remove('ring-2', 'ring-primary', 'ring-offset-2', 'ring-offset-background');
                    }, 2000);
                  }
                }}
                className="inline-flex items-center gap-2 rounded-full bg-primary px-6 py-2.5 text-sm font-semibold uppercase tracking-[2px] text-text-inverse transition hover:bg-primary-dark"
              >
                Create Your Identity →
              </button>
              <button
                type="button"
                onClick={() => router.push('/')}
                className="inline-flex items-center gap-2 rounded-full border border-border px-4 py-2 text-xs font-semibold uppercase tracking-[2px] text-text-secondary transition hover:border-primary hover:text-primary"
              >
                Or Explore Boards First
              </button>
            </div>
            <p className="mt-3 text-xs text-text-tertiary">
              ↓ Scroll down to create your identity and choose a pseudonym
            </p>
          </div>
        ) : (
          <div className="space-y-8">
            {error && (
              <div className="rounded-2xl border border-primary/40 bg-primary/10 p-4 text-sm text-primary">
                {error}
              </div>
            )}

            <section className="rounded-2xl border border-border/70 bg-surface-raised/80 p-6 shadow-sm">
              {loading && !profile ? (
                <div className="flex items-center gap-3 text-sm text-text-secondary">
                  <Loader2 className="h-4 w-4 animate-spin" /> Loading profile…
                </div>
              ) : profile ? (
                <>
                  <div className="flex flex-wrap items-start justify-between gap-6">
                    <div>
                      <p className="text-xs uppercase tracking-[2px] text-text-tertiary">Global pseudonym</p>
                      <h2 className="mt-1 text-2xl font-semibold text-text-primary">@{profile.user.pseudonym}</h2>
                      {memberSince && (
                        <p className="mt-1 text-xs text-text-secondary">Member since {memberSince}</p>
                      )}
                    </div>
                    <div className="grid grid-cols-3 gap-3 min-w-[240px]">
                      <StatTile label="Followers" value={profile.user.followerCount.toString()} />
                      <StatTile label="Following" value={profile.user.followingCount.toString()} />
                      <StatTile label="Boards" value={profile.aliases.length.toString()} />
                    </div>
                  </div>
                  <div className="mt-6">
                    <InfluenceMeter value={profile.user.influence} />
                  </div>
                </>
              ) : (
                <p className="text-sm text-text-secondary">Profile data will appear once loaded.</p>
              )}
            </section>

            <section id="aliases" className="rounded-2xl border border-border/70 bg-surface p-6 shadow-sm">
              <h3 className="text-sm font-semibold uppercase tracking-[2px] text-text-tertiary">Board aliases</h3>
              <p className="mt-1 text-xs text-text-secondary">
                Customize how you appear on each board. Aliases help local communities recognize you without revealing your global pseudonym.
              </p>
              <div className="mt-4 flex flex-wrap gap-3">
                {profile && profile.aliases.length > 0 ? (
                  profile.aliases.map(alias => (
                    <div
                      key={`${alias.boardId}:${alias.id}`}
                      className="rounded-full border border-border/60 bg-surface-raised/70 px-4 py-2 text-xs font-medium text-text-secondary"
                    >
                      <span className="text-text-primary">{alias.alias}</span>
                      <span className="ml-2 text-text-tertiary">{formatBoardName(alias.boardId)}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-text-secondary">No aliases yet—set one from a board detail page.</p>
                )}
              </div>
            </section>

            <section id="notifications" className="rounded-2xl border border-border/70 bg-surface p-6 shadow-sm">
              <h3 className="text-sm font-semibold uppercase tracking-[2px] text-text-tertiary">Notifications</h3>
              <p className="mt-1 text-xs text-text-secondary">
                Choose how Board Rooms alerts you when classmates reply or trending posts appear nearby.
              </p>
              <div className="mt-4 space-y-3 text-sm text-text-secondary">
                <p>Push notifications and email digests are rolling out soon. In the meantime, you can opt into realtime banners from each board.</p>
                <button
                  type="button"
                  onClick={() => router.push('/')}
                  className="inline-flex items-center gap-2 rounded-full border border-border/60 px-4 py-2 text-xs font-semibold uppercase tracking-[2px] text-text-secondary transition hover:border-primary/40 hover:text-primary"
                >
                  Manage board alerts
                </button>
              </div>
            </section>

            <section className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold uppercase tracking-[2px] text-text-tertiary">Recent posts</h3>
                {profile && profile.recentPosts.length > 0 ? (
                  <button
                    type="button"
                    onClick={() => router.push('/')}
                    className="text-xs uppercase tracking-[2px] text-primary hover:text-primary-light"
                  >
                    Explore boards
                  </button>
                ) : null}
              </div>
              {profile && profile.recentPosts.length > 0 ? (
                profile.recentPosts.map(post => (
                  <PostCard
                    key={post.id}
                    post={post}
                    boardName={formatBoardName(post.boardId, post.boardName)}
                    disabled
                    disabledReason="Open the board to interact with this post."
                    onOpen={() => router.push(`/boards/${post.boardId}`)}
                  />
                ))
              ) : (
                <div className="rounded-2xl border border-border/60 bg-surface p-6 text-sm text-text-secondary">
                  Posts you share will appear here. Head to a board to start the conversation.
                </div>
              )}
            </section>
          </div>
        )}

        <section className="rounded-2xl border border-border/70 bg-surface p-6 shadow-sm">
          <h3 className="text-sm font-semibold uppercase tracking-[2px] text-text-tertiary">Identity & aliases</h3>
          <p className="mt-1 text-xs text-text-secondary">
            Register or refresh your campus identity, manage per-board aliases, and link Access.
          </p>
          <div className="mt-4">
            <IdentityPanel />
          </div>
        </section>
      </div>
    </PageShell>
  );
}
