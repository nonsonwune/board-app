import { PageShell, PageHeader } from '../../components/page-shell';

export const metadata = {
  title: 'Following | Board Rooms'
};

export default function FollowingPage() {
  return (
    <PageShell>
      <div className="space-y-8">
        <PageHeader
          eyebrow="Following"
          title="Voices you follow"
          description="Cross-board feed pulling in the latest posts from identities you trust."
        />
        <div className="rounded-2xl border border-border/70 bg-surface-raised/80 p-6 text-sm text-text-secondary">
          Following feed is coming soon. For now, follow authors from board posts to curate your stream.
        </div>
      </div>
    </PageShell>
  );
}
