import { PageShell, PageHeader } from '../../components/page-shell';

export const metadata = {
  title: 'Search | Board Rooms'
};

export default function SearchPage() {
  return (
    <PageShell>
      <div className="space-y-8">
        <PageHeader
          eyebrow="Discover"
          title="Search boards"
          description="Find posts, topics, and live threads across the boards you can access."
        />
        <div className="rounded-2xl border border-border/70 bg-surface-raised/80 p-6 text-sm text-text-secondary">
          Search tooling is on the way. In the meantime, jump into a board to explore trending topics.
        </div>
      </div>
    </PageShell>
  );
}
