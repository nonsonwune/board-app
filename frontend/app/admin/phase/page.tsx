import PhaseAdminPanel from '../../../components/phase-admin-panel';
import { PageShell, PageHeader } from '../../../components/page-shell';

export default function PhaseAdminPage() {
  return (
    <PageShell>
      <div className="space-y-10">
        <PageHeader
          eyebrow="Launch Controls"
          title="Phase 1 Configuration"
          description="Lock boards into Phase 1 fixed radius and text-only modes before rolling new cohorts."
        />
        <PhaseAdminPanel />
      </div>
    </PageShell>
  );
}
