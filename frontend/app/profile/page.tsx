import IdentityPanel from '../../components/identity-panel';

export const metadata = {
  title: 'Profile | Board Rooms'
};

export default function ProfilePage() {
  return (
    <div className="min-h-screen bg-slate-950 py-12">
      <div className="mx-auto max-w-3xl px-6 text-slate-100">
        <h1 className="text-3xl font-semibold">Identity &amp; Aliases</h1>
        <p className="mt-2 text-sm text-slate-400">
          Manage your global pseudonym and per-board aliases used across the Board Rooms preview UI.
        </p>
        <div className="mt-10">
          <IdentityPanel />
        </div>
      </div>
    </div>
  );
}
