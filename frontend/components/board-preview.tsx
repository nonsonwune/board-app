'use client';

import Link from 'next/link';

const boards = [
  { id: 'demo-board', name: 'Demo Board' },
  { id: 'campus-north', name: 'Campus North' }
];

export default function BoardPreview() {
  return (
    <div className="min-h-screen bg-slate-950 text-white py-16">
      <div className="mx-auto max-w-3xl px-6">
        <header className="text-center">
          <p className="text-sm uppercase tracking-[3px] text-slate-400">Realtime beta</p>
          <h1 className="mt-4 text-4xl font-semibold">Board Rooms</h1>
          <p className="mt-6 text-slate-300">
            Pick a board to watch live activity. We replay recent events and stream future ones straight from the Worker.
          </p>
        </header>

        <div className="mt-12 grid gap-6 sm:grid-cols-2">
          {boards.map(board => (
            <Link
              key={board.id}
              href={`/boards/${board.id}`}
              className="group rounded-xl border border-slate-800 bg-slate-900/60 p-6 transition hover:border-sky-500/50 hover:bg-slate-900"
            >
              <p className="text-xs uppercase tracking-[2px] text-slate-400">Board</p>
              <p className="mt-2 text-2xl font-semibold text-white">
                {board.name}
              </p>
              <p className="mt-4 text-sm text-slate-400">ws://localhost:8788/boards?boardId={board.id}</p>
              <span className="mt-6 inline-flex items-center gap-2 text-sm font-medium text-sky-400">
                Join live<span aria-hidden>→</span>
              </span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
