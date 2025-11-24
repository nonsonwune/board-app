"use client";

import { Bell } from "lucide-react";
import Link from "next/link";

export default function NotificationsPage() {
    return (
        <div className="container mx-auto max-w-2xl px-4 py-8">
            <div className="mb-8 flex items-center justify-between">
                <h1 className="text-2xl font-bold text-text-primary">Notifications</h1>
                <Link href="/profile#notifications" className="text-xs font-medium text-primary hover:underline">
                    Settings
                </Link>
            </div>

            <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-border py-16 text-center">
                <div className="mb-4 rounded-full bg-surface-raised p-4">
                    <Bell className="h-8 w-8 text-text-tertiary" />
                </div>
                <h2 className="text-lg font-medium text-text-primary">All caught up</h2>
                <p className="mt-2 text-sm text-text-secondary max-w-xs">
                    When you get replies or reactions, they&apos;ll show up here.
                </p>
            </div>
        </div>
    );
}
