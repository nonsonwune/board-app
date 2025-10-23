"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Home, Search, User, Users } from "lucide-react";
import type { ComponentType } from "react";

interface NavItem {
  href: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
}

const NAV_ITEMS: NavItem[] = [
  { href: "/", label: "Home", icon: Home },
  { href: "/following", label: "Following", icon: Users },
  { href: "/search", label: "Search", icon: Search },
  { href: "/profile", label: "You", icon: User }
];

function isActivePath(pathname: string | null, href: string) {
  if (!pathname) return false;
  if (href === "/") {
    return pathname === "/";
  }
  return pathname.startsWith(href);
}

export default function BottomNav() {
  const pathname = usePathname();

  return (
    <nav className="fixed inset-x-0 bottom-0 z-40 border-t border-border/60 bg-surface/95 backdrop-blur supports-[backdrop-filter]:bg-surface/80">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-2.5 sm:px-6">
        {NAV_ITEMS.map(item => {
          const active = isActivePath(pathname, item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex flex-col items-center gap-1 rounded-full px-3 py-2 text-xs font-medium uppercase tracking-[1.5px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 ${
                active ? "text-primary" : "text-text-tertiary hover:text-text-secondary"
              }`}
            >
              <Icon className="h-5 w-5" aria-hidden />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </div>
      <div className="h-[calc(env(safe-area-inset-bottom,_0px))]" />
    </nav>
  );
}
