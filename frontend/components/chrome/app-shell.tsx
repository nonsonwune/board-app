"use client";

import type { ReactNode } from "react";
import { useAppChrome } from "../../context/app-chrome-context";
import TopBar from "./top-bar";
import BottomNav from "./bottom-nav";
import FloatingActionButton from "./floating-action-button";

interface AppShellProps {
  children: ReactNode;
}

export default function AppShell({ children }: AppShellProps) {
  const { topBar, fab } = useAppChrome();

  return (
    <div className="flex min-h-screen flex-col bg-background text-text-primary">
      <TopBar state={topBar} />
      <div className="relative flex-1 pb-[120px]">
        {children}
      </div>
      <BottomNav />
      <FloatingActionButton state={fab} />
    </div>
  );
}
