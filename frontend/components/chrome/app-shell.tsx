"use client";

import type { ReactNode } from "react";
import { useAppChrome } from "../../context/app-chrome-context";
import TopBar from "./top-bar";
import BottomNav from "./bottom-nav";
import FloatingActionButton from "./floating-action-button";
import AppHeader from "../app-header";

interface AppShellProps {
  children: ReactNode;
}

export default function AppShell({ children }: AppShellProps) {
  const { topBar, fab } = useAppChrome();

  return (
    <div className="flex min-h-screen flex-col bg-background text-text-primary">
      <AppHeader />
      <TopBar state={topBar} />
      <div className="relative flex-1 pb-24 md:pb-0">
        {children}
      </div>
      <BottomNav />
      <FloatingActionButton state={fab} />
    </div>
  );
}
