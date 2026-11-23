import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";

export function AppLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-forge-bg">
      <Sidebar />
      <main className="min-h-screen md:ml-[238px]">{children}</main>
    </div>
  );
}
