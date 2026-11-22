import { AppLayout } from "../components/AppLayout";

export default function Settings() {
  return (
    <AppLayout>
      <header className="flex h-16 items-center border-b border-forge-border px-6 md:px-8">
        <div>
          <p className="text-[10px] uppercase tracking-[0.18em] text-forge-muted">Configuration</p>
          <p className="mt-0.5 text-[13px] font-medium">Settings</p>
        </div>
      </header>
      <div className="mx-auto max-w-[760px] px-6 py-10 md:px-8">
        <section className="border-b border-forge-border py-5">
          <p className="text-[10px] uppercase tracking-[0.16em] text-forge-gold">Threat intelligence</p>
          <p className="mt-2 text-[13px]">Optional provider connections</p>
          <p className="mt-1.5 text-xs leading-5 text-forge-muted">Configure API credentials in the server environment. No provider is active until credentials are supplied.</p>
        </section>
        <section className="border-b border-forge-border py-5">
          <p className="text-[10px] uppercase tracking-[0.16em] text-forge-muted">Execution</p>
          <p className="mt-2 text-[13px]">Investigation pipeline</p>
          <p className="mt-1.5 text-xs leading-5 text-forge-muted">Foundation stage: execution is not currently enabled.</p>
        </section>
      </div>
    </AppLayout>
  );
}
