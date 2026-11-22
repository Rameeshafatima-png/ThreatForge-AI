function getApiBaseUrl(): string {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim();
  if (!configuredUrl) {
    throw new Error(
      "NEXT_PUBLIC_API_URL is not configured. Set it to the deployed ThreatForge backend URL.",
    );
  }
  return configuredUrl.replace(/\/+$/, "");
}

export function apiUrl(path: string): string {
  const normalizedPath = path.replace(/^\/+/, "");
  return `${getApiBaseUrl()}/${normalizedPath}`;
}
