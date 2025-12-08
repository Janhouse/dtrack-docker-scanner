import { hostname } from "node:os";

export interface Config {
  dtrack: {
    url: string;
    apiKey: string;
    parentProject: string;
  };
  scanner: {
    hostname: string;
    cronSchedule: string;
    scanOnStart: boolean;
    excludeImages: string[];
    cleanupStale: boolean;
    concurrency: number;
    watchDocker: boolean;
    cacheTtlMinutes: number;
    inactiveAfterMinutes: number;
    initialCleanupDelayMinutes: number;
  };
}

function getEnv(key: string, defaultValue?: string): string {
  const value = process.env[key];
  if (value === undefined || value === "") {
    if (defaultValue !== undefined) {
      return defaultValue;
    }
    throw new Error(`Required environment variable ${key} is not set`);
  }
  return value;
}

function getEnvBool(key: string, defaultValue: boolean): boolean {
  const value = process.env[key]?.toLowerCase();
  if (value === undefined || value === "") {
    return defaultValue;
  }
  return value === "true" || value === "1" || value === "yes";
}

function getEnvInt(key: string, defaultValue: number): number {
  const value = process.env[key];
  if (value === undefined || value === "") {
    return defaultValue;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? defaultValue : parsed;
}

function getEnvList(key: string, defaultValue: string[] = []): string[] {
  const value = process.env[key];
  if (value === undefined || value === "") {
    return defaultValue;
  }
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function loadConfig(): Config {
  return {
    dtrack: {
      url: getEnv("DTRACK_URL"),
      apiKey: getEnv("DTRACK_API_KEY"),
      parentProject: getEnv("DTRACK_PARENT_PROJECT", "").trim(),
    },
    scanner: {
      hostname: getEnv("SCANNER_HOSTNAME", hostname()),
      cronSchedule: getEnv("SCAN_INTERVAL", "0 */6 * * *"),
      scanOnStart: getEnvBool("SCAN_ON_START", true),
      excludeImages: getEnvList("EXCLUDE_IMAGES"),
      cleanupStale: getEnvBool("CLEANUP_STALE", true),
      concurrency: getEnvInt("SCAN_CONCURRENCY", 2),
      watchDocker: getEnvBool("WATCH_DOCKER", true),
      cacheTtlMinutes: getEnvInt("CACHE_TTL_MINUTES", 60),
      inactiveAfterMinutes: getEnvInt("INACTIVE_AFTER_MINUTES", 60),
      initialCleanupDelayMinutes: getEnvInt("INITIAL_CLEANUP_DELAY_MINUTES", 3),
    },
  };
}

export function validateConfig(config: Config): void {
  if (!config.dtrack.url.startsWith("http")) {
    throw new Error("DTRACK_URL must be a valid HTTP(S) URL");
  }

  if (config.dtrack.apiKey.length < 10) {
    throw new Error("DTRACK_API_KEY appears to be invalid (too short)");
  }
}
