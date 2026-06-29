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
    // Sources to scan. Docker stays on by default (backward compatible);
    // Kubernetes is opt-in (intended for a DaemonSet in a k8s cluster).
    scanDocker: boolean;
    scanKubernetes: boolean;
  };
  kubernetes: {
    // Restrict to pods on this node (set from the downward API in a DaemonSet).
    nodeName: string;
    // Only scan these namespaces (empty => all visible to the token).
    namespaces: string[];
    // Trivy image source for k8s images: "containerd" (default; scans images
    // already on the node via the containerd socket, no registry creds needed)
    // or "remote" (pull from the registry).
    trivyImageSrc: string;
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
      hostname: getEnv(
        "SCANNER_HOSTNAME",
        process.env.KUBE_NODE_NAME?.trim() || hostname(),
      ),
      cronSchedule: getEnv("SCAN_INTERVAL", "0 */6 * * *"),
      scanOnStart: getEnvBool("SCAN_ON_START", true),
      excludeImages: getEnvList("EXCLUDE_IMAGES"),
      cleanupStale: getEnvBool("CLEANUP_STALE", true),
      concurrency: getEnvInt("SCAN_CONCURRENCY", 2),
      watchDocker: getEnvBool("WATCH_DOCKER", true),
      cacheTtlMinutes: getEnvInt("CACHE_TTL_MINUTES", 60),
      inactiveAfterMinutes: getEnvInt("INACTIVE_AFTER_MINUTES", 60),
      initialCleanupDelayMinutes: getEnvInt("INITIAL_CLEANUP_DELAY_MINUTES", 3),
      scanDocker: getEnvBool("SCAN_DOCKER", true),
      scanKubernetes: getEnvBool("SCAN_KUBERNETES", false),
    },
    kubernetes: {
      nodeName: getEnv("KUBE_NODE_NAME", "").trim(),
      namespaces: getEnvList("KUBE_NAMESPACES"),
      trivyImageSrc: getEnv("TRIVY_K8S_IMAGE_SRC", "containerd,remote").trim(),
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

  if (!config.scanner.scanDocker && !config.scanner.scanKubernetes) {
    throw new Error(
      "At least one of SCAN_DOCKER or SCAN_KUBERNETES must be enabled",
    );
  }
}
