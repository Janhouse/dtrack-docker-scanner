/**
 * Health check script for the SBOM Scanner.
 *
 * Checks the connectivity required by the *enabled* sources:
 *   - Docker socket          (when SCAN_DOCKER is on)
 *   - Kubernetes SA token    (when SCAN_KUBERNETES is on)
 */

import { existsSync } from "node:fs";
import { loadConfig } from "./config";

async function checkDocker(): Promise<boolean> {
  try {
    const proc = Bun.spawn(["docker", "info"], {
      stdout: "pipe",
      stderr: "pipe",
    });
    const exitCode = await proc.exited;
    return exitCode === 0;
  } catch {
    return false;
  }
}

function checkKubernetes(): boolean {
  // Cheap liveness signal: the in-cluster service-account token is mounted.
  return existsSync("/var/run/secrets/kubernetes.io/serviceaccount/token");
}

async function main(): Promise<void> {
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
  } catch {
    // Config invalid => unhealthy
    process.exit(1);
  }

  if (config.scanner.scanDocker && !(await checkDocker())) {
    console.error("Docker socket not accessible");
    process.exit(1);
  }

  if (config.scanner.scanKubernetes && !checkKubernetes()) {
    console.error("Kubernetes service-account token not found");
    process.exit(1);
  }

  process.exit(0);
}

main().catch(() => {
  process.exit(1);
});
