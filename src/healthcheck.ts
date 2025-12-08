/**
 * Health check script for the Docker SBOM Scanner
 *
 * Checks:
 * 1. Docker socket is accessible
 */

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

async function main(): Promise<void> {
  // Check Docker socket
  if (!(await checkDocker())) {
    console.error("Docker socket not accessible");
    process.exit(1);
  }

  process.exit(0);
}

main().catch(() => {
  process.exit(1);
});
