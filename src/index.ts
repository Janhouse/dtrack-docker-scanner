import { Cron } from "croner";
import {
  DependencyTrackClient,
  DockerClient,
  KubernetesClient,
} from "./clients";
import { type Config, loadConfig, validateConfig } from "./config";
import { logger } from "./logger";
import { Scanner } from "./scanner";

async function testConnections(
  config: Config,
  dtrack: DependencyTrackClient,
  docker: DockerClient,
  kubernetes: KubernetesClient | null,
): Promise<boolean> {
  // Test Docker socket (only if docker scanning is enabled)
  if (config.scanner.scanDocker) {
    if (!(await docker.testConnection())) {
      logger.error("Cannot connect to Docker socket");
      return false;
    }
    logger.success("Docker connection OK");
  }

  // Test Kubernetes API (only if k8s scanning is enabled)
  if (kubernetes) {
    if (!(await kubernetes.testConnection())) {
      logger.error("Cannot connect to Kubernetes API");
      return false;
    }
    logger.success("Kubernetes connection OK");
  }

  // Test Dependency-Track
  if (!(await dtrack.testConnection())) {
    logger.error("Cannot connect to Dependency-Track");
    return false;
  }
  logger.success("Dependency-Track connection OK");

  return true;
}

async function main(): Promise<void> {
  logger.section("Docker SBOM Scanner");

  // Load and validate config
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
    validateConfig(config);
  } catch (err) {
    logger.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  logger.info(`Dependency-Track URL: ${config.dtrack.url}`);
  logger.info(`Scan interval: ${config.scanner.cronSchedule}`);
  logger.info(`Concurrency: ${config.scanner.concurrency}`);
  logger.info(
    `Sources: docker=${config.scanner.scanDocker} kubernetes=${config.scanner.scanKubernetes}`,
  );
  if (config.scanner.scanKubernetes) {
    logger.info(
      `Kubernetes node: ${config.kubernetes.nodeName || "<all>"} | image-src: ${config.kubernetes.trivyImageSrc}`,
    );
  }
  logger.info(`Watch Docker events: ${config.scanner.watchDocker}`);
  logger.info(`Cache TTL: ${config.scanner.cacheTtlMinutes} minutes`);
  logger.info(`Inactive after: ${config.scanner.inactiveAfterMinutes} minutes`);
  logger.info(
    `Initial cleanup delay: ${config.scanner.initialCleanupDelayMinutes} minutes`,
  );

  // Test connections
  const dtrack = new DependencyTrackClient(
    config.dtrack.url,
    config.dtrack.apiKey,
  );
  const docker = new DockerClient();
  const kubernetes = config.scanner.scanKubernetes
    ? new KubernetesClient({
        nodeName: config.kubernetes.nodeName,
        namespaces: config.kubernetes.namespaces,
      })
    : null;

  if (!(await testConnections(config, dtrack, docker, kubernetes))) {
    process.exit(1);
  }

  logger.success("Connection tests passed");

  // Create scanner instance
  const scanner = new Scanner(config);

  // Start Docker event listener if enabled (docker source only)
  if (config.scanner.scanDocker && config.scanner.watchDocker) {
    logger.info("Starting Docker event listener...");
    scanner.getDockerClient().startEventListener((event) => {
      if (event.action === "start") {
        // Handle container start events asynchronously
        scanner.handleContainerStart(event).catch((err) => {
          logger.error(
            `Error handling container start for ${event.image}:`,
            err instanceof Error ? err.message : String(err),
          );
        });
      } else if (event.action === "stop" || event.action === "die") {
        // Handle container stop/die events synchronously
        scanner.handleContainerStop(event);
      }
    });
    logger.success("Docker event listener started");
  }

  // Run initial scan if requested
  if (config.scanner.scanOnStart) {
    logger.info("Running initial scan (cleanup delayed)...");
    try {
      // Skip cleanup on initial scan - schedule it for later
      // This prevents deleting projects for containers that haven't started yet
      await scanner.run(true);

      // Schedule cleanup after delay to allow other containers to start
      scanner.scheduleDelayedCleanup(config.scanner.initialCleanupDelayMinutes);
    } catch (err) {
      logger.error(
        "Initial scan failed:",
        err instanceof Error ? err.message : String(err),
      );
      // Continue to scheduler even if initial scan fails
    }
  }

  // Set up cron scheduler
  logger.info("Starting cron scheduler...");
  logger.info(`Schedule: ${config.scanner.cronSchedule}`);

  const job = new Cron(config.scanner.cronSchedule, async () => {
    logger.info("Scheduled scan triggered");
    try {
      await scanner.run();
    } catch (err) {
      logger.error(
        "Scheduled scan failed:",
        err instanceof Error ? err.message : String(err),
      );
    }
  });

  // Log next scheduled run
  const nextRun = job.nextRun();
  if (nextRun) {
    logger.info(`Next scan scheduled for: ${nextRun.toISOString()}`);
  }

  // Start periodic checker for inactive container marking (every 5 minutes)
  let inactiveChecker: ReturnType<typeof setInterval> | null = null;
  if (config.scanner.scanDocker && config.scanner.watchDocker) {
    inactiveChecker = setInterval(
      async () => {
        try {
          await scanner.checkStoppedContainers();
        } catch (err) {
          logger.error(
            "Error checking stopped containers:",
            err instanceof Error ? err.message : String(err),
          );
        }
      },
      5 * 60 * 1000,
    ); // Every 5 minutes
    logger.info("Started inactive container checker (runs every 5 minutes)");
  }

  // Keep process running
  logger.info("Scanner is running. Press Ctrl+C to stop.");

  // Graceful shutdown handler
  const shutdown = () => {
    logger.info("Shutting down...");
    job.stop();
    if (inactiveChecker) {
      clearInterval(inactiveChecker);
    }
    if (config.scanner.scanDocker && config.scanner.watchDocker) {
      scanner.getDockerClient().stopEventListener();
    }
    logger.info(`Cache size at shutdown: ${scanner.getCacheSize()} entries`);
    logger.info(
      `Stopped containers tracked: ${scanner.getStoppedContainersCount()}`,
    );
    process.exit(0);
  };

  // Handle graceful shutdown
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  // Keep the process alive
  await new Promise(() => {});
}

main().catch((err) => {
  logger.error(
    "Fatal error:",
    err instanceof Error ? err.message : String(err),
  );
  process.exit(1);
});
