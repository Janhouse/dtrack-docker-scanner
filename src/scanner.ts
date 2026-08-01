import { ImageCache } from "./cache";
import {
  DependencyTrackClient,
  DockerClient,
  type DockerEvent,
  getBaseName,
  KubernetesClient,
  parseImageRef,
} from "./clients";
import type { Config } from "./config";
import { logger } from "./logger";
import { cleanupSbomFile, generateSbom, readSbomAsBase64 } from "./sbom";
import type { DTrackProject, ImageScanResult } from "./types";

// DependencyTrack tags identifying which scanner manages a project. Cleanup is
// scoped per-source so the Docker and Kubernetes passes never delete each other's
// projects.
const DOCKER_MARKER = "docker-scanner";
const K8S_MARKER = "k8s-scanner";

interface ScanStats {
  total: number;
  success: number;
  failed: number;
  skipped: number;
  cached: number;
}

interface StoppedContainer {
  imageId: string;
  image: string;
  stoppedAt: number;
}

export class Scanner {
  private readonly config: Config;
  private readonly dtrack: DependencyTrackClient;
  private readonly docker: DockerClient;
  private readonly kubernetes: KubernetesClient | null;
  private readonly cache: ImageCache;
  private readonly uploadedVersions: Set<string> = new Set();
  private readonly stoppedContainers: Map<string, StoppedContainer> = new Map();
  private isScanning = false;
  private isEventScanning = false;
  private eventScanQueue: ImageScanResult[] = [];

  constructor(config: Config) {
    this.config = config;
    this.dtrack = new DependencyTrackClient(
      config.dtrack.url,
      config.dtrack.apiKey,
    );
    this.docker = new DockerClient();
    this.kubernetes = config.scanner.scanKubernetes
      ? new KubernetesClient({
          nodeName: config.kubernetes.nodeName,
          namespaces: config.kubernetes.namespaces,
        })
      : null;
    this.cache = new ImageCache(config.scanner.cacheTtlMinutes);
  }

  /**
   * Trivy options for an image, based on which source it came from. Kubernetes
   * images are read from the node's image store (default: containerd).
   */
  private sbomOptsFor(container: ImageScanResult): { imageSrc?: string } {
    if (
      container.source === "kubernetes" &&
      this.config.kubernetes.trivyImageSrc
    ) {
      return { imageSrc: this.config.kubernetes.trivyImageSrc };
    }
    return {};
  }

  /**
   * Collect images to scan from every enabled source (docker + kubernetes).
   */
  private async collectImages(): Promise<ImageScanResult[]> {
    const images: ImageScanResult[] = [];
    if (this.config.scanner.scanDocker) {
      const docker = await this.docker.getRunningContainers();
      logger.info(`Docker: ${docker.length} running image(s)`);
      images.push(...docker);
    }
    if (this.kubernetes) {
      const k8s = await this.kubernetes.getRunningImages();
      logger.info(`Kubernetes: ${k8s.length} pod image(s)`);
      images.push(...k8s);
    }
    return images;
  }

  /**
   * Get the Docker client for event listening
   */
  getDockerClient(): DockerClient {
    return this.docker;
  }

  /**
   * Handle a Docker container start event
   */
  async handleContainerStart(event: DockerEvent): Promise<void> {
    // Check if image is excluded
    if (this.isExcluded(event.image)) {
      logger.debug(`Skipping excluded image from event: ${event.image}`);
      return;
    }

    // Get full image info
    const imageId =
      event.imageId || (await this.docker.getImageId(event.image)) || "";

    // Remove from stopped containers if it was there (container restarted)
    if (imageId && this.stoppedContainers.has(imageId)) {
      logger.debug(
        `Container restarted, removing from stopped list: ${event.image}`,
      );
      this.stoppedContainers.delete(imageId);
    }

    // Check local cache
    if (imageId && this.cache.has(imageId)) {
      logger.debug(
        `Skipping recently scanned image: ${event.image} (${imageId})`,
      );
      // Look up project in DTrack to track for cleanup and reactivate if needed
      const cachedProject = await this.dtrack.findProjectByImageHash(imageId);
      if (cachedProject) {
        const lookupKey = `${cachedProject.name}:${cachedProject.version}`;
        this.uploadedVersions.add(lookupKey);
        if (cachedProject.active === false) {
          logger.info(`Reactivating project: ${event.image}`);
          await this.dtrack.setProjectActive(cachedProject.uuid, true);
        }
      }
      return;
    }

    // Check Dependency-Track for existing SBOM with this image hash
    if (imageId) {
      const existingProject = await this.dtrack.findProjectByImageHash(imageId);
      if (existingProject) {
        logger.debug(
          `Skipping image (SBOM exists in Dependency-Track): ${event.image}`,
        );
        // Add to local cache
        const { name, tag } = parseImageRef(event.image);
        this.cache.set(imageId, name, tag);

        // Track for cleanup - use project name/version from DTrack
        const lookupKey = `${existingProject.name}:${existingProject.version}`;
        this.uploadedVersions.add(lookupKey);

        // Reactivate if it was marked inactive
        if (existingProject.active === false) {
          logger.info(`Reactivating project: ${event.image}`);
          await this.dtrack.setProjectActive(existingProject.uuid, true);
        }
        return;
      }
    }

    logger.info(`New container detected: ${event.image}`);

    const { name, tag } = parseImageRef(event.image);

    const scanResult: ImageScanResult = {
      image: event.image,
      imageName: name,
      imageTag: tag,
      imageId,
      composeProjects: event.composeProject ? [event.composeProject] : [],
    };

    // Always queue event-driven scans to ensure sequential trivy execution
    this.eventScanQueue.push(scanResult);

    // Start processing queue if not already running and no main scan in progress
    if (!this.isEventScanning && !this.isScanning) {
      this.processEventScanQueue();
    }
  }

  /**
   * Process the event scan queue sequentially
   */
  private async processEventScanQueue(): Promise<void> {
    if (this.isEventScanning || this.isScanning) {
      return;
    }

    this.isEventScanning = true;

    try {
      while (this.eventScanQueue.length > 0 && !this.isScanning) {
        const container = this.eventScanQueue.shift();
        if (container) {
          await this.scanSingleImage(container);
        }
      }
    } finally {
      this.isEventScanning = false;
    }
  }

  /**
   * Handle a Docker container stop/die event
   */
  handleContainerStop(event: DockerEvent): void {
    // Check if image is excluded
    if (this.isExcluded(event.image)) {
      return;
    }

    const imageId = event.imageId;
    if (!imageId) {
      logger.debug(`Stop event without imageId: ${event.image}`);
      return;
    }

    // Record the stop time
    if (!this.stoppedContainers.has(imageId)) {
      logger.debug(`Container stopped: ${event.image} (${imageId})`);
      this.stoppedContainers.set(imageId, {
        imageId,
        image: event.image,
        stoppedAt: Date.now(),
      });
    }
  }

  /**
   * Check stopped containers and mark inactive after timeout
   */
  async checkStoppedContainers(): Promise<void> {
    const now = Date.now();
    const timeoutMs = this.config.scanner.inactiveAfterMinutes * 60 * 1000;

    for (const [imageId, container] of this.stoppedContainers) {
      const elapsed = now - container.stoppedAt;
      if (elapsed >= timeoutMs) {
        logger.info(
          `Marking project inactive (stopped ${Math.round(elapsed / 60000)} min): ${container.image}`,
        );

        const success = await this.dtrack.setProjectActiveByImageHash(
          imageId,
          false,
        );
        if (success) {
          logger.success(`Project marked inactive: ${container.image}`);
        }

        // Remove from tracking regardless of success
        this.stoppedContainers.delete(imageId);
      }
    }
  }

  /**
   * Get count of stopped containers being tracked
   */
  getStoppedContainersCount(): number {
    return this.stoppedContainers.size;
  }

  /**
   * Scan a single image (used for event-driven scans)
   */
  private async scanSingleImage(container: ImageScanResult): Promise<boolean> {
    // Check cache again (might have been scanned while queued)
    if (container.imageId && this.cache.has(container.imageId)) {
      logger.debug(`Skipping cached image: ${container.image}`);
      return true;
    }

    logger.info(`Scanning: ${container.image}`);

    // Generate SBOM
    const sbomResult = await generateSbom(
      container.image,
      this.sbomOptsFor(container),
    );
    if (!sbomResult.success || !sbomResult.filePath) {
      logger.error(`Failed to generate SBOM: ${sbomResult.error}`);
      return false;
    }

    // Upload to Dependency-Track
    const uploaded = await this.uploadSbom(container, sbomResult.filePath);

    // Cleanup temp file
    await cleanupSbomFile(sbomResult.filePath);

    return uploaded;
  }

  /**
   * Run a full scan cycle
   * @param skipCleanup - If true, skip the cleanup phase (for initial scan with delayed cleanup)
   */
  async run(skipCleanup = false): Promise<void> {
    if (this.isScanning) {
      logger.warn("Scan already in progress, skipping");
      return;
    }

    this.isScanning = true;

    try {
      logger.section("Starting SBOM scan");
      logger.info(`Host: ${this.config.scanner.hostname}`);
      logger.info(
        `Parent project: ${this.config.dtrack.parentProject || "<none>"}`,
      );
      logger.info(`Cleanup stale: ${this.config.scanner.cleanupStale}`);
      logger.info(`Concurrency: ${this.config.scanner.concurrency}`);

      // Clear tracked uploads for this scan cycle (only if not skipping cleanup)
      // When skipping cleanup, we keep the uploads to accumulate during the delay
      if (!skipCleanup) {
        this.uploadedVersions.clear();
      }

      // Ensure parent project exists
      if (this.config.dtrack.parentProject) {
        const parent = await this.dtrack.ensureParentProject(
          this.config.dtrack.parentProject,
          this.config.scanner.hostname,
        );
        if (!parent) {
          logger.error("Failed to ensure parent project exists, aborting");
          return;
        }
        logger.success("Parent project ready");
      }

      // Get running images from every enabled source (docker + kubernetes)
      const containers = await this.collectImages();

      if (containers.length === 0) {
        logger.info("No running images found");
        if (this.config.scanner.cleanupStale && !skipCleanup) {
          await this.cleanupAllSources();
        }
        return;
      }

      // Scan containers in parallel batches
      const stats = await this.scanContainersParallel(containers);

      logger.section("Scan complete");
      logger.info(
        `Total: ${stats.total} | Success: ${stats.success} | Failed: ${stats.failed} | Skipped: ${stats.skipped} | Cached: ${stats.cached}`,
      );

      // Cleanup stale projects (sequential) - skip if requested
      if (this.config.scanner.cleanupStale && !skipCleanup) {
        await this.cleanupAllSources();
      }
    } finally {
      this.isScanning = false;
    }

    // Process any queued event scans that came in during the main scan
    if (this.eventScanQueue.length > 0) {
      logger.info(
        `Processing ${this.eventScanQueue.length} queued event scans...`,
      );
      await this.processEventScanQueue();
    }
  }

  /**
   * Schedule delayed cleanup after initial scan
   * This allows time for other containers to start and be scanned
   */
  scheduleDelayedCleanup(delayMinutes: number): void {
    if (!this.config.scanner.cleanupStale) {
      logger.info("Cleanup disabled, skipping delayed cleanup");
      return;
    }

    const delayMs = delayMinutes * 60 * 1000;
    logger.info(`Scheduling cleanup in ${delayMinutes} minutes...`);

    setTimeout(async () => {
      logger.section("Running delayed cleanup");
      try {
        await this.cleanupAllSources();
        // Clear uploadedVersions after delayed cleanup completes
        this.uploadedVersions.clear();
      } catch (err) {
        logger.error(
          "Delayed cleanup failed:",
          err instanceof Error ? err.message : String(err),
        );
      }
    }, delayMs);
  }

  /**
   * Scan containers in parallel with concurrency limit
   */
  private async scanContainersParallel(
    containers: ImageScanResult[],
  ): Promise<ScanStats> {
    const stats: ScanStats = {
      total: 0,
      success: 0,
      failed: 0,
      skipped: 0,
      cached: 0,
    };

    // Filter out excluded and cached images
    const toScan: ImageScanResult[] = [];

    for (const container of containers) {
      stats.total++;

      // Check exclusions
      if (this.isExcluded(container.image)) {
        logger.info(`Skipping excluded image: ${container.image}`);
        stats.skipped++;
        continue;
      }

      // Check local cache
      if (container.imageId && this.cache.has(container.imageId)) {
        logger.info(`Skipping cached image: ${container.image}`);
        stats.cached++;
        // Still track for cleanup
        const projectName = this.buildProjectName(container);
        this.uploadedVersions.add(`${projectName}:${container.imageTag}`);
        continue;
      }

      // Check Dependency-Track for existing SBOM with this image hash
      if (container.imageId) {
        const existsInDtrack = await this.dtrack.hasProjectWithImageHash(
          container.imageId,
        );
        if (existsInDtrack) {
          logger.info(
            `Skipping image (SBOM exists in Dependency-Track): ${container.image}`,
          );
          stats.cached++;
          // Add to local cache and track for cleanup
          const projectName = this.buildProjectName(container);
          this.cache.set(container.imageId, projectName, container.imageTag);
          this.uploadedVersions.add(`${projectName}:${container.imageTag}`);
          continue;
        }
      }

      toScan.push(container);
    }

    if (toScan.length === 0) {
      logger.info("No new images to scan");
      return stats;
    }

    logger.info(
      `Scanning ${toScan.length} images (upload concurrency: ${this.config.scanner.concurrency})`,
    );

    // Producer-consumer pattern:
    // - Producer: Sequential SBOM generation (trivy uses shared cache)
    // - Consumer: Parallel upload workers

    const uploadQueue: Array<{
      container: ImageScanResult;
      sbomPath: string;
    }> = [];
    const activeUploads: Promise<boolean>[] = [];
    let scanningDone = false;

    // Upload worker - processes queue items
    const processUpload = async (
      container: ImageScanResult,
      sbomPath: string,
    ): Promise<boolean> => {
      const result = await this.uploadSbom(container, sbomPath);
      await cleanupSbomFile(sbomPath);
      return result;
    };

    // Start upload consumer loop
    const uploadConsumer = async (): Promise<void> => {
      while (
        !scanningDone ||
        uploadQueue.length > 0 ||
        activeUploads.length > 0
      ) {
        // Start new uploads if we have capacity and items in queue
        while (
          activeUploads.length < this.config.scanner.concurrency &&
          uploadQueue.length > 0
        ) {
          const task = uploadQueue.shift();
          if (task) {
            const uploadPromise = processUpload(task.container, task.sbomPath)
              .then((result) => {
                if (result) {
                  stats.success++;
                } else {
                  stats.failed++;
                }
                // Remove from active uploads
                const idx = activeUploads.indexOf(uploadPromise);
                if (idx >= 0) activeUploads.splice(idx, 1);
                return result;
              })
              .catch(() => {
                stats.failed++;
                const idx = activeUploads.indexOf(uploadPromise);
                if (idx >= 0) activeUploads.splice(idx, 1);
                return false;
              });
            activeUploads.push(uploadPromise);
          }
        }

        // Wait a bit before checking again, or wait for an upload to complete
        if (activeUploads.length > 0) {
          await Promise.race([
            Promise.race(activeUploads),
            new Promise((r) => setTimeout(r, 100)),
          ]);
        } else if (!scanningDone) {
          await new Promise((r) => setTimeout(r, 50));
        }
      }
    };

    // Start consumer in background
    const consumerPromise = uploadConsumer();

    // Producer: Generate SBOMs sequentially and queue for upload
    for (const container of toScan) {
      logger.info(`Generating SBOM: ${container.image}`);

      const sbomResult = await generateSbom(
        container.image,
        this.sbomOptsFor(container),
      );
      if (!sbomResult.success || !sbomResult.filePath) {
        logger.error(`Failed to generate SBOM: ${sbomResult.error}`);
        stats.failed++;
        continue;
      }

      // Add to upload queue
      uploadQueue.push({ container, sbomPath: sbomResult.filePath });
    }

    // Signal that scanning is done
    scanningDone = true;

    // Wait for all uploads to complete
    await consumerPromise;

    return stats;
  }

  /**
   * Build project name from container info
   */
  private buildProjectName(container: ImageScanResult): string {
    const { imageName, composeProjects } = container;
    return composeProjects.length > 0
      ? `${composeProjects[0]}/${imageName}`
      : imageName;
  }

  /**
   * Upload SBOM to Dependency-Track
   */
  private async uploadSbom(
    container: ImageScanResult,
    sbomPath: string,
  ): Promise<boolean> {
    const { imageName, imageTag, imageId, composeProjects } = container;
    const baseName = getBaseName(imageName);
    const projectName = this.buildProjectName(container);
    const projectVersion = imageTag;

    logger.info(
      `Uploading SBOM for ${projectName}:${projectVersion} (compose: ${
        composeProjects.join(", ") || "none"
      })`,
    );

    // Find existing versions BEFORE uploading
    const existingProjects = await this.dtrack.findProjectsByName(projectName);
    const oldVersions = existingProjects.filter(
      (p) => p.version !== projectVersion,
    );

    // Build tags (source-specific marker + grouping tag)
    const isK8s = container.source === "kubernetes";
    const tags = [
      baseName,
      `host:${this.config.scanner.hostname}`,
      isK8s ? K8S_MARKER : DOCKER_MARKER,
      ...(isK8s
        ? (container.namespaces ?? []).map((n) => `namespace:${n}`)
        : composeProjects.map((p) => `compose:${p}`)),
      ...(imageId ? [`imageid:${imageId}`] : []),
    ];

    // Read and encode SBOM
    const bomBase64 = await readSbomAsBase64(sbomPath);

    // Upload to Dependency-Track
    const token = await this.dtrack.uploadBom(
      projectName,
      projectVersion,
      bomBase64,
      tags,
      this.config.dtrack.parentProject || undefined,
    );

    if (!token) {
      return false;
    }

    logger.success(`Uploaded successfully (token: ${token})`);

    // Track this upload for cleanup phase
    this.uploadedVersions.add(`${projectName}:${projectVersion}`);

    // Cache the image ID
    if (imageId) {
      this.cache.set(imageId, projectName, projectVersion);
    }

    // Wait for BOM processing and clone analysis from old versions
    logger.indent("Waiting for BOM processing...");

    if (await this.dtrack.waitForBomProcessing(token)) {
      const newProject = await this.dtrack.lookupProject(
        projectName,
        projectVersion,
      );

      if (newProject && oldVersions.length > 0) {
        await this.cloneAndCleanupOldVersions(newProject.uuid, oldVersions);
      }
    }

    return true;
  }

  /**
   * Clone analysis decisions from old versions and delete them
   */
  private async cloneAndCleanupOldVersions(
    newUuid: string,
    oldVersions: DTrackProject[],
  ): Promise<void> {
    for (const oldProject of oldVersions) {
      logger.indent(`Cloning analysis from ${oldProject.version}...`);

      if (await this.dtrack.cloneAnalysisDecisions(oldProject.uuid, newUuid)) {
        logger.indentSuccess("Cloned successfully");

        // Delete old version after successful clone
        logger.indent(`Deleting old version ${oldProject.version}...`);
        if (await this.dtrack.deleteProject(oldProject.uuid)) {
          logger.indentSuccess("Old version deleted");
        }
      } else {
        logger.warn("Clone failed, keeping old version");
      }
    }
  }

  /**
   * Run stale-project cleanup for each enabled source. Scoped per-source marker so
   * the Docker and Kubernetes passes never delete each other's projects.
   */
  private async cleanupAllSources(): Promise<void> {
    if (this.config.scanner.scanDocker) {
      await this.cleanupStaleProjects(DOCKER_MARKER);
    }
    if (this.config.scanner.scanKubernetes) {
      await this.cleanupStaleProjects(K8S_MARKER);
    }
    // Also cleanup expired cache entries (once per cycle)
    this.cache.cleanup();
  }

  /**
   * Clean up stale projects for this host + source marker
   */
  private async cleanupStaleProjects(marker: string): Promise<void> {
    logger.section(
      `Cleaning up stale ${marker} projects for host: ${this.config.scanner.hostname}`,
    );

    const allProjects = await this.dtrack.getAllProjects();
    if (allProjects.length === 0) {
      logger.info("No projects found or failed to fetch");
      return;
    }

    const hostTag = `host:${this.config.scanner.hostname}`;
    const requiredTags = [marker, hostTag];

    let deleted = 0;
    let kept = 0;

    for (const project of allProjects) {
      // Only consider projects with our tags
      if (!this.dtrack.projectHasTags(project, requiredTags)) {
        continue;
      }

      // Skip parent project
      if (
        this.config.dtrack.parentProject &&
        project.name === this.config.dtrack.parentProject &&
        !project.version
      ) {
        logger.info(`Skipping parent project: ${project.name}`);
        continue;
      }

      // Check if this version was uploaded in current scan
      const lookupKey = `${project.name}:${project.version}`;

      if (!this.uploadedVersions.has(lookupKey)) {
        // This version wasn't uploaded - it's stale
        logger.info(
          `Deleting stale project: ${project.name}:${project.version}`,
        );
        if (await this.dtrack.deleteProject(project.uuid)) {
          logger.success("Deleted successfully");
          deleted++;
        }
      } else {
        kept++;
      }
    }

    logger.info(`Cleanup complete: ${deleted} deleted, ${kept} kept`);
  }

  /**
   * Check if an image matches any exclusion pattern
   */
  private isExcluded(image: string): boolean {
    return this.config.scanner.excludeImages.some((pattern) =>
      image.includes(pattern),
    );
  }

  /**
   * Get cache stats
   */
  getCacheSize(): number {
    return this.cache.size;
  }
}

// Run scanner if executed directly
if (import.meta.main) {
  const { loadConfig, validateConfig } = await import("./config");

  try {
    const config = loadConfig();
    validateConfig(config);

    const scanner = new Scanner(config);
    await scanner.run();
  } catch (err) {
    logger.error(
      "Scanner failed:",
      err instanceof Error ? err.message : String(err),
    );
    process.exit(1);
  }
}
