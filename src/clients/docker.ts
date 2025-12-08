import { logger } from "../logger";
import type { ImageScanResult } from "../types";

export type DockerEventCallback = (event: DockerEvent) => void;

export interface DockerEvent {
  type: "container";
  action: "start" | "stop" | "die" | "destroy";
  containerId: string;
  image: string;
  imageId: string;
  composeProject?: string;
}

/**
 * Parse Docker image string into name and tag
 */
export function parseImage(image: string): { name: string; tag: string } {
  const colonIndex = image.lastIndexOf(":");
  // Handle cases like "registry.example.com:5000/image:tag"
  const slashIndex = image.lastIndexOf("/");

  if (colonIndex > slashIndex) {
    return {
      name: image.substring(0, colonIndex),
      tag: image.substring(colonIndex + 1),
    };
  }

  return { name: image, tag: "latest" };
}

/**
 * Get base image name without registry prefix
 */
export function getBaseName(imageName: string): string {
  const slashIndex = imageName.lastIndexOf("/");
  return slashIndex >= 0 ? imageName.substring(slashIndex + 1) : imageName;
}

/**
 * Run a command and return stdout
 */
async function exec(
  cmd: string[],
): Promise<{ success: boolean; stdout: string; stderr: string }> {
  try {
    const proc = Bun.spawn(cmd, {
      stdout: "pipe",
      stderr: "pipe",
    });

    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);

    const exitCode = await proc.exited;
    return { success: exitCode === 0, stdout, stderr };
  } catch (err) {
    return {
      success: false,
      stdout: "",
      stderr: err instanceof Error ? err.message : String(err),
    };
  }
}

export class DockerClient {
  private eventProcess: ReturnType<typeof Bun.spawn> | null = null;
  private eventCallback: DockerEventCallback | null = null;

  /**
   * Test Docker socket connection
   */
  async testConnection(): Promise<boolean> {
    const result = await exec(["docker", "info"]);
    return result.success;
  }

  /**
   * Get all running containers with their images, compose projects, and image IDs
   */
  async getRunningContainers(): Promise<ImageScanResult[]> {
    // Get image, compose project, and image ID
    const result = await exec([
      "docker",
      "ps",
      "--format",
      '{{.Image}}|{{.Label "com.docker.compose.project"}}|{{.ID}}',
    ]);

    if (!result.success) {
      logger.error("Failed to list containers:", result.stderr);
      return [];
    }

    // Get container details including image ID
    const containerIds = result.stdout
      .trim()
      .split("\n")
      .filter((l) => l)
      .map((l) => l.split("|")[2])
      .filter((id): id is string => !!id);

    // Get image IDs for each container
    const imageIdMap = await this.getImageIds(containerIds);

    // Aggregate by image, collecting all compose projects
    const imageMap = new Map<
      string,
      { composeProjects: Set<string>; imageId: string }
    >();

    for (const line of result.stdout.trim().split("\n")) {
      if (!line) continue;

      const [image, composeProject, containerId] = line.split("|");
      if (!image || !containerId) continue;

      const imageId = imageIdMap.get(containerId) ?? "";
      const existing = imageMap.get(image) ?? {
        composeProjects: new Set(),
        imageId,
      };

      if (composeProject) {
        existing.composeProjects.add(composeProject);
      }
      if (imageId && !existing.imageId) {
        existing.imageId = imageId;
      }
      imageMap.set(image, existing);
    }

    // Convert to ImageScanResult array
    const results: ImageScanResult[] = [];
    for (const [image, data] of imageMap) {
      const { name, tag } = parseImage(image);
      results.push({
        image,
        imageName: name,
        imageTag: tag,
        imageId: data.imageId,
        composeProjects: Array.from(data.composeProjects),
      });
    }

    return results;
  }

  /**
   * Get image IDs for containers
   */
  private async getImageIds(
    containerIds: string[],
  ): Promise<Map<string, string>> {
    const result = new Map<string, string>();
    if (containerIds.length === 0) return result;

    const inspectResult = await exec([
      "docker",
      "inspect",
      "--format",
      "{{.Id}}|{{.Image}}",
      ...containerIds,
    ]);

    if (!inspectResult.success) {
      return result;
    }

    const lines = inspectResult.stdout.trim().split("\n");
    for (let i = 0; i < containerIds.length && i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      const imageId = line.split("|")[1];
      const containerId = containerIds[i];
      if (imageId && containerId) {
        // Extract short image ID (sha256:xxx -> first 12 chars after sha256:)
        const shortId = imageId.replace("sha256:", "").substring(0, 12);
        result.set(containerId, shortId);
      }
    }

    return result;
  }

  /**
   * Get image ID for a specific image
   */
  async getImageId(image: string): Promise<string | null> {
    const result = await exec([
      "docker",
      "inspect",
      "--format",
      "{{.Id}}",
      image,
    ]);

    if (!result.success) {
      return null;
    }

    const imageId = result.stdout.trim();
    // Extract short image ID
    return imageId.replace("sha256:", "").substring(0, 12);
  }

  /**
   * Start listening for Docker events
   */
  startEventListener(callback: DockerEventCallback): void {
    if (this.eventProcess) {
      logger.warn("Docker event listener already running");
      return;
    }

    this.eventCallback = callback;
    logger.info("Starting Docker event listener...");

    // Listen for container lifecycle events with JSON output
    this.eventProcess = Bun.spawn(
      [
        "docker",
        "events",
        "--filter",
        "type=container",
        "--filter",
        "event=start",
        "--filter",
        "event=stop",
        "--filter",
        "event=die",
        "--format",
        '{"action":"{{.Action}}","id":"{{.Actor.ID}}","image":"{{.Actor.Attributes.image}}","imageId":"{{.Actor.Attributes.imageId}}","compose":"{{index .Actor.Attributes "com.docker.compose.project"}}"}',
      ],
      {
        stdout: "pipe",
        stderr: "pipe",
      },
    );

    // Read events from stdout
    this.readEvents();
  }

  /**
   * Read Docker events from the process stdout
   */
  private async readEvents(): Promise<void> {
    if (!this.eventProcess) return;

    const stdout = this.eventProcess.stdout;
    if (!stdout || typeof stdout === "number") return;

    const reader = stdout.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");

        // Process complete lines
        for (let i = 0; i < lines.length - 1; i++) {
          const line = lines[i]?.trim();
          if (line) {
            this.processEvent(line);
          }
        }

        // Keep incomplete line in buffer
        buffer = lines[lines.length - 1] ?? "";
      }
    } catch (err) {
      if (this.eventProcess) {
        logger.error(
          "Docker event listener error:",
          err instanceof Error ? err.message : String(err),
        );
      }
    }
  }

  /**
   * Clean Docker template value - Docker returns "<no value>" for missing attributes
   */
  private cleanDockerValue(value: string | undefined): string {
    if (!value || value === "<no value>") return "";
    return value;
  }

  /**
   * Process a single Docker event
   */
  private processEvent(line: string): void {
    try {
      const data = JSON.parse(line) as {
        action: string;
        id: string;
        image: string;
        imageId: string;
        compose: string;
      };

      // Validate action is one we handle
      const validActions = ["start", "stop", "die", "destroy"] as const;
      if (
        !validActions.includes(data.action as (typeof validActions)[number])
      ) {
        return;
      }

      const rawImageId = this.cleanDockerValue(data.imageId);
      const imageId = rawImageId
        ? rawImageId.replace("sha256:", "").substring(0, 12)
        : "";

      const event: DockerEvent = {
        type: "container",
        action: data.action as DockerEvent["action"],
        containerId: data.id.substring(0, 12),
        image: data.image,
        imageId,
        composeProject: this.cleanDockerValue(data.compose) || undefined,
      };

      logger.debug(
        `Docker event: ${event.action} ${event.image} (${event.imageId || "no id"})`,
      );

      if (this.eventCallback) {
        this.eventCallback(event);
      }
    } catch {
      // Ignore parse errors
    }
  }

  /**
   * Stop listening for Docker events
   */
  stopEventListener(): void {
    if (this.eventProcess) {
      logger.info("Stopping Docker event listener...");
      this.eventProcess.kill();
      this.eventProcess = null;
      this.eventCallback = null;
    }
  }
}
