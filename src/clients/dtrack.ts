import { logger } from "../logger";
import type {
  DTrackBomProcessingStatus,
  DTrackBomUploadRequest,
  DTrackBomUploadResponse,
  DTrackProject,
} from "../types";

export class DependencyTrackClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl.replace(/\/$/, ""); // Remove trailing slash
    this.apiKey = apiKey;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ data: T | null; httpCode: number; error?: string }> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "X-Api-Key": this.apiKey,
      Accept: "application/json",
    };

    if (body) {
      headers["Content-Type"] = "application/json";
    }

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });

      const httpCode = response.status;

      // Handle error responses (except 404 and 409 which we handle specially)
      if (!response.ok && httpCode !== 404 && httpCode !== 409) {
        const errorText = await response.text();
        return { data: null, httpCode, error: errorText };
      }

      // No body expected for these status codes
      if (httpCode === 204 || httpCode === 404 || httpCode === 409) {
        return { data: null, httpCode };
      }

      // Try to parse JSON response
      const text = await response.text();
      if (!text) {
        return { data: null, httpCode };
      }

      const data = JSON.parse(text) as T;
      return { data, httpCode };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      return { data: null, httpCode: 0, error };
    }
  }

  /**
   * Test connection to Dependency-Track
   */
  async testConnection(): Promise<boolean> {
    const { httpCode } = await this.request<DTrackProject[]>(
      "GET",
      "/api/v1/project?limit=1",
    );
    return httpCode === 200;
  }

  /**
   * Get all projects with pagination
   */
  async getAllProjects(): Promise<DTrackProject[]> {
    const allProjects: DTrackProject[] = [];
    let offset = 0;
    const limit = 100;
    const maxOffset = 10000;

    while (offset < maxOffset) {
      const { data, httpCode } = await this.request<DTrackProject[]>(
        "GET",
        `/api/v1/project?limit=${limit}&offset=${offset}`,
      );

      if (httpCode !== 200 || !data) {
        logger.error(`Failed to fetch projects at offset ${offset}`);
        break;
      }

      if (data.length === 0) {
        break;
      }

      allProjects.push(...data);
      offset += limit;
    }

    return allProjects;
  }

  /**
   * Find projects by name (returns all versions)
   */
  async findProjectsByName(name: string): Promise<DTrackProject[]> {
    const encodedName = encodeURIComponent(name);
    const { data } = await this.request<DTrackProject[]>(
      "GET",
      `/api/v1/project?name=${encodedName}`,
    );
    return data ?? [];
  }

  /**
   * Lookup a specific project by name and version
   */
  async lookupProject(
    name: string,
    version: string,
  ): Promise<DTrackProject | null> {
    const encodedName = encodeURIComponent(name);
    const encodedVersion = encodeURIComponent(version);
    const { data, httpCode } = await this.request<DTrackProject>(
      "GET",
      `/api/v1/project/lookup?name=${encodedName}&version=${encodedVersion}`,
    );
    return httpCode === 200 ? data : null;
  }

  /**
   * Create a project
   * Returns the project on success, or null on failure
   * On 409 (conflict/already exists), returns { alreadyExists: true }
   */
  async createProject(
    name: string,
    version: string,
    description: string,
    tags: string[],
  ): Promise<{ project: DTrackProject | null; alreadyExists: boolean }> {
    const payload = {
      name,
      version,
      description,
      tags: tags.map((t) => ({ name: t })),
    };

    const { data, httpCode, error } = await this.request<DTrackProject>(
      "PUT",
      "/api/v1/project",
      payload,
    );

    if (httpCode === 201) {
      return { project: data, alreadyExists: false };
    }

    if (httpCode === 409) {
      // Project already exists
      return { project: null, alreadyExists: true };
    }

    logger.error(`Failed to create project (HTTP ${httpCode}): ${error}`);
    return { project: null, alreadyExists: false };
  }

  /**
   * Delete a project by UUID
   */
  async deleteProject(uuid: string): Promise<boolean> {
    const { httpCode } = await this.request<void>(
      "DELETE",
      `/api/v1/project/${uuid}`,
    );
    return httpCode === 204;
  }

  /**
   * Upload a BOM to Dependency-Track
   */
  async uploadBom(
    projectName: string,
    projectVersion: string,
    bomBase64: string,
    tags: string[],
    parentName?: string,
  ): Promise<string | null> {
    const payload: DTrackBomUploadRequest = {
      projectName,
      projectVersion,
      autoCreate: true,
      bom: bomBase64,
      projectTags: tags,
    };

    if (parentName) {
      payload.parentName = parentName;
    }

    const { data, httpCode, error } =
      await this.request<DTrackBomUploadResponse>(
        "PUT",
        "/api/v1/bom",
        payload,
      );

    if (httpCode !== 200 || !data) {
      logger.error(`Upload failed (HTTP ${httpCode}): ${error}`);
      return null;
    }

    return data.token;
  }

  /**
   * Wait for BOM processing to complete
   */
  async waitForBomProcessing(
    token: string,
    maxWaitSeconds = 120,
  ): Promise<boolean> {
    const startTime = Date.now();
    const maxWaitMs = maxWaitSeconds * 1000;

    while (Date.now() - startTime < maxWaitMs) {
      const { data } = await this.request<DTrackBomProcessingStatus>(
        "GET",
        `/api/v1/bom/token/${token}`,
      );

      if (data && !data.processing) {
        return true;
      }

      await Bun.sleep(2000);
    }

    logger.warn(`BOM processing timeout after ${maxWaitSeconds}s`);
    return false;
  }

  /**
   * Clone analysis decisions from source project to target project
   */
  async cloneAnalysisDecisions(
    sourceUuid: string,
    targetUuid: string,
  ): Promise<boolean> {
    const { httpCode } = await this.request<void>(
      "POST",
      `/api/v1/finding/project/${targetUuid}/clone?sourceProjectUuid=${sourceUuid}`,
    );
    return httpCode === 200 || httpCode === 204;
  }

  /**
   * Find a project with empty version by name
   */
  private async findProjectWithEmptyVersion(
    name: string,
  ): Promise<DTrackProject | null> {
    const projects = await this.findProjectsByName(name);
    // Find the one with empty or no version
    return projects.find((p) => !p.version || p.version === "") ?? null;
  }

  /**
   * Ensure parent project exists, create if not
   */
  async ensureParentProject(
    name: string,
    hostname: string,
  ): Promise<DTrackProject | null> {
    // Check if exists - use findProjectsByName since lookup doesn't work well with empty version
    const existing = await this.findProjectWithEmptyVersion(name);
    if (existing) {
      logger.success("Parent project exists");
      return existing;
    }

    // Create it
    logger.info(`Creating parent project: ${name}`);
    const tags = ["docker-scanner", `host:${hostname}`];
    const result = await this.createProject(
      name,
      "",
      "Auto-created parent project for docker-scanner",
      tags,
    );

    if (result.project) {
      logger.success("Parent project created");
      return result.project;
    }

    if (result.alreadyExists) {
      // Race condition - project was created between lookup and create
      // Try to look it up again
      logger.info("Parent project already exists, looking up...");
      return await this.findProjectWithEmptyVersion(name);
    }

    return null;
  }

  /**
   * Check if a project has specific tags
   */
  projectHasTags(project: DTrackProject, requiredTags: string[]): boolean {
    const projectTags = (project.tags ?? []).map((t) => t.name);
    return requiredTags.every((tag) => projectTags.includes(tag));
  }

  /**
   * Find projects by tag
   */
  async findProjectsByTag(tag: string): Promise<DTrackProject[]> {
    const encodedTag = encodeURIComponent(tag);
    const { data, httpCode } = await this.request<DTrackProject[]>(
      "GET",
      `/api/v1/project/tag/${encodedTag}`,
    );
    if (httpCode !== 200) {
      return [];
    }
    return data ?? [];
  }

  /**
   * Check if a project exists with the given image hash tag
   */
  async hasProjectWithImageHash(imageHash: string): Promise<boolean> {
    if (!imageHash) return false;
    const tag = `imageid:${imageHash}`;
    const projects = await this.findProjectsByTag(tag);
    return projects.length > 0;
  }

  /**
   * Find project by image hash tag
   */
  async findProjectByImageHash(
    imageHash: string,
  ): Promise<DTrackProject | null> {
    if (!imageHash) return null;
    const tag = `imageid:${imageHash}`;
    const projects = await this.findProjectsByTag(tag);
    return projects[0] ?? null;
  }

  /**
   * Set project active status
   */
  async setProjectActive(uuid: string, active: boolean): Promise<boolean> {
    const { httpCode, error } = await this.request<DTrackProject>(
      "PATCH",
      `/api/v1/project/${uuid}`,
      { active },
    );

    if (httpCode !== 200) {
      logger.error(
        `Failed to set project active=${active} (HTTP ${httpCode}): ${error}`,
      );
      return false;
    }

    return true;
  }

  /**
   * Set project active status by image hash
   */
  async setProjectActiveByImageHash(
    imageHash: string,
    active: boolean,
  ): Promise<boolean> {
    const project = await this.findProjectByImageHash(imageHash);
    if (!project) {
      return false;
    }
    return this.setProjectActive(project.uuid, active);
  }
}
