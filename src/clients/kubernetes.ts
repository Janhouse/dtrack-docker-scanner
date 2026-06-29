import { logger } from "../logger";
import type { ImageScanResult } from "../types";
import { parseImage } from "./docker";

const SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount";

interface K8sContainerStatus {
  image?: string;
  imageID?: string;
}

interface K8sPod {
  metadata?: { namespace?: string; name?: string };
  status?: {
    containerStatuses?: K8sContainerStatus[];
    initContainerStatuses?: K8sContainerStatus[];
    ephemeralContainerStatuses?: K8sContainerStatus[];
  };
}

interface K8sPodList {
  items?: K8sPod[];
}

export interface KubernetesClientOptions {
  // Restrict to pods scheduled on this node (recommended for a DaemonSet).
  nodeName?: string;
  // Only scan these namespaces (empty => all namespaces visible to the token).
  namespaces?: string[];
  // Override in-cluster discovery (defaults to the SA token + KUBERNETES_SERVICE_*).
  apiUrl?: string;
  tokenFile?: string;
}

/**
 * Extract the short (12-char) sha256 image digest from a k8s imageID, which looks
 * like "registry/repo@sha256:<hex>" or bare "sha256:<hex>".
 */
function shortDigest(imageId: string | undefined): string {
  if (!imageId) return "";
  const m = imageId.match(/sha256:([0-9a-f]{12,64})/i);
  return m?.[1] ? m[1].substring(0, 12) : "";
}

export class KubernetesClient {
  private readonly apiUrl: string;
  private readonly token: string;
  private readonly ca: string;
  private readonly nodeName: string;
  private readonly namespaces: string[];

  constructor(opts: KubernetesClientOptions = {}) {
    const host = process.env.KUBERNETES_SERVICE_HOST;
    const port = process.env.KUBERNETES_SERVICE_PORT_HTTPS || "443";
    this.apiUrl = (
      opts.apiUrl ||
      (host ? `https://${host}:${port}` : "https://kubernetes.default.svc")
    ).replace(/\/$/, "");

    const tokenFile = opts.tokenFile || `${SA_DIR}/token`;
    try {
      this.token = require("node:fs").readFileSync(tokenFile, "utf8").trim();
    } catch {
      this.token = "";
    }
    try {
      this.ca = require("node:fs").readFileSync(`${SA_DIR}/ca.crt`, "utf8");
    } catch {
      this.ca = "";
    }
    this.nodeName = opts.nodeName ?? "";
    this.namespaces = opts.namespaces ?? [];
  }

  private async apiGet<T>(path: string): Promise<T | null> {
    try {
      // Bun honours NODE_EXTRA_CA_CERTS, but also pass the SA CA explicitly so the
      // client works without extra env. (tls is a Bun fetch extension.)
      const init = {
        headers: {
          Authorization: `Bearer ${this.token}`,
          Accept: "application/json",
        },
        ...(this.ca ? { tls: { ca: this.ca } } : {}),
      } as RequestInit;
      const res = await fetch(`${this.apiUrl}${path}`, init);
      if (!res.ok) {
        logger.error(`Kubernetes API ${path} -> HTTP ${res.status}`);
        return null;
      }
      return (await res.json()) as T;
    } catch (err) {
      logger.error(
        `Kubernetes API ${path} failed:`,
        err instanceof Error ? err.message : String(err),
      );
      return null;
    }
  }

  /**
   * Verify the API is reachable and the token works.
   */
  async testConnection(): Promise<boolean> {
    if (!this.token) {
      logger.error("No Kubernetes service-account token found");
      return false;
    }
    const data = await this.apiGet<K8sPodList>(this.podsPath(1));
    return data !== null;
  }

  private podsPath(limit?: number): string {
    const params: string[] = [];
    if (this.nodeName) {
      params.push(
        `fieldSelector=spec.nodeName=${encodeURIComponent(this.nodeName)}`,
      );
    }
    if (limit) params.push(`limit=${limit}`);
    const qs = params.length ? `?${params.join("&")}` : "";
    return `/api/v1/pods${qs}`;
  }

  /**
   * List images of pods running on this node (or all nodes if nodeName unset),
   * one ImageScanResult per unique image reference. Mirrors DockerClient's output
   * so the Scanner pipeline is identical.
   */
  async getRunningImages(): Promise<ImageScanResult[]> {
    const list = await this.apiGet<K8sPodList>(this.podsPath());
    if (!list) {
      logger.error("Failed to list Kubernetes pods");
      return [];
    }

    // image ref -> { imageId, namespaces }
    const imageMap = new Map<
      string,
      { imageId: string; namespaces: Set<string> }
    >();

    for (const pod of list.items ?? []) {
      const ns = pod.metadata?.namespace ?? "default";
      if (this.namespaces.length > 0 && !this.namespaces.includes(ns)) continue;

      const statuses = [
        ...(pod.status?.containerStatuses ?? []),
        ...(pod.status?.initContainerStatuses ?? []),
        ...(pod.status?.ephemeralContainerStatuses ?? []),
      ];

      for (const cs of statuses) {
        const image = cs.image;
        if (!image) continue;
        const imageId = shortDigest(cs.imageID);
        const existing = imageMap.get(image) ?? {
          imageId,
          namespaces: new Set<string>(),
        };
        existing.namespaces.add(ns);
        if (imageId && !existing.imageId) existing.imageId = imageId;
        imageMap.set(image, existing);
      }
    }

    const results: ImageScanResult[] = [];
    for (const [image, data] of imageMap) {
      const { name, tag } = parseImage(image);
      results.push({
        image,
        imageName: name,
        imageTag: tag,
        imageId: data.imageId,
        composeProjects: [],
        source: "kubernetes",
        namespaces: Array.from(data.namespaces),
      });
    }
    return results;
  }
}
