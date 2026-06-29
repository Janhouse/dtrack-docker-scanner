/**
 * Types for Docker operations
 */

export type ScanSource = "docker" | "kubernetes";

export interface ImageScanResult {
  image: string;
  imageName: string;
  imageTag: string;
  imageId: string;
  composeProjects: string[];
  // Where this image was discovered. Absent => "docker" (backward compatible).
  source?: ScanSource;
  // Kubernetes namespaces this image runs in (source === "kubernetes").
  namespaces?: string[];
}
