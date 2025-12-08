/**
 * Types for Docker operations
 */

export interface DockerContainer {
  id: string;
  image: string;
  names: string[];
  labels: Record<string, string>;
  state: string;
}

export interface DockerContainerInfo {
  image: string;
  imageName: string;
  imageTag: string;
  composeProject?: string;
}

export interface ImageScanResult {
  image: string;
  imageName: string;
  imageTag: string;
  imageId: string;
  composeProjects: string[];
}
