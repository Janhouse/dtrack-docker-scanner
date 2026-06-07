/**
 * Types for Docker operations
 */

export interface ImageScanResult {
  image: string;
  imageName: string;
  imageTag: string;
  imageId: string;
  composeProjects: string[];
}
