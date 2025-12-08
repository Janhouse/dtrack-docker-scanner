/**
 * Types for OWASP Dependency-Track API
 */

export interface DTrackTag {
  name: string;
}

export interface DTrackProject {
  uuid: string;
  name: string;
  version: string;
  description?: string;
  tags?: DTrackTag[];
  active?: boolean;
  parent?: {
    uuid: string;
    name: string;
  };
}

export interface DTrackProjectCreate {
  name: string;
  version: string;
  description?: string;
  tags?: DTrackTag[];
}

export interface DTrackBomUploadRequest {
  projectName: string;
  projectVersion: string;
  autoCreate: boolean;
  bom: string; // Base64 encoded
  parentName?: string;
  projectTags?: string[];
}

export interface DTrackBomUploadResponse {
  token: string;
}

export interface DTrackBomProcessingStatus {
  processing: boolean;
}

export interface DTrackApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  httpCode: number;
}
