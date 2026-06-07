import { logger } from "./logger";

interface CacheEntry {
  scannedAt: number;
  projectName: string;
  projectVersion: string;
}

/**
 * In-memory cache for tracking scanned images
 * Prevents re-scanning the same image within the TTL period
 */
export class ImageCache {
  private readonly cache: Map<string, CacheEntry> = new Map();
  private readonly ttlMs: number;

  constructor(ttlMinutes: number) {
    this.ttlMs = ttlMinutes * 60 * 1000;
  }

  /**
   * Generate a cache key from image ID or digest
   */
  private makeKey(imageId: string): string {
    return imageId;
  }

  /**
   * Check if an image was recently scanned
   */
  has(imageId: string): boolean {
    const key = this.makeKey(imageId);
    const entry = this.cache.get(key);

    if (!entry) {
      return false;
    }

    // Check if entry has expired
    if (Date.now() - entry.scannedAt > this.ttlMs) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Mark an image as scanned
   */
  set(imageId: string, projectName: string, projectVersion: string): void {
    const key = this.makeKey(imageId);
    this.cache.set(key, {
      scannedAt: Date.now(),
      projectName,
      projectVersion,
    });
  }

  /**
   * Remove expired entries from cache
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [key, entry] of this.cache) {
      if (now - entry.scannedAt > this.ttlMs) {
        this.cache.delete(key);
        removed++;
      }
    }

    if (removed > 0) {
      logger.debug(`Cache cleanup: removed ${removed} expired entries`);
    }

    return removed;
  }

  /**
   * Get current cache size
   */
  get size(): number {
    return this.cache.size;
  }
}
