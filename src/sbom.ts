import { tmpdir } from "node:os";
import { join } from "node:path";

interface SbomResult {
  success: boolean;
  filePath?: string;
  error?: string;
}

interface CycloneDxLicense {
  expression?: string;
  license?: {
    id?: string;
    name?: string;
  };
}

interface CycloneDxComponent {
  licenses?: CycloneDxLicense[];
  [key: string]: unknown;
}

interface CycloneDxBom {
  specVersion?: string;
  components?: CycloneDxComponent[];
  [key: string]: unknown;
}

// DependencyTrack accepts CycloneDX up to this spec version (DT 4.14). Newer Trivy
// emits 1.7, which DT rejects ("Unrecognized specVersion"); the component data is
// backward-compatible, so we clamp the declared version down to this.
const MAX_CYCLONEDX_SPEC = "1.6";

export interface SbomOptions {
  // Trivy image source: e.g. "docker", "containerd", "remote". Maps to
  // `trivy image --image-src <src>`. Omit to let Trivy auto-detect (default,
  // used for the Docker path).
  imageSrc?: string;
}

/**
 * Generate SBOM for a container image using Trivy. With opts.imageSrc the image
 * is read from that source (e.g. "containerd" for images already on a k8s node).
 */
export async function generateSbom(
  image: string,
  opts: SbomOptions = {},
): Promise<SbomResult> {
  // Try each image source in order (e.g. "containerd,remote"): scan the node's
  // local store first, then fall back to a registry pull when its layer blobs
  // were garbage-collected (k3s containerd discards unpacked layers, so Trivy
  // can hit "content digest ... not found"). Empty => a single auto-detect run.
  const sources = (opts.imageSrc ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const attempts = sources.length > 0 ? sources : [""];
  let lastError = "SBOM generation failed";

  for (const src of attempts) {
    const outputPath = join(
      tmpdir(),
      `sbom-${Date.now()}-${Math.random().toString(36).substring(2)}.json`,
    );
    try {
      const proc = Bun.spawn(
        [
          "trivy",
          "image",
          ...(src ? ["--image-src", src] : []),
          "--format",
          "cyclonedx",
          "--output",
          outputPath,
          image,
        ],
        { stdout: "pipe", stderr: "pipe" },
      );

      const stderr = await new Response(proc.stderr).text();
      const exitCode = await proc.exited;

      if (exitCode !== 0) {
        lastError = `${src || "auto"}: ${stderr || `Trivy exited with code ${exitCode}`}`;
        await cleanupSbomFile(outputPath);
        continue;
      }

      const file = Bun.file(outputPath);
      if (!(await file.exists()) || file.size === 0) {
        lastError = `${src || "auto"}: Empty SBOM generated`;
        continue;
      }

      // Clean up the SBOM to fix license schema + spec-version issues
      await cleanupSbom(outputPath);
      return { success: true, filePath: outputPath };
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
  }

  return { success: false, error: lastError };
}

/**
 * Clean up SBOM to fix schema validation issues
 * Dependency-Track may reject SBOMs with invalid license entries
 */
async function cleanupSbom(filePath: string): Promise<void> {
  try {
    const file = Bun.file(filePath);
    const content = (await file.json()) as CycloneDxBom;

    // Clamp the CycloneDX spec version down to what DependencyTrack accepts.
    if (content.specVersion) {
      const [maj = 0, min = 0] = content.specVersion.split(".").map(Number);
      const [mMaj, mMin] = MAX_CYCLONEDX_SPEC.split(".").map(Number);
      if (maj > (mMaj ?? 0) || (maj === mMaj && min > (mMin ?? 0))) {
        content.specVersion = MAX_CYCLONEDX_SPEC;
      }
    }

    // Fix license entries
    content.components = (content.components ?? []).map((component) => {
      if (!component.licenses || component.licenses.length === 0) {
        return component;
      }

      // Simplify license entries to just expression
      const firstLicense = component.licenses[0];
      let expression = "NOASSERTION";

      if (firstLicense) {
        if (firstLicense.expression) {
          expression = firstLicense.expression;
        } else if (firstLicense.license?.id) {
          expression = firstLicense.license.id;
        }
      }

      return {
        ...component,
        licenses: [{ expression }],
      };
    });

    await Bun.write(filePath, JSON.stringify(content));
  } catch {
    // If cleanup fails, just continue with original file
  }
}

/**
 * Read and base64 encode an SBOM file
 */
export async function readSbomAsBase64(filePath: string): Promise<string> {
  const file = Bun.file(filePath);
  const buffer = await file.arrayBuffer();
  return Buffer.from(buffer).toString("base64");
}

/**
 * Clean up temporary SBOM file
 */
export async function cleanupSbomFile(filePath: string): Promise<void> {
  try {
    const { unlink } = await import("node:fs/promises");
    await unlink(filePath);
  } catch {
    // Ignore cleanup errors
  }
}
