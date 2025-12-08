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
  components?: CycloneDxComponent[];
  [key: string]: unknown;
}

/**
 * Generate SBOM for a Docker image using Trivy
 */
export async function generateSbom(image: string): Promise<SbomResult> {
  const outputPath = join(
    tmpdir(),
    `sbom-${Date.now()}-${Math.random().toString(36).substring(2)}.json`,
  );

  try {
    const proc = Bun.spawn(
      [
        "trivy",
        "image",
        "--format",
        "cyclonedx",
        "--output",
        outputPath,
        image,
      ],
      {
        stdout: "pipe",
        stderr: "pipe",
      },
    );

    const stderr = await new Response(proc.stderr).text();
    const exitCode = await proc.exited;

    if (exitCode !== 0) {
      return {
        success: false,
        error: stderr || `Trivy exited with code ${exitCode}`,
      };
    }

    // Check if file exists and has content
    const file = Bun.file(outputPath);
    if (!(await file.exists()) || file.size === 0) {
      return { success: false, error: "Empty SBOM generated" };
    }

    // Clean up the SBOM to fix license schema issues
    await cleanupSbom(outputPath);

    return { success: true, filePath: outputPath };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Clean up SBOM to fix schema validation issues
 * Dependency-Track may reject SBOMs with invalid license entries
 */
async function cleanupSbom(filePath: string): Promise<void> {
  try {
    const file = Bun.file(filePath);
    const content = (await file.json()) as CycloneDxBom;

    if (!content.components) {
      return;
    }

    // Fix license entries
    content.components = content.components.map((component) => {
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
