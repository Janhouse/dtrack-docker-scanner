import { tmpdir } from "node:os";
import { join } from "node:path";
import { logger } from "./logger";

/**
 * Runtimes that no package manager knows about.
 *
 * Trivy builds the OS part of an SBOM from the package database (apk/dpkg/
 * rpm). Official runtime images compile or untar their runtime instead —
 * postgres, redis, python, node, php, bun, ruby… — so Trivy reports the
 * image's Alpine/Debian packages and its pip/npm deps but NOT the runtime
 * itself (measured on fr2/media: every postgres:*, redis:*, python:* and
 * node image was missing its interpreter/server).
 *
 * syft identifies those executables by content (binary classifiers) and has
 * a dedicated PHP interpreter cataloger (php-cli, php-fpm, libphp and the
 * compiled extensions). We run ONLY those catalogers and merge what they find
 * into Trivy's SBOM, so everything Trivy already reports stays as it was.
 */
const BINARY_CATALOGERS = [
  "binary-classifier-cataloger",
  "php-interpreter-cataloger",
];
// The OS package-database catalogers run too, but only so syft can drop
// binary matches for files a distro package owns (its default
// exclude-binary-overlap-by-ownership). Without them, apk's curl 8.14.1-r2
// would also appear as pkg:generic/curl@8.14.1 — and matching the plain
// upstream version against NVD flags every CVE the distro backported a fix
// for (Debian/Ubuntu openssl 3.0.2-0ubuntu1.18 …). Their own components are
// discarded: Trivy already reports the OS packages.
const OWNERSHIP_CATALOGERS = [
  "apk-db-cataloger",
  "dpkg-db-cataloger",
  "rpm-db-cataloger",
  "alpm-db-cataloger",
  "portage-cataloger",
];

interface CdxComponent {
  "bom-ref"?: string;
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  properties?: { name: string; value: string }[];
  [key: string]: unknown;
}

interface CdxBom {
  components?: CdxComponent[];
  [key: string]: unknown;
}

/** syft's --from for the image source Trivy succeeded with. */
function syftSource(trivySrc: string): string {
  switch (trivySrc) {
    case "containerd":
      // Reads CONTAINERD_ADDRESS / CONTAINERD_NAMESPACE, which the k8s
      // DaemonSet already sets for Trivy.
      return "containerd";
    case "remote":
      return "registry";
    case "podman":
      return "podman";
    default:
      return "docker";
  }
}

/**
 * Components from `extra` that `base` lacks, re-keyed so their bom-refs can't
 * collide. Same PURL, or same name+version, counts as already present.
 */
export function mergeComponents(base: CdxBom, extra: CdxBom): number {
  const have = new Set<string>();
  for (const c of base.components ?? []) {
    if (c.purl) have.add(c.purl.split("?")[0]?.toLowerCase() ?? "");
    if (c.name) have.add(`${c.name}@${c.version ?? ""}`.toLowerCase());
  }
  const added: CdxComponent[] = [];
  for (const c of extra.components ?? []) {
    // Only what the binary/PHP catalogers found — not the ownership-only
    // OS packages, not syft's file and operating-system records.
    const foundBy = c.properties?.find(
      (p) => p.name === "syft:package:foundBy",
    )?.value;
    if (!foundBy || !BINARY_CATALOGERS.includes(foundBy)) continue;
    if (!c.name || !c.version || !c.purl) continue;
    const purl = c.purl?.split("?")[0]?.toLowerCase();
    const nv = `${c.name}@${c.version ?? ""}`.toLowerCase();
    if ((purl && have.has(purl)) || have.has(nv)) continue;
    have.add(nv);
    if (purl) have.add(purl);
    added.push({
      ...c,
      "bom-ref": `syft-binary:${c["bom-ref"] ?? nv}`,
      properties: [
        ...(c.properties ?? []),
        { name: "dtrack-scanner:detected-by", value: "syft-binary" },
      ],
    });
  }
  base.components = [...(base.components ?? []), ...added];
  return added.length;
}

/**
 * Add syft-detected runtimes to the Trivy SBOM at `sbomPath`, in place.
 * Best effort: any failure leaves Trivy's SBOM untouched.
 */
export async function addBinaryComponents(
  sbomPath: string,
  image: string,
  trivySrc: string,
  // A running container's root filesystem (source "rootfs"): scanned in
  // place, never following a link above it.
  rootfs?: string,
): Promise<void> {
  const syftPath = join(
    tmpdir(),
    `syft-${Date.now()}-${Math.random().toString(36).substring(2)}.json`,
  );
  try {
    const proc = Bun.spawn(
      [
        "syft",
        "scan",
        ...(rootfs
          ? [`dir:${rootfs}`, "--base-path", rootfs]
          : ["--from", syftSource(trivySrc), image]),
        "--override-default-catalogers",
        [...BINARY_CATALOGERS, ...OWNERSHIP_CATALOGERS].join(","),
        "--quiet",
        // Dependency-Track 5.x accepts CycloneDX ≤ 1.6 (see Dockerfile).
        "-o",
        `cyclonedx-json@1.6=${syftPath}`,
      ],
      { stdout: "ignore", stderr: "pipe" },
    );
    const stderr = await new Response(proc.stderr).text();
    if ((await proc.exited) !== 0) {
      logger.warn(
        `  syft binary scan failed (Trivy SBOM kept): ${stderr.trim().split("\n").pop()}`,
      );
      return;
    }
    const base = (await Bun.file(sbomPath).json()) as CdxBom;
    const extra = (await Bun.file(syftPath).json()) as CdxBom;
    const added = mergeComponents(base, extra);
    if (added > 0) {
      await Bun.write(sbomPath, JSON.stringify(base));
      logger.indent(`+${added} runtime component(s) from syft`);
    }
  } catch (err) {
    logger.warn(
      `  syft binary scan failed (Trivy SBOM kept): ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    try {
      const { unlink } = await import("node:fs/promises");
      await unlink(syftPath);
    } catch {
      // not created
    }
  }
}
