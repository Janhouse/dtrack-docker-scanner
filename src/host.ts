import { createHash } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { release, tmpdir } from "node:os";
import { join } from "node:path";
import { logger } from "./logger";
import { addTrivyVerdicts } from "./trivy-verdicts";

/**
 * The node's own operating system packages (and its running kernel) as an
 * SBOM, from read-only mounts of the host's package database under
 * HOST_SCAN_ROOT — nothing else of the host is visible:
 *
 *   Debian/Ubuntu  <root>/var/lib/dpkg       + <root>/usr/lib/os-release
 *                  + <root>/etc/debian_version (Trivy detects Debian by it;
 *                  without it packages come out with no purl)
 *   Arch           <root>/var/lib/pacman/local + <root>/usr/lib/os-release
 *
 * Debian-family hosts go through Trivy, whose data is the distro's own
 * security tracker: fixed versions are per release, so a backported fix
 * (6.12.113-1 on trixie) counts as fixed. Installed-but-not-running kernel
 * packages are dropped — only the kernel actually booted matters.
 *
 * Distros no vulnerability source tracks per package (Arch: Trivy has no
 * support, OSV has no Arch ecosystem, DT can't match pkg:alpm) get syft's
 * inventory — searchable, but no findings — plus one component for the
 * running kernel with an NVD CPE (cpe:…:linux:linux_kernel:<version>), so DT
 * matches kernel CVEs by upstream version range. Not done on Debian: the
 * upstream version there would ignore every backported fix.
 */

export interface HostSbom {
  path: string;
  /** "debian-13", "arch-rolling" */
  version: string;
}

const TRIVY_DISTROS = new Set([
  "debian",
  "ubuntu",
  "alpine",
  "rhel",
  "centos",
  "rocky",
  "almalinux",
  "fedora",
  "amzn",
  "ol",
  "opensuse-leap",
  "sles",
  "photon",
  "wolfi",
  "chainguard",
  "azurelinux",
  "mariner",
]);

async function osRelease(root: string): Promise<Record<string, string>> {
  for (const p of ["usr/lib/os-release", "etc/os-release"]) {
    const f = Bun.file(join(root, p));
    if (await f.exists()) {
      const out: Record<string, string> = {};
      for (const line of (await f.text()).split("\n")) {
        const m = /^([A-Z_]+)=("?)(.*)\2$/.exec(line.trim());
        if (m) out[m[1]!] = m[3]!;
      }
      return out;
    }
  }
  return {};
}

/** Cheap change detector: package DB metadata + the running kernel. */
export async function hostFingerprint(root: string): Promise<string> {
  const h = createHash("sha256").update(release());
  for (const p of ["var/lib/dpkg/status", "var/lib/pacman/local"]) {
    const st = await stat(join(root, p)).catch(() => null);
    if (!st) continue;
    h.update(`${p}:${st.size}:${st.mtimeMs}`);
    if (st.isDirectory()) {
      const entries = await readdir(join(root, p)).catch(() => []);
      h.update(entries.sort().join("\n"));
    }
  }
  return h.digest("hex").slice(0, 12);
}

async function run(cmd: string[]): Promise<{ code: number; stderr: string }> {
  const proc = Bun.spawn(cmd, { stdout: "ignore", stderr: "pipe" });
  const timer = setTimeout(() => proc.kill(), 900_000);
  const stderr = await new Response(proc.stderr).text();
  const code = await proc.exited;
  clearTimeout(timer);
  return { code, stderr };
}

interface CdxComponent {
  name?: string;
  version?: string;
  type?: string;
  purl?: string;
  cpe?: string;
  "bom-ref"?: string;
  properties?: { name: string; value: string }[];
  [key: string]: unknown;
}

/** "6.12.113+deb13-amd64" → "6.12.113"; "7.2.11-zen1-1-zen" → "7.2.11" */
export function kernelVersion(uname: string): string | null {
  return /^(\d+\.\d+(?:\.\d+)?)/.exec(uname)?.[1] ?? null;
}

/**
 * Debian ships one linux-image/-headers/-modules package per kernel ABI
 * ("linux-image-6.12.111+deb13-amd64"); keep only the running one's, plus
 * unversioned metapackages.
 */
export function isStaleKernelPackage(name: string, uname: string): boolean {
  const m = /^linux-(?:image|headers|modules|modules-extra)-(\d.*)$/.exec(name);
  if (!m) return false;
  // "6.12.113+deb13-amd64" → "6.12.113+deb13": the running kernel's ABI,
  // shared by its -amd64 image and -common headers.
  const abi = uname.replace(/-[a-z0-9]+$/, "");
  return !m[1]!.startsWith(abi);
}

export async function generateHostSbom(root: string): Promise<HostSbom | null> {
  const os = await osRelease(root);
  const id = (os.ID ?? "").toLowerCase();
  if (!id) {
    logger.warn(`Host scan: no os-release under ${root}`);
    return null;
  }
  const version = `${id}-${os.VERSION_ID || "rolling"}`;
  const uname = release();
  const out = join(tmpdir(), `host-sbom-${Date.now()}.json`);

  const viaTrivy = TRIVY_DISTROS.has(id);
  const r = viaTrivy
    ? await run([
        "trivy",
        "rootfs",
        "--quiet",
        "--format",
        "cyclonedx",
        "--output",
        out,
        root,
      ])
    : await run([
        "syft",
        "scan",
        `dir:${root}`,
        "--override-default-catalogers",
        "alpm-db-cataloger,dpkg-db-cataloger,rpm-db-cataloger,apk-db-cataloger,portage-cataloger",
        "-q",
        "-o",
        `cyclonedx-json@1.6=${out}`,
      ]);
  if (r.code !== 0) {
    logger.error(`Host scan failed: ${r.stderr.trim().slice(0, 300)}`);
    return null;
  }

  const bom = (await Bun.file(out).json()) as {
    components?: CdxComponent[];
    [k: string]: unknown;
  };
  let components = bom.components ?? [];
  components = components.filter(
    (c) =>
      // syft lists every owned file too; packages only
      c.type !== "file" && !isStaleKernelPackage(String(c.name ?? ""), uname),
  );
  if (!viaTrivy) {
    const kv = kernelVersion(uname);
    if (kv) {
      components.push({
        "bom-ref": "dtrack-scanner:running-kernel",
        type: "operating-system",
        name: "linux-kernel",
        version: kv,
        cpe: `cpe:2.3:o:linux:linux_kernel:${kv}:*:*:*:*:*:*:*`,
        properties: [{ name: "dtrack-scanner:kernel-release", value: uname }],
      });
    }
  }
  bom.components = components;
  await Bun.write(out, JSON.stringify(bom));
  logger.info(
    `Host scan: ${components.length} packages (${version}, kernel ${uname}, ${viaTrivy ? "trivy" : "syft inventory"})`,
  );
  if (viaTrivy) await addTrivyVerdicts(out);
  return { path: out, version };
}
