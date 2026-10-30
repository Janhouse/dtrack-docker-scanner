import { createHash } from "node:crypto";
import { lstat, mkdir, readlink, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { logger } from "./logger";

/**
 * govulncheck on the Go binaries in an image.
 *
 * Trivy reports every module compiled into a Go binary (PkgType "gobinary"),
 * and Dependency-Track flags each module version with a known vulnerability —
 * whether or not the binary contains the vulnerable code. The Go linker drops
 * unreachable functions, so govulncheck's binary mode can tell: a
 * vulnerability whose vulnerable symbols are absent from the binary cannot
 * affect it (measured on fr2: 49 of keel's 83 third-party module findings).
 *
 * Results ride along in the SBOM as properties on each gobinary component —
 *   dtrack-scanner:govulncheck:absent   ids whose vulnerable code is NOT in the binary
 *   dtrack-scanner:govulncheck:present  ids whose vulnerable symbols ARE in it
 * — every id with its aliases (GO-…, CVE-…, GHSA-…). dtrack-panel turns
 * "absent" into a NOT_AFFECTED analysis; "present" only says the code is
 * there, not that it is reachable with attacker input, so it stays open.
 * Both properties (possibly empty) mean "scanned"; neither means "not scanned".
 *
 * Getting the binary, without pulling or copying the image:
 *   rootfs  k8s: a running container's root filesystem, which containerd
 *           keeps mounted on the node at <rootfsDir>/<container id>/rootfs —
 *           read in place through a read-only hostPath mount. No containerd
 *           socket, no registry pull, no extra disk. Only images with a
 *           running container on this node (the ones the collector scans).
 *   docker  docker hosts: docker create + docker cp of just the binaries.
 */

export const PROP_ABSENT = "dtrack-scanner:govulncheck:absent";
export const PROP_PRESENT = "dtrack-scanner:govulncheck:present";

export type GoSource = "rootfs" | "docker";

export interface GovulncheckOptions {
  sources: GoSource[];
  /** Go vulnerability DB (a mirror): https://vuln.go.dev or http://govulndb…/govulndb */
  dbUrl: string;
  /** Node dir holding <container id>/rootfs (the k3s containerd task dir). */
  rootfsDir: string;
  /** Running containers of this image on this node (k8s). */
  containerIds?: string[];
}

interface CdxProperty {
  name: string;
  value: string;
}
interface CdxComponent {
  purl?: string;
  properties?: CdxProperty[];
  components?: CdxComponent[];
  [key: string]: unknown;
}
interface CdxBom {
  components?: CdxComponent[];
  [key: string]: unknown;
}

const prop = (c: CdxComponent, name: string) =>
  c.properties?.find((p) => p.name === name)?.value;

/** pkg:golang/golang.org/x/crypto@v0.21.0 → golang.org/x/crypto; stdlib → stdlib */
export function goModuleOf(purl: string | undefined): string | null {
  const m = /^pkg:golang\/([^@?#]+)/.exec(purl ?? "");
  return m ? decodeURIComponent(m[1]!) : null;
}

async function run(
  cmd: string[],
  timeoutMs = 300_000,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe" });
  const timer = setTimeout(() => proc.kill(), timeoutMs);
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const code = await proc.exited;
  clearTimeout(timer);
  return { code, stdout, stderr };
}

// ─── govulncheck output ──────────────────────────────────────────────────────

export interface ModuleVerdicts {
  /** module path → ids (with aliases) whose vulnerable code is absent / present */
  absent: Map<string, Set<string>>;
  present: Map<string, Set<string>>;
}

const RANK = { module: 0, package: 1, symbol: 2 } as const;

/**
 * Parse `govulncheck -mode=binary -format json` (a stream of JSON objects).
 * A vulnerability's deepest trace frame across its findings decides: a
 * function frame = the symbol is in the binary; package/module only = not.
 */
export function parseGovulncheck(stream: string): ModuleVerdicts {
  const aliases = new Map<string, string[]>();
  const level = new Map<string, { module: string; rank: number }>();
  const dec = (s: string) => {
    const out: unknown[] = [];
    let depth = 0;
    let start = -1;
    let inStr = false;
    let esc = false;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (inStr) {
        if (esc) esc = false;
        else if (ch === "\\") esc = true;
        else if (ch === '"') inStr = false;
        continue;
      }
      if (ch === '"') inStr = true;
      else if (ch === "{") {
        if (depth++ === 0) start = i;
      } else if (ch === "}" && --depth === 0) {
        out.push(JSON.parse(s.slice(start, i + 1)));
      }
    }
    return out;
  };
  for (const o of dec(stream) as Record<string, any>[]) {
    if (o.osv?.id) aliases.set(o.osv.id, o.osv.aliases ?? []);
    const f = o.finding;
    if (!f?.osv || !f.trace?.length) continue;
    const top = f.trace[0];
    const rank = top.function
      ? RANK.symbol
      : top.package
        ? RANK.package
        : RANK.module;
    const key = `${f.osv}\u0000${top.module}`;
    const prev = level.get(key);
    if (!prev || rank > prev.rank) level.set(key, { module: top.module, rank });
  }
  const out: ModuleVerdicts = { absent: new Map(), present: new Map() };
  for (const [key, { module, rank }] of level) {
    const id = key.split("\u0000")[0]!;
    const side = rank === RANK.symbol ? out.present : out.absent;
    const set = side.get(module) ?? new Set<string>();
    for (const x of [id, ...(aliases.get(id) ?? [])]) set.add(x);
    side.set(module, set);
  }
  return out;
}

// ─── getting the binaries ────────────────────────────────────────────────────

/**
 * The binaries from a running container's root filesystem, read in place.
 * Symlinks are resolved inside that root, never on the node.
 */
async function fromRootfs(
  rootfsDir: string,
  containerIds: string[],
  paths: string[],
): Promise<Map<string, string>> {
  const found = new Map<string, string>();
  for (const id of containerIds) {
    const root = join(rootfsDir, id, "rootfs");
    if (!(await stat(root).catch(() => null))?.isDirectory()) continue;
    for (const p of paths) {
      if (found.has(p)) continue;
      const f = await insideRoot(root, p);
      if (f) found.set(p, f);
    }
    if (found.size === paths.length) break;
  }
  return found;
}

/** Resolve `rel` under `root` following symlinks as the container would. */
export async function insideRoot(
  root: string,
  rel: string,
): Promise<string | null> {
  let parts = rel.split("/").filter(Boolean);
  let cur = root;
  for (let hops = 0; parts.length > 0 && hops < 40; ) {
    const next = join(cur, parts[0]!);
    const st = await lstat(next).catch(() => null);
    if (!st) return null;
    if (st.isSymbolicLink()) {
      hops++;
      const target = await readlink(next);
      const base = target.startsWith("/") ? root : cur;
      parts = [...target.split("/").filter(Boolean), ...parts.slice(1)];
      cur = base;
      continue;
    }
    cur = next;
    parts = parts.slice(1);
    if (parts.length === 0) return st.isFile() ? cur : null;
    if (!st.isDirectory()) return null;
  }
  return null;
}

async function extractFromDocker(
  image: string,
  paths: string[],
  out: string,
): Promise<Map<string, string>> {
  const found = new Map<string, string>();
  const created = await run(["docker", "create", image], 120_000);
  const id = created.stdout.trim();
  if (created.code !== 0 || !id) return found;
  try {
    for (const p of paths) {
      const dest = join(out, createHash("sha1").update(p).digest("hex"));
      const cp = await run(
        ["docker", "cp", "-L", `${id}:/${p}`, dest],
        300_000,
      );
      if (cp.code === 0 && (await stat(dest).catch(() => null))?.isFile()) {
        found.set(p, dest);
      }
    }
  } finally {
    await run(["docker", "rm", "-f", id], 60_000);
  }
  return found;
}

// ─── the SBOM pass ───────────────────────────────────────────────────────────

/**
 * Run govulncheck on every Go binary Trivy found in the image and annotate
 * its modules' components in the SBOM. Best effort: any failure leaves the
 * SBOM as Trivy (and syft) wrote it.
 */
export async function addGovulncheck(
  sbomPath: string,
  image: string,
  opts: GovulncheckOptions,
): Promise<void> {
  if (opts.sources.length === 0) return;
  let bom: CdxBom;
  try {
    bom = (await Bun.file(sbomPath).json()) as CdxBom;
  } catch {
    return;
  }

  const byBinary = new Map<string, CdxComponent[]>();
  const walk = (list: CdxComponent[] | undefined) => {
    for (const c of list ?? []) {
      const path = prop(c, "aquasecurity:trivy:FilePath");
      if (prop(c, "aquasecurity:trivy:PkgType") === "gobinary" && path) {
        const rel = path.replace(/^\/+/, "");
        byBinary.set(rel, [...(byBinary.get(rel) ?? []), c]);
      }
      walk(c.components);
    }
  };
  walk(bom.components);
  if (byBinary.size === 0) return;

  const work = join(
    tmpdir(),
    `gvc-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  await mkdir(work, { recursive: true });
  let scanned = 0;
  try {
    const paths = [...byBinary.keys()];
    let files = new Map<string, string>();
    for (const src of opts.sources) {
      try {
        if (src === "rootfs" && opts.containerIds?.length) {
          files = await fromRootfs(opts.rootfsDir, opts.containerIds, paths);
        } else if (src === "docker") {
          files = await extractFromDocker(image, paths, work);
        }
      } catch (err) {
        logger.debug(`govulncheck: ${src} failed for ${image}: ${err}`);
      }
      if (files.size > 0) break;
    }
    for (const [rel, file] of files) {
      const r = await run(
        [
          "govulncheck",
          "-mode=binary",
          "-format",
          "json",
          "-db",
          opts.dbUrl,
          file,
        ],
        600_000,
      );
      // Exit 3 = vulnerabilities found (json mode exits 0); anything else
      // without output is a failure for this binary only.
      if (!r.stdout.trim()) {
        logger.debug(
          `govulncheck: no output for ${rel} in ${image}: ${r.stderr.trim().slice(0, 200)}`,
        );
        continue;
      }
      const v = parseGovulncheck(r.stdout);
      for (const c of byBinary.get(rel) ?? []) {
        const mod = goModuleOf(c.purl);
        if (!mod) continue;
        c.properties = (c.properties ?? []).filter(
          (p) => p.name !== PROP_ABSENT && p.name !== PROP_PRESENT,
        );
        c.properties.push(
          {
            name: PROP_ABSENT,
            value: [...(v.absent.get(mod) ?? [])].sort().join(","),
          },
          {
            name: PROP_PRESENT,
            value: [...(v.present.get(mod) ?? [])].sort().join(","),
          },
        );
      }
      scanned++;
    }

    if (scanned > 0) {
      await Bun.write(sbomPath, JSON.stringify(bom));
      logger.info(
        `  govulncheck: ${scanned}/${byBinary.size} Go binaries in ${image}`,
      );
    } else {
      logger.debug(`govulncheck: no Go binary of ${image} could be read`);
    }
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
