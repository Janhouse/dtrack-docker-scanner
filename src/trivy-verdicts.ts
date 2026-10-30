import { tmpdir } from "node:os";
import { join } from "node:path";
import { logger } from "./logger";

/**
 * Trivy's own verdict per package, carried in the SBOM.
 *
 * Dependency-Track's Trivy analyzer keeps only the CVE ids from Trivy: it
 * re-rates each from its NVD copy (varnish:7.6 — Trivy 17 critical, DT 518)
 * and drops the fixed version (every OS finding showed "fixed in —"). Trivy
 * knows both: the DISTRO's severity for OS packages and the version that
 * fixes it. So after generating an SBOM we run `trivy sbom` over it and put
 * the verdicts on each component:
 *
 *   dtrack-scanner:trivy:v:<n>  "CVE-…|C|F|3.5.5-1~deb13u2;CVE-…|H|F|…"
 *
 * id | severity (C/H/M/L/U) | status (F fixed, A affected, W will_not_fix,
 * D fix_deferred, E end_of_life, O other) | fixed version. Chunked at
 * 1000 characters per property (DT's property value limit). dtrack-panel
 * reads them for "fixed in" and the distro severity.
 */

export const PROP_PREFIX = "dtrack-scanner:trivy:v:";
const CHUNK = 1000;
/** Per package; worst first. Beyond this the panel falls back to DT. */
const MAX_PER_COMPONENT = 300;
/** Kernel header packages: dtrack-panel closes their findings anyway. */
const SKIP =
  /^(linux-libc-dev|linux-headers(-.+)?|kernel-headers|linux-api-headers)$/;

const SEV: Record<string, string> = {
  CRITICAL: "C",
  HIGH: "H",
  MEDIUM: "M",
  LOW: "L",
};
const STATUS: Record<string, string> = {
  fixed: "F",
  affected: "A",
  will_not_fix: "W",
  fix_deferred: "D",
  end_of_life: "E",
};
const RANK: Record<string, number> = { C: 0, H: 1, M: 2, L: 3, U: 4 };

interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  PkgIdentifier?: { BOMRef?: string };
  Severity?: string;
  Status?: string;
  FixedVersion?: string;
}

interface CdxComponent {
  "bom-ref"?: string;
  properties?: { name: string; value: string }[];
  components?: CdxComponent[];
  [key: string]: unknown;
}

/** "id|sev|status|fixed" entries → ≤CHUNK-character property values. */
export function chunkVerdicts(entries: string[]): string[] {
  const out: string[] = [];
  let cur = "";
  for (const e of entries) {
    if (e.length > CHUNK) continue;
    if (cur && cur.length + 1 + e.length > CHUNK) {
      out.push(cur);
      cur = "";
    }
    cur = cur ? `${cur};${e}` : e;
  }
  if (cur) out.push(cur);
  return out;
}

/** Trivy JSON results → bom-ref → verdict entries, worst first, capped. */
export function verdictsByRef(vulns: TrivyVuln[]): Map<string, string[]> {
  const byRef = new Map<string, { rank: number; entry: string }[]>();
  for (const v of vulns) {
    const ref = v.PkgIdentifier?.BOMRef;
    if (!ref || !v.VulnerabilityID || SKIP.test(v.PkgName ?? "")) continue;
    const sev = SEV[v.Severity ?? ""] ?? "U";
    const status = STATUS[v.Status ?? ""] ?? "O";
    const fixed = (v.FixedVersion ?? "").replace(/[;|]/g, " ").trim();
    const list = byRef.get(ref) ?? [];
    list.push({
      rank: RANK[sev] ?? 4,
      entry: `${v.VulnerabilityID}|${sev}|${status}|${fixed}`,
    });
    byRef.set(ref, list);
  }
  const out = new Map<string, string[]>();
  for (const [ref, list] of byRef) {
    out.set(
      ref,
      list
        .sort((a, b) => a.rank - b.rank)
        .slice(0, MAX_PER_COMPONENT)
        .map((x) => x.entry),
    );
  }
  return out;
}

/** Annotate the SBOM at `sbomPath` in place. Best effort. */
export async function addTrivyVerdicts(sbomPath: string): Promise<void> {
  const out = join(
    tmpdir(),
    `verdicts-${Date.now()}-${Math.random().toString(36).slice(2)}.json`,
  );
  try {
    const proc = Bun.spawn(
      [
        "trivy",
        "sbom",
        "--quiet",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--output",
        out,
        sbomPath,
      ],
      { stdout: "ignore", stderr: "pipe" },
    );
    const stderr = await new Response(proc.stderr).text();
    if ((await proc.exited) !== 0) {
      logger.warn(
        `  trivy verdicts skipped: ${stderr.trim().split("\n").pop()}`,
      );
      return;
    }
    const results =
      (
        (await Bun.file(out).json()) as {
          Results?: { Vulnerabilities?: TrivyVuln[] }[];
        }
      ).Results ?? [];
    const verdicts = verdictsByRef(
      results.flatMap((r) => r.Vulnerabilities ?? []),
    );
    if (verdicts.size === 0) return;

    const bom = (await Bun.file(sbomPath).json()) as {
      components?: CdxComponent[];
    };
    let annotated = 0;
    const walk = (list: CdxComponent[] | undefined) => {
      for (const c of list ?? []) {
        const entries = c["bom-ref"] ? verdicts.get(c["bom-ref"]) : undefined;
        if (entries) {
          c.properties = [
            ...(c.properties ?? []).filter(
              (p) => !p.name.startsWith(PROP_PREFIX),
            ),
            ...chunkVerdicts(entries).map((value, i) => ({
              name: `${PROP_PREFIX}${i}`,
              value,
            })),
          ];
          annotated++;
        }
        walk(c.components);
      }
    };
    walk(bom.components);
    await Bun.write(sbomPath, JSON.stringify(bom));
    logger.indent(`trivy verdicts on ${annotated} package(s)`);
  } catch (err) {
    logger.warn(`  trivy verdicts skipped: ${err}`);
  } finally {
    await Bun.file(out)
      .delete()
      .catch(() => {});
  }
}
