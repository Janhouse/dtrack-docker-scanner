import { describe, expect, test } from "bun:test";
import {
  goBinaries,
  goModuleOf,
  insideRoot,
  parseGovulncheck,
} from "./govulncheck";

describe("govulncheck helpers", () => {
  test("goModuleOf", () => {
    expect(goModuleOf("pkg:golang/golang.org/x/crypto@v0.21.0")).toBe(
      "golang.org/x/crypto",
    );
    expect(goModuleOf("pkg:golang/stdlib@v1.22.1")).toBe("stdlib");
    expect(goModuleOf("pkg:golang/github.com/%40x/y@v1")).toBe(
      "github.com/@x/y",
    );
    expect(goModuleOf("pkg:npm/x@1")).toBeNull();
  });

  test("insideRoot resolves symlinks within the container root", async () => {
    const { mkdtemp, mkdir, writeFile, symlink } = await import(
      "node:fs/promises"
    );
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const root = await mkdtemp(join(tmpdir(), "gvc-root-"));
    await mkdir(join(root, "usr/local/bin"), { recursive: true });
    await writeFile(join(root, "usr/local/bin/app"), "x");
    await symlink("/usr/local/bin/app", join(root, "usr/local/bin/link"));
    await symlink("usr/local", join(root, "opt"));
    await symlink("/etc/passwd", join(root, "escape"));
    expect(await insideRoot(root, "usr/local/bin/app")).toBe(
      join(root, "usr/local/bin/app"),
    );
    expect(await insideRoot(root, "usr/local/bin/link")).toBe(
      join(root, "usr/local/bin/app"),
    );
    expect(await insideRoot(root, "opt/bin/app")).toBe(
      join(root, "usr/local/bin/app"),
    );
    // an absolute link resolves inside the root, never on the node
    expect(await insideRoot(root, "escape")).toBeNull();
    expect(await insideRoot(root, "nope")).toBeNull();
  });

  test("parseGovulncheck: deepest frame per vulnerability and module", () => {
    const stream = [
      { config: { scanner_name: "govulncheck" } },
      { osv: { id: "GO-1", aliases: ["CVE-1", "GHSA-a"] } },
      { osv: { id: "GO-2", aliases: ["CVE-2"] } },
      { finding: { osv: "GO-1", trace: [{ module: "golang.org/x/net" }] } },
      {
        finding: {
          osv: "GO-1",
          trace: [
            { module: "golang.org/x/net", package: "golang.org/x/net/html" },
          ],
        },
      },
      {
        finding: {
          osv: "GO-2",
          trace: [{ module: "stdlib", package: "net/http" }],
        },
      },
      {
        finding: {
          osv: "GO-2",
          trace: [{ module: "stdlib", package: "net/http", function: "Serve" }],
        },
      },
    ]
      .map((o) => JSON.stringify(o, null, 2))
      .join("\n");
    const v = parseGovulncheck(stream);
    expect([...(v.absent.get("golang.org/x/net") ?? [])].sort()).toEqual([
      "CVE-1",
      "GHSA-a",
      "GO-1",
    ]);
    expect([...(v.present.get("stdlib") ?? [])].sort()).toEqual([
      "CVE-2",
      "GO-2",
    ]);
    expect(v.present.get("golang.org/x/net")).toBeUndefined();
  });

  test("goBinaries follows Trivy's application → module dependency graph", () => {
    const bom = {
      components: [
        {
          "bom-ref": "app",
          type: "application",
          name: "bin/keel",
          properties: [{ name: "aquasecurity:trivy:Type", value: "gobinary" }],
        },
        {
          "bom-ref": "m1",
          type: "library",
          name: "golang.org/x/crypto",
          purl: "pkg:golang/golang.org/x/crypto@v0.21.0",
        },
        {
          "bom-ref": "m2",
          type: "library",
          name: "stdlib",
          purl: "pkg:golang/stdlib@v1.22.1",
        },
        {
          "bom-ref": "os",
          type: "library",
          name: "busybox",
          purl: "pkg:apk/alpine/busybox@1",
        },
      ],
      dependencies: [
        { ref: "app", dependsOn: ["m1", "m2"] },
        { ref: "m1", dependsOn: [] },
      ],
    };
    const m = goBinaries(bom);
    expect([...m.keys()]).toEqual(["bin/keel"]);
    expect(m.get("bin/keel")?.map((c) => c.name)).toEqual([
      "golang.org/x/crypto",
      "stdlib",
    ]);
  });
});

import { isStaleKernelPackage, kernelVersion } from "./host";

describe("host scan helpers", () => {
  test("kernelVersion", () => {
    expect(kernelVersion("6.12.113+deb13-amd64")).toBe("6.12.113");
    expect(kernelVersion("7.2.11-zen1-1-zen")).toBe("7.2.11");
  });
  test("only the running kernel's packages stay", () => {
    const uname = "6.12.113+deb13-amd64";
    expect(
      isStaleKernelPackage("linux-image-6.12.111+deb13-amd64", uname),
    ).toBe(true);
    expect(
      isStaleKernelPackage("linux-image-6.12.113+deb13-amd64", uname),
    ).toBe(false);
    expect(
      isStaleKernelPackage("linux-headers-6.12.111+deb13-common", uname),
    ).toBe(true);
    expect(
      isStaleKernelPackage("linux-headers-6.12.113+deb13-common", uname),
    ).toBe(false);
    expect(isStaleKernelPackage("linux-image-amd64", uname)).toBe(false);
    expect(isStaleKernelPackage("openssl", uname)).toBe(false);
  });
});

import { chunkVerdicts, verdictsByRef } from "./trivy-verdicts";

describe("trivy verdicts", () => {
  test("worst first, kernel headers skipped, epoch colons kept", () => {
    const m = verdictsByRef([
      {
        VulnerabilityID: "CVE-1",
        PkgName: "openssl",
        PkgIdentifier: { BOMRef: "r1" },
        Severity: "LOW",
        Status: "fixed",
        FixedVersion: "1:3.5.5-1",
      },
      {
        VulnerabilityID: "CVE-2",
        PkgName: "openssl",
        PkgIdentifier: { BOMRef: "r1" },
        Severity: "CRITICAL",
        Status: "affected",
      },
      {
        VulnerabilityID: "CVE-3",
        PkgName: "linux-libc-dev",
        PkgIdentifier: { BOMRef: "r2" },
        Severity: "HIGH",
        Status: "fixed",
        FixedVersion: "6.12.1",
      },
    ]);
    expect(m.get("r1")).toEqual(["CVE-2|C|A|", "CVE-1|L|F|1:3.5.5-1"]);
    expect(m.has("r2")).toBe(false);
  });
  test("chunks stay under 1000 characters", () => {
    const entries = Array.from(
      { length: 200 },
      (_, i) => `CVE-2026-${10000 + i}|H|F|3.5.5-1~deb13u2`,
    );
    const chunks = chunkVerdicts(entries);
    expect(chunks.every((c) => c.length <= 1000)).toBe(true);
    expect(chunks.join(";").split(";")).toHaveLength(200);
  });
});
