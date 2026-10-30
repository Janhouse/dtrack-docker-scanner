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
