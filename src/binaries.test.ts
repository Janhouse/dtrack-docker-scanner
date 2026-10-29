import { describe, expect, test } from "bun:test";
import { mergeComponents } from "./binaries";

const by = (cataloger: string) => [
  { name: "syft:package:foundBy", value: cataloger },
];

describe("mergeComponents", () => {
  test("adds runtimes Trivy missed, keeps Trivy's own", () => {
    const base = {
      components: [
        {
          "bom-ref": "a",
          name: "musl",
          version: "1.2.5-r9",
          purl: "pkg:apk/alpine/musl@1.2.5-r9?arch=x86_64",
        },
      ],
    };
    const syft = {
      components: [
        {
          "bom-ref": "x",
          name: "postgresql",
          version: "17.6",
          purl: "pkg:generic/postgresql@17.6",
          properties: by("binary-classifier-cataloger"),
        },
        {
          "bom-ref": "p",
          name: "php-fpm",
          version: "8.3.12",
          purl: "pkg:generic/php-fpm@8.3.12",
          properties: by("php-interpreter-cataloger"),
        },
      ],
    };
    expect(mergeComponents(base, syft)).toBe(2);
    expect(base.components.map((c) => c.name)).toEqual([
      "musl",
      "postgresql",
      "php-fpm",
    ]);
    const pg = base.components[1] as Record<string, unknown>;
    expect(pg["bom-ref"]).toBe("syft-binary:x");
  });

  test("ignores the ownership-only OS packages and syft's file/OS records", () => {
    const base = { components: [] as Record<string, unknown>[] };
    const syft = {
      components: [
        {
          name: "musl",
          version: "1.2.5-r9",
          purl: "pkg:apk/alpine/musl@1.2.5-r9",
          properties: by("apk-db-cataloger"),
        },
        { name: "alpine", version: "3.22.5", type: "operating-system" },
        { name: "/bin/busybox", type: "file" },
      ],
    };
    expect(mergeComponents(base, syft)).toBe(0);
  });

  test("dedupes against Trivy by purl (ignoring qualifiers) and name+version", () => {
    const base = {
      components: [
        {
          name: "nginx",
          version: "1.27.5",
          purl: "pkg:generic/nginx@1.27.5?arch=x86_64",
        },
      ],
    };
    const syft = {
      components: [
        {
          name: "nginx",
          version: "1.27.5",
          purl: "pkg:generic/nginx@1.27.5",
          properties: by("binary-classifier-cataloger"),
        },
      ],
    };
    expect(mergeComponents(base, syft)).toBe(0);
  });

  test("tolerates an empty syft result", () => {
    const base = { components: [{ name: "a", version: "1" }] };
    expect(mergeComponents(base, {})).toBe(0);
    expect(base.components).toHaveLength(1);
  });
});
