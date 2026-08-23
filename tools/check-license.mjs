#!/usr/bin/env node
/** Check the public package surfaces for the declared Apache-2.0 license. */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (file) => readFile(join(root, file), "utf8");
const node = JSON.parse(await read("packages/agent-control/package.json"));
const py = await read("packages/cirvix-python/pyproject.toml");
for (const [name, file] of [["LICENSE", "LICENSE"], ["Node LICENSE", "packages/agent-control/LICENSE"], ["Python LICENSE", "packages/cirvix-python/LICENSE"]]) {
  const source = await read(file);
  if (!source.includes("Apache License") || !source.includes("Version 2.0")) throw new Error(`${name} is not Apache-2.0`);
}
if (node.license !== "Apache-2.0" || !/^license\s*=\s*[\"']Apache-2\.0[\"']/m.test(py)) throw new Error("package metadata does not declare Apache-2.0");
console.log("Apache-2.0 license and package metadata verified");
