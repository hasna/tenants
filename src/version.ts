import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const FALLBACK_PACKAGE_VERSION = "0.0.0";

/** Read the package version, tolerating both source and built dist layouts. */
export function getPackageVersion(): string {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  for (const relativePath of ["../package.json", "../../package.json", "../../../package.json"]) {
    try {
      const parsed = JSON.parse(readFileSync(join(currentDir, relativePath), "utf8")) as { version?: string };
      if (parsed.version) return parsed.version;
    } catch {
      // Try the next packaged/source layout before falling back.
    }
  }
  return FALLBACK_PACKAGE_VERSION;
}
