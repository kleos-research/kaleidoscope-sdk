import { chmodSync, existsSync, realpathSync } from "node:fs";
import { delimiter, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const FAKE_BINARY = realpathSync(
  resolve(here, "../../python/tests/fixtures/fake_kscope_mcp.py"),
);
chmodSync(FAKE_BINARY, 0o755);
export const FAKE_MANAGER = realpathSync(
  resolve(here, "../../conformance/fake_account_manager.py"),
);
chmodSync(FAKE_MANAGER, 0o755);

const pythonBin = resolve(here, "../../python/.venv/bin");
if (!existsSync(resolve(pythonBin, "python"))) {
  throw new Error(
    "TypeScript MCP tests require python/.venv with mcp==1.29.0; run npm run test:bootstrap",
  );
}
process.env.PATH = `${pythonBin}${delimiter}${process.env.PATH ?? ""}`;
