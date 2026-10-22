import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (process.argv.length > 3)
  throw new Error(
    "Usage: node scripts/verify-real-ghidra-mipsel.mjs [installed-rea-entrypoint]",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to a bring-your-own Ghidra installation.",
  );
const exec = promisify(execFile);
const run = createVerifierRun();
const root = fileURLToPath(new URL("..", import.meta.url));
await mkdir(join(root, "build"), { recursive: true });
const workspace = await mkdtemp(join(root, "build", "rea-mipsel-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const path = join(workspace, "image.bin");
const entrypoint =
  process.argv[2] === undefined
    ? join(root, "scripts", "rea.mjs")
    : resolve(process.argv[2]);
const env = {
  ...process.env,
  TMPDIR: runtime,
  TMP: runtime,
  TEMP: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
};
// Independently hand-authored MIPS-I instructions; no Sony bytes, compiler or target execution.
// bfc00000: addiu sp,sp,-16; sw ra,12(sp); jal bfc00030;
//           addiu a0,zero,7 (call delay slot); lw ra,12(sp); addiu sp,sp,16;
//           jr ra; nop (return delay slot).
// bfc00030: addiu v0,a0,3; jr ra; nop.
const words = [
  0x27bdfff0, 0xafbf000c, 0x0ff0000c, 0x24040007, 0x8fbf000c, 0x27bd0010,
  0x03e00008, 0, 0, 0, 0, 0, 0x24820003, 0x03e00008, 0,
];
const bytes = Buffer.alloc(words.length * 4);
words.forEach((word, offset) => bytes.writeUInt32LE(word, offset * 4));
assert.equal(bytes.subarray(8, 16).toString("hex"), "0c00f00f07000424");
await writeFile(path, bytes);
const sha256 = createHash("sha256").update(bytes).digest("hex");
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-mipsel-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let report;
try {
  await client.connect(transport);
  const opened = await call("open_binary", {
    path,
    format: "raw-binary",
    architecture: "mipsel",
    entry_point: "0xBFC00000",
    provider_id: "ghidra",
  });
  assert.equal(opened.architecture, "mipsel");
  assert.equal(opened.entry_point, "0xbfc00000");
  const status = await call("binary_session");
  const image = evidence(await call("inspect_native_load_image"));
  assert.equal(
    image.normalized_result.status,
    "verified",
    JSON.stringify(image.normalized_result),
  );
  assert.equal(image.normalized_result.architecture, "mipsel");
  assert.equal(image.normalized_result.base_address, "0xbfc00000");
  assert.equal(image.normalized_result.language_id, "MIPS:LE:32:default");
  assert.equal(image.normalized_result.compiler_spec_id, "default");
  assert.equal(image.normalized_result.file_bytes, bytes.length);
  const memory = evidence(
    await call("read_bytes", { address: "0xbfc00000", length: bytes.length }),
  );
  assert.equal(memory.normalized_result.bytes_hex, bytes.toString("hex"));
  const procedures = evidence(await call("list_procedures"));
  for (const address of ["0xbfc00000", "0xbfc00030"])
    assert.ok(
      procedures.normalized_result.some(
        (procedure) => procedure.address === address,
      ),
      JSON.stringify(procedures.normalized_result),
    );
  const instruction = evidence(
    await call("inspect_native_instruction", { address: "0xbfc00008" }),
  );
  assert.equal(instruction.normalized_result.mnemonic.toUpperCase(), "JAL");
  assert.ok(
    instruction.normalized_result.references.some(
      (reference) =>
        reference.call && reference.target_address === "0xbfc00030",
    ),
  );
  const pseudo = evidence(
    await call("procedure_pseudo_code", { procedure: "0xbfc00030" }),
  );
  assert.match(pseudo.normalized_result, /\+\s*(?:3|0x3)/u);
  const filePseudo = evidence(
    await call("procedure_pseudo_code", { procedure: "file-offset:0x30" }),
  );
  assert.equal(filePseudo.normalized_result, pseudo.normalized_result);
  assert.ok(
    filePseudo.locations.some(
      (location) => location.kind === "file-offset" && location.offset === 48,
    ),
  );
  for (const [entry_point, reason] of [
    ["0xbfc00002", /4-byte aligned/u],
    ["0xfffffffc", /mipsel address width/u],
  ]) {
    const rejected = await client.callTool({
      name: "open_binary",
      arguments: {
        path,
        format: "raw-binary",
        architecture: "mipsel",
        entry_point,
      },
    });
    assert.equal(rejected.isError, true);
    assert.match(JSON.stringify(rejected.content), reason);
    const preserved = await call("binary_session");
    assert.equal(preserved.analysis_run.run_id, status.analysis_run.run_id);
    assert.equal(preserved.entry_point, "0xbfc00000");
  }
  await call("close_binary");
  await client.ping();
  const cliArgs = (command) => [
    entrypoint,
    command,
    path,
    "--target-format",
    "raw-binary",
    "--architecture",
    "mipsel",
    "--entry-point",
    "0xbfc00000",
    "--provider",
    "ghidra",
    "--json",
  ];
  const cli = evidence(
    JSON.parse(
      (
        await exec(process.execPath, cliArgs("inspect-native-load-image"), {
          env,
          timeout: 240000,
          maxBuffer: 16 * 1024 * 1024,
        })
      ).stdout,
    ),
  );
  assert.deepEqual(cli.normalized_result, image.normalized_result);
  assert.equal(cli.analysis_profile.digest, image.analysis_profile.digest);
  const fileCli = evidence(
    JSON.parse(
      (
        await exec(
          process.execPath,
          [...cliArgs("decompile"), "--file-offset=0x30"],
          { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
        )
      ).stdout,
    ),
  );
  assert.equal(fileCli.normalized_result, filePseudo.normalized_result);
  assert.deepEqual(fileCli.locations, filePseudo.locations);
  assert.deepEqual(await readFile(path), bytes);
  assert.deepEqual(await readdir(runtime), []);
  let windowsReparseAdmission = "not-applicable";
  if (process.platform === "win32") {
    const junction = join(workspace, "linked");
    await symlink(workspace, junction, "junction");
    try {
      await call("open_binary", {
        path: join(junction, "image.bin"),
        format: "raw-binary",
        architecture: "mipsel",
        entry_point: "0xbfc00000",
        provider_id: "ghidra",
      });
      // The selected session is lazy; the first analysis performs native path admission.
      const rejected = await client.callTool(
        { name: "inspect_native_load_image", arguments: {} },
        { timeout: 240000 },
      );
      assert.equal(rejected.isError, true);
      assert.match(
        JSON.stringify(rejected.content),
        /Reparse path component is unsupported/u,
      );
      await call("close_binary");
      await client.ping();
      assert.deepEqual(await readFile(path), bytes);
      assert.deepEqual(await readdir(runtime), []);
      windowsReparseAdmission = "mcp-rejected";
    } finally {
      await unlink(junction);
    }
  }
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-mipsel",
    host: process.platform,
    provider: image.provider,
    target: {
      sha256,
      bytes: bytes.length,
      architecture: "mipsel",
      entry: "0xbfc00000",
      fixture: "hand-authored MIPS-I subset",
    },
    cli_mcp_load_image_parity: true,
    instructions_and_call_reference: true,
    decompilation: true,
    file_offset_decompilation_cli_mcp: true,
    invalid_mapping_preserves_session: true,
    windows_reparse_admission: windowsReparseAdmission,
    source_unchanged: true,
    runtime_cleanup: "complete",
    limitations: [
      "Generic MIPS32 language; no claim of exact R3000 or PS1 GTE coverage",
      "Static analysis only; no target execution",
    ],
  };
} catch (cause) {
  if (stderr) process.stderr.write(stderr);
  throw cause;
} finally {
  try {
    await client.close();
  } finally {
    await transport.close();
  }
}
const verifierRun = await completeVerifierRun(run);
if (process.platform !== "win32") {
  assert.equal(verifierRun.process_lineage.status, "verified");
  assert.deepEqual(verifierRun.process_lineage.descendants, []);
}
await rm(workspace, { recursive: true, force: true });
process.stdout.write(
  JSON.stringify({ verifier_run: verifierRun, ...report }) + "\n",
);

async function call(name, args = {}) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  if (["open_binary", "binary_session", "close_binary"].includes(name))
    return requireMcpOperationResult(result, name);
  return result.structuredContent;
}
function evidence(value) {
  const result = parseEvidence(value);
  assert.equal(result.subject.digest.sha256, sha256);
  assert.equal(result.subject.architecture, "mipsel");
  assert.equal(result.subject.format, "raw-binary");
  return result;
}
