#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import process from "node:process";

const args = parseArgs(process.argv.slice(2));
if (args.help) usage(0);

for (const required of ["artifact", "provenance", "expected_repository", "expected_builder", "expected_build_type", "expected_workflow"]) {
  if (!args[required]) die(`missing --${dash(required)}`);
}

const report = args.report ?? "target/quality/slsa-provenance-policy.md";
const checks = [];
const errors = [];
const artifactSha = await fileSha256(args.artifact);
const raw = await readFile(args.provenance, "utf8");
const { statement, signatureState } = provenanceStatement(raw);

checkEquals("predicateType", statement.predicateType, "https://slsa.dev/provenance/v1");
checkSubjectDigest(statement, artifactSha);
checkEquals("builder.id", builderId(statement), args.expected_builder);
checkEquals("buildType", buildType(statement), args.expected_build_type);
checkEquals("source.repository", sourceRepository(statement), args.expected_repository);
checkEquals("workflow", workflowRef(statement), args.expected_workflow);

if (args.require_signature) {
  checkTruth("provenance signature", signatureState === "present", "provenance contains at least one DSSE/in-toto signature");
}

if (args.require_build_l3) {
  const builder = builderId(statement) ?? "";
  const hosted = /^https:\/\/github\.com\/actions\/runner\//.test(builder)
    || /^https:\/\/github\.com\/Attestations\/GitHubHostedActions@/.test(builder)
    || /^https:\/\/github\.com\/0xdoublesharp\/locket\/\.github\/workflows\//.test(builder);
  checkTruth("Build L3 hosted-runner target", hosted, "builder identity is a hosted CI builder, not a local workstation");
}

await writeReport(report, checks, errors, artifactSha);

if (errors.length > 0) {
  console.error(`SLSA provenance policy failed; see ${report}`);
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}

console.log(`SLSA provenance policy passed; see ${report}`);

function parseArgs(argv) {
  const parsed = {};
  while (argv.length > 0) {
    const arg = argv.shift();
    if (arg === "--help") {
      parsed.help = true;
      continue;
    }
    if (arg === "--require-signature") {
      parsed.require_signature = true;
      continue;
    }
    if (arg === "--require-build-l3") {
      parsed.require_build_l3 = true;
      continue;
    }
    const match = /^--([a-z0-9-]+)$/.exec(arg);
    if (!match) die(`unknown argument: ${arg}`);
    if (argv.length === 0) die(`missing value for ${arg}`);
    parsed[match[1].replaceAll("-", "_")] = argv.shift();
  }
  return parsed;
}

function usage(code) {
  console.log(`usage: slsa-provenance-policy.mjs --artifact <path> --provenance <json>
       --expected-repository <uri> --expected-builder <id>
       --expected-build-type <type> --expected-workflow <ref>
       [--require-signature] [--require-build-l3] [--report <path>]`);
  process.exit(code);
}

function die(message) {
  console.error(message);
  process.exit(2);
}

function dash(value) {
  return value.replaceAll("_", "-");
}

async function fileSha256(path) {
  const content = await readFile(path);
  return createHash("sha256").update(content).digest("hex");
}

function provenanceStatement(raw) {
  const json = JSON.parse(raw);
  if (isObject(json) && "payload" in json && "payloadType" in json) {
    const payload = Buffer.from(json.payload, "base64").toString("utf8");
    return {
      statement: JSON.parse(payload),
      signatureState: Array.isArray(json.signatures) && json.signatures.length > 0 ? "present" : "missing",
    };
  }
  if (isObject(json) && Array.isArray(json.signatures) && json.signatures.length > 0) {
    return { statement: json, signatureState: "present" };
  }
  return { statement: json, signatureState: "unchecked" };
}

function checkEquals(name, actual, expected) {
  if (actual != null && actual === expected) {
    checks.push([name, "passed", actual]);
    return;
  }
  const detail = actual != null ? `expected ${expected}, got ${actual}` : `expected ${expected}, got <missing>`;
  checks.push([name, "failed", detail]);
  errors.push(`${name}: ${detail}`);
}

function checkTruth(name, ok, detail) {
  checks.push([name, ok ? "passed" : "failed", detail]);
  if (!ok) errors.push(`${name}: ${detail}`);
}

function checkSubjectDigest(statement, artifactSha) {
  if (!Array.isArray(statement.subject)) {
    checks.push(["subject digest", "failed", "subject array missing"]);
    errors.push("subject digest: subject array missing");
    return;
  }
  for (const subject of statement.subject) {
    if (isObject(subject?.digest) && subject.digest.sha256 === artifactSha) {
      checks.push(["subject digest", "passed", `sha256=${artifactSha}`]);
      return;
    }
  }
  checks.push(["subject digest", "failed", `artifact sha256 ${artifactSha} not present`]);
  errors.push(`subject digest: artifact sha256 ${artifactSha} not present`);
}

function builderId(statement) {
  return nested(statement, ["predicate", "runDetails", "builder", "id"])
    ?? nested(statement, ["predicate", "builder", "id"]);
}

function buildType(statement) {
  return nested(statement, ["predicate", "buildDefinition", "buildType"])
    ?? nested(statement, ["predicate", "buildType"]);
}

function sourceRepository(statement) {
  return nested(statement, ["predicate", "buildDefinition", "externalParameters", "repository"])
    ?? nested(statement, ["predicate", "buildDefinition", "externalParameters", "sourceRepository"])
    ?? nested(statement, ["predicate", "buildDefinition", "externalParameters", "gitRepository"])
    ?? nested(statement, ["predicate", "invocation", "configSource", "uri"]);
}

function workflowRef(statement) {
  return nested(statement, ["predicate", "buildDefinition", "externalParameters", "workflow"])
    ?? nested(statement, ["predicate", "buildDefinition", "externalParameters", "workflow_ref"])
    ?? nested(statement, ["predicate", "buildDefinition", "externalParameters", "github_workflow_ref"])
    ?? nested(statement, ["predicate", "invocation", "configSource", "entryPoint"]);
}

function nested(value, path) {
  let current = value;
  for (const key of path) {
    if (!isObject(current) || !(key in current)) return undefined;
    current = current[key];
  }
  return isObject(current) || Array.isArray(current) ? undefined : current;
}

async function writeReport(path, checks, errors, artifactSha) {
  await mkdir(dirname(path), { recursive: true });
  const lines = [
    "# SLSA Provenance Policy",
    "",
    `- Artifact SHA-256: ${artifactSha}`,
    `- Result: ${errors.length > 0 ? "failed" : "passed"}`,
    "",
    "| Check | Status | Detail |",
    "| --- | --- | --- |",
  ];
  for (const [name, status, detail] of checks) {
    lines.push(`| ${name} | ${status} | ${markdownEscape(detail)} |`);
  }
  lines.push("");
  await writeFile(path, lines.join("\n"));
}

function isObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function markdownEscape(value) {
  return String(value ?? "").replaceAll("|", "\\|").replace(/\r?\n/g, " ");
}
