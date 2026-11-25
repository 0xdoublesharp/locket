#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";

const [auditJson, metadataJson, ledgerJson, reportPath] = process.argv.slice(2);
if (!auditJson || !metadataJson || !ledgerJson || !reportPath) {
  console.error("usage: rustsec-policy.mjs <cargo-audit-json> <cargo-metadata-json> <supply-chain-exceptions.json> <report.md>");
  process.exit(2);
}

const audit = JSON.parse(await readFile(auditJson, "utf8"));
const metadata = JSON.parse(await readFile(metadataJson, "utf8"));
const ledger = JSON.parse(await readFile(ledgerJson, "utf8"));

const scopeByPackage = packageScopes(metadata);
const exceptions = exceptionIndex(ledger);
const findings = audit?.vulnerabilities?.list;
if (!Array.isArray(findings)) {
  throw new Error("cargo-audit report is missing its vulnerability list");
}
const rows = [];
let blocking = false;

for (const finding of findings) {
  const advisory = finding.advisory ?? {};
  const packageName = advisory.package ?? finding.package?.name ?? "unknown";
  const version = finding.package?.version ?? advisory.version ?? "";
  const scope = scopeFor(scopeByPackage, packageName, version);
  const severity = severityFor(advisory);
  const [decision, blocks] = decisionFor(severity, scope, exceptions, {
    advisory: advisory.id ?? "unknown",
    package: packageName,
    version,
  });
  blocking ||= blocks;
  rows.push({
    id: advisory.id ?? "unknown",
    package: packageName,
    version,
    severity,
    scope,
    decision,
    title: markdownEscape(advisory.title ?? ""),
  });
}

await writeFile(reportPath, renderReport(rows, blocking));

if (blocking) {
  console.error(`RustSec policy failed; see ${reportPath}`);
  process.exit(1);
}

console.log(`RustSec policy passed; see ${reportPath}`);

function packageScopes(metadata) {
  const packagesById = new Map((metadata.packages ?? []).map((pkg) => [pkg.id, pkg]));
  const nodesById = new Map((metadata.resolve?.nodes ?? []).map((node) => [node.id, node]));
  const workspace = metadata.workspace_members ?? [];
  const runtimeReachable = new Set();
  const allReachable = new Set();

  for (const root of workspace) {
    traverse(root, nodesById, runtimeReachable, false);
    traverse(root, nodesById, allReachable, true);
  }

  const scopes = new Map();
  for (const id of allReachable) {
    const pkg = packagesById.get(id);
    if (!pkg) continue;
    const key = packageKey(pkg.name, pkg.version);
    const scope = runtimeReachable.has(id) ? "runtime" : "dev-only";
    scopes.set(key, mergeScope(scopes.get(key), scope));
  }
  return scopes;
}

function traverse(id, nodesById, seen, includeDev) {
  if (seen.has(id)) return;
  seen.add(id);
  const node = nodesById.get(id);
  if (!node) return;
  for (const dep of node.deps ?? []) {
    if (!includeDev && depIsDevOnly(dep)) continue;
    traverse(dep.pkg, nodesById, seen, includeDev);
  }
}

function depIsDevOnly(dep) {
  const kinds = dep.dep_kinds ?? [];
  return kinds.length > 0 && kinds.every((kind) => kind.kind === "dev");
}

function packageKey(name, version) {
  return `${name ?? ""}\u0000${version ?? ""}`;
}

function mergeScope(left, right) {
  if (!left) return right;
  return left === "runtime" || right === "runtime" ? "runtime" : left;
}

function scopeFor(scopes, packageName, version) {
  const exact = scopes.get(packageKey(packageName, version));
  if (exact) return exact;
  const matches = new Set();
  for (const [key, scope] of scopes.entries()) {
    const [name] = key.split("\u0000");
    if (name === packageName) matches.add(scope);
  }
  if (matches.has("runtime")) return "runtime";
  if (matches.has("dev-only")) return "dev-only";
  return "unknown";
}

function severityFor(advisory) {
  const severity = String(advisory.severity ?? "").toLowerCase();
  if (/^(critical|high|medium|low)$/.test(severity)) return severity;
  const score = /^([0-9]+(?:\.[0-9]+)?)/.exec(String(advisory.cvss ?? ""))?.[1];
  if (score != null) {
    const value = Number(score);
    if (value >= 9.0) return "critical";
    if (value >= 7.0) return "high";
    if (value >= 4.0) return "medium";
    if (value > 0) return "low";
  }
  return "unknown";
}

function exceptionIndex(ledger) {
  if (!Array.isArray(ledger.exceptions)) {
    throw new Error("supply-chain exception ledger must contain an exceptions array");
  }

  const today = process.env.LOCKET_TODAY ?? new Date().toISOString().slice(0, 10);
  const index = new Set();
  for (const entry of ledger.exceptions) {
    if (!isObject(entry)) continue;
    if (!nonEmptyString(entry.package) || !nonEmptyString(entry.version)) continue;
    if (!nonEmptyString(entry.advisory)) continue;
    if (!nonEmptyString(entry.reason) || !nonEmptyString(entry.owner)) continue;
    if (!validFutureDate(entry.expires_at, today)) continue;
    if (!Array.isArray(entry.compensating_controls) || entry.compensating_controls.some((control) => !nonEmptyString(control))) {
      continue;
    }
    index.add(exceptionKey(entry.package, entry.version, entry.advisory));
  }
  return index;
}

function decisionFor(severity, scope, exceptions, finding) {
  if (severity === "critical" || severity === "high") return ["block", true];
  if (severity === "medium" && scope !== "dev-only") return ["block", true];
  if (severity === "medium") {
    if (exceptions.has(exceptionKey(finding.package, finding.version, finding.advisory))) {
      return ["dev-only exception accepted", false];
    }
    return ["block: missing dev-only exception", true];
  }
  if (severity === "low") return ["triage before release", false];
  return ["block: unknown severity", true];
}

function exceptionKey(packageName, version, advisory) {
  return `${packageName ?? ""}\u0000${version ?? ""}\u0000${advisory ?? ""}`;
}

function isObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && /\S/.test(value);
}

function validFutureDate(value, today) {
  if (!nonEmptyString(value) || !/^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.test(value)) return false;
  return value >= today;
}

function renderReport(rows, blocking) {
  const lines = [
    "# RustSec Advisory Policy",
    "",
    "- High and critical advisories block.",
    "- Medium runtime advisories block; medium dev-only advisories require a matching, unexpired supply-chain exception.",
    "- Low advisories require triage before release.",
    "- Unknown severity blocks fail-closed.",
    "",
    "| Advisory | Package | Version | Severity | Scope | Decision | Title |",
    "| --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const row of rows) {
    lines.push(`| ${row.id} | ${row.package} | ${row.version} | ${row.severity} | ${row.scope} | ${row.decision} | ${row.title} |`);
  }
  lines.push("");
  lines.push(`Blocking advisories: ${blocking ? "yes" : "no"}`);
  lines.push("");
  return lines.join("\n");
}

function markdownEscape(value) {
  return String(value ?? "").replaceAll("|", "\\|").replace(/\r?\n/g, " ");
}
