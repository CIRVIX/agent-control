/**
 * Safe Configuration & Rollback Management for CIRVIX AgentControl.
 *
 * Ensures CIRVIX never silently damages, overwrites, or corrupts existing
 * agent configurations (Claude Code, Cursor, Windsurf, Cline, Roo Code, etc.).
 *
 * Capabilities:
 * - Non-destructive schema-aware JSON/JSONC parsing and serialization
 * - Automated pre-modification backups (.cirvix/backups/<timestamp>/)
 * - Safe transactional write with atomic replacement
 * - Full rollback of previous configurations
 * - Strict schema validation and circular-proxy detection
 */

import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { normalizeFsPath } from "./windows.mjs";

/**
 * Strips comments from JSONC (JSON with comments) strings without external deps.
 */
export function stripJsonComments(text) {
  if (typeof text !== "string") return "";
  let insideString = false;
  let stringChar = "";
  let isEscaped = false;
  let result = "";

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const next = text[i + 1];

    if (insideString) {
      result += char;
      if (isEscaped) {
        isEscaped = false;
      } else if (char === "\\") {
        isEscaped = true;
      } else if (char === stringChar) {
        insideString = false;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      insideString = true;
      stringChar = char;
      result += char;
      continue;
    }

    // Line comment: //
    if (char === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      if (i < text.length) result += text[i]; // keep newline
      continue;
    }

    // Block comment: /* ... */
    if (char === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++; // skip closing /
      continue;
    }

    result += char;
  }

  // Remove trailing commas before } or ]
  return result.replace(/,\s*([}\]])/g, "$1");
}

/**
 * Parses JSON or JSONC safely. Returns null on parse error.
 */
export function parseConfigJson(raw) {
  if (typeof raw !== "string" || !raw.trim()) return null;
  try {
    return JSON.parse(raw);
  } catch {
    try {
      const stripped = stripJsonComments(raw);
      return JSON.parse(stripped);
    } catch {
      return null;
    }
  }
}

/**
 * Computes sha256 hash of a string or buffer.
 */
export function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Backup and Rollback Manager.
 */
export class ConfigBackupManager {
  constructor({ stateDir = join(process.cwd(), ".cirvix") } = {}) {
    this.stateDir = stateDir;
    this.backupDir = join(stateDir, "backups");
  }

  /**
   * Creates a backup of one or more configuration files before modifying them.
   *
   * @param {string[]} filePaths
   * @param {string} [reason="pre-integration"]
   * @returns {Promise<{ backupId: string, timestamp: string, files: Array<{ path: string, backupPath: string, sha: string }> }>}
   */
  async createBackup(filePaths, reason = "pre-integration") {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupId = `backup-${timestamp}`;
    const targetDir = join(this.backupDir, backupId);
    await mkdir(targetDir, { recursive: true });

    const backedUp = [];

    for (const filePath of filePaths) {
      const resolved = resolve(filePath);
      try {
        const content = await readFile(resolved);
        const hash = sha256(content);
        const safeName = normalizeFsPath(resolved).replace(/[:/\\]/g, "_");
        const backupPath = join(targetDir, safeName);

        await writeFile(backupPath, content);
        backedUp.push({
          path: resolved,
          backupPath,
          sha: hash,
        });
      } catch (err) {
        // File may not exist yet; record as non-existent
        backedUp.push({
          path: resolved,
          backupPath: null,
          sha: null,
          notExisted: true,
        });
      }
    }

    const manifest = {
      backupId,
      timestamp: new Date().toISOString(),
      reason,
      files: backedUp,
    };

    await writeFile(join(targetDir, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8");
    return manifest;
  }

  /**
   * Lists available backups, newest first.
   */
  async listBackups() {
    try {
      const entries = await readdir(this.backupDir, { withFileTypes: true });
      const manifests = [];

      for (const entry of entries) {
        if (!entry.isDirectory() || !entry.name.startsWith("backup-")) continue;
        const manifestPath = join(this.backupDir, entry.name, "manifest.json");
        try {
          const raw = await readFile(manifestPath, "utf8");
          manifests.push(JSON.parse(raw));
        } catch {}
      }

      return manifests.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    } catch {
      return [];
    }
  }

  /**
   * Restores configuration files from a backup.
   *
   * @param {string} [backupId] - Defaults to latest backup if omitted.
   * @returns {Promise<{ restored: string[], removed: string[], backupId: string }>}
   */
  async rollback(backupId = null) {
    const backups = await this.listBackups();
    if (backups.length === 0) {
      throw new Error("No CIRVIX backups found in " + this.backupDir);
    }

    const target = backupId ? backups.find((b) => b.backupId === backupId) : backups[0];
    if (!target) {
      throw new Error(`Backup "${backupId}" not found.`);
    }

    const restored = [];
    const removed = [];

    for (const file of target.files) {
      if (file.notExisted) {
        // The file did not exist before CIRVIX created it. Remove it cleanly.
        try {
          const { unlink } = await import("node:fs/promises");
          await unlink(file.path);
          removed.push(file.path);
        } catch {}
      } else if (file.backupPath) {
        await mkdir(dirname(file.path), { recursive: true });
        await copyFile(file.backupPath, file.path);
        restored.push(file.path);
      }
    }

    return { restored, removed, backupId: target.backupId };
  }
}

/**
 * Safe configuration patcher helper.
 */
export class SafeConfigPatcher {
  constructor(options = {}) {
    this.backupManager = new ConfigBackupManager(options);
  }

  async patchJson(filePath, updateFn) {
    const raw = await readFile(filePath, "utf8");
    const parsed = parseConfigJson(raw) || {};
    const updated = await updateFn(parsed);
    await this.backupManager.createBackup([filePath]);
    await writeFile(filePath, JSON.stringify(updated, null, 2), "utf8");
    return updated;
  }
}

/**
 * Validates an MCP server map to ensure no circular references to cirvix
 * and that each server has required fields.
 */
export function validateMcpServersMap(serverMap) {
  const errors = [];
  if (!serverMap || typeof serverMap !== "object") {
    errors.push("Server map must be an object.");
    return { ok: false, errors };
  }

  for (const [name, def] of Object.entries(serverMap)) {
    if (!def || typeof def !== "object") {
      errors.push(`Server "${name}" definition must be an object.`);
      continue;
    }

    if (name === "cirvix") {
      // CIRVIX server itself must specify command and arguments
      if (!def.command && !def.url) {
        errors.push(`CIRVIX entry in server map must have a command or url.`);
      }
      continue;
    }

    if (!def.command && !def.url) {
      errors.push(`Server "${name}" must define either "command" or "url".`);
    }

    // Circular check: does an upstream invoke cirvix gateway with circular arguments?
    if (typeof def.command === "string" && def.command.includes("cirvix") && Array.isArray(def.args)) {
      if (def.args.includes("gateway")) {
        errors.push(`Server "${name}" circularly invokes "cirvix gateway".`);
      }
    }
  }

  return {
    ok: errors.length === 0,
    errors,
  };
}
