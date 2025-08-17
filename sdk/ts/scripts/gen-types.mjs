#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
import s2o from 'swagger2openapi';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const specPath = path.resolve(__dirname, '..', '..', 'spec', 'openapi.json');
const outPath = path.resolve(__dirname, '..', 'src', 'generated', 'openapi.d.ts');
const cacheDir = path.resolve(__dirname, '..', '.cache');
const cachedOpenApi3Path = path.resolve(cacheDir, 'openapi3.json');
const execFile = promisify(execFileCb);

async function main() {
  const raw = await fs.readFile(specPath, 'utf8');
  let spec;
  try {
    spec = JSON.parse(raw);
  } catch (e) {
    console.error('Failed to parse spec at', specPath);
    throw e;
  }

  // We'll produce a path for the CLI (converted if needed)
  let inputPathForCli = specPath;
  // Convert Swagger 2.0 -> OpenAPI 3 before generating types
  if (spec && spec.swagger && String(spec.swagger).startsWith('2')) {
    const result = await s2o.convertObj(spec, { patch: true, warnOnly: true });
    const converted = result && result.openapi ? result.openapi : null;
    if (!converted) {
      throw new Error('swagger2openapi conversion failed: no openapi document returned');
    }
    await fs.mkdir(cacheDir, { recursive: true });
    await fs.writeFile(cachedOpenApi3Path, JSON.stringify(converted, null, 2), 'utf8');
    inputPathForCli = cachedOpenApi3Path;
  }

  // Ensure output directory exists
  await fs.mkdir(path.dirname(outPath), { recursive: true });

  // Invoke openapi-typescript CLI installed locally
  const binPath = path.resolve(__dirname, '..', 'node_modules', '.bin', process.platform === 'win32' ? 'openapi-typescript.cmd' : 'openapi-typescript');
  const args = [inputPathForCli, '--output', outPath, '--httpClient', 'fetch'];
  try {
    await execFile(binPath, args, { cwd: path.resolve(__dirname, '..') });
  } catch (e) {
    // Fallback: run via node to handle non-executable shebang scenarios
    const nodeBin = process.execPath;
    await execFile(nodeBin, [binPath, ...args], { cwd: path.resolve(__dirname, '..') });
  }
  console.log(`Generated types: ${path.relative(path.resolve(__dirname, '..'), outPath)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
