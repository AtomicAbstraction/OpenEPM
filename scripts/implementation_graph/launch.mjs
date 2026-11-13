#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const project=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const pointer=JSON.parse(fs.readFileSync(path.join(project,'docs/implementation-graph/local-artifact.json'),'utf8'));
process.argv=[process.argv[0],process.argv[1],'--root',pointer.artifact,'--state',path.join(project,'docs/implementation-graph/annotations.json'),...process.argv.slice(2)];
await import('./server.mjs');
