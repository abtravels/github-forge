// github-forge — a GitHub-compatible git forge (make.fun github-core-clone-01).
// One process, Node 22 standard library only. In-memory store, deterministic state.
// Serves: git smart HTTP (upload-pack v2 + receive-pack v0), REST v3, GraphQL v4, MCP.
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const FIXED_TS = '2026-11-19T00:00:00Z';
const COMMIT_TS = 1700000000;
const SERVER_IDENTITY = 'adaiversen <adaiversen@example.invalid>';
const FORGE_VERSION = '1.0.0';
const ZERO_OID = '0000000000000000000000000000000000000000';
const AGENT_NAME = 'forge/1.0';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// ---------------------------------------------------------------- small helpers
function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function b64encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}
function b64decode(text: string): string {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64').toString('utf8');
}
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function isHex40(s: string): boolean {
  return /^[0-9a-f]{40}$/.test(s);
}

// ---------------------------------------------------------------- pkt-lines
function pktLine(data: string | Buffer): Buffer {
  const b = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const len = b.length + 4;
  return Buffer.concat([Buffer.from(len.toString(16).padStart(4, '0'), 'ascii'), b]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type PktItem = { kind: 'data'; data: Buffer } | { kind: 'flush' } | { kind: 'delim' };

function parsePktLines(buf: Buffer): { lines: PktItem[]; rest: Buffer } {
  const lines: PktItem[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const hex = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('malformed pkt-line');
    const len = parseInt(hex, 16);
    if (len === 0) {
      lines.push({ kind: 'flush' });
      off += 4;
      continue;
    }
    if (len === 1) {
      lines.push({ kind: 'delim' });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    lines.push({ kind: 'data', data: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { lines, rest: buf.subarray(off) };
}

// Parse pkt-lines until the first flush; everything after it is the rest (a pack).
function parsePktUntilFlush(buf: Buffer): { lines: PktItem[]; rest: Buffer } {
  const lines: PktItem[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const hex = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('malformed pkt-line');
    const len = parseInt(hex, 16);
    if (len === 0) {
      off += 4;
      return { lines, rest: buf.subarray(off) };
    }
    if (len === 1) {
      lines.push({ kind: 'delim' });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    lines.push({ kind: 'data', data: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { lines, rest: buf.subarray(off) };
}

function pktTextLines(lines: PktItem[]): string[] {
  const out: string[] = [];
  for (const item of lines) {
    if (item.kind === 'data') out.push(item.data.toString('utf8').replace(/\n$/, ''));
  }
  return out;
}

// sideband-64k framing: one pkt-line per chunk, first byte is the band (1 = data).
function sideband(data: Buffer | string): Buffer {
  const b = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const payload = Buffer.concat([Buffer.from([1]), b]);
  return pktLine(payload);
}
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const max = 65515;
  for (let off = 0; off < pack.length; off += max) {
    parts.push(sideband(pack.subarray(off, Math.min(pack.length, off + max))));
  }
  if (parts.length === 0) parts.push(sideband(Buffer.alloc(0)));
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- store
type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}
interface CommentRec {
  id: number;
  body: string;
}
interface IssueRec {
  globalId: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: CommentRec[];
}
interface PullRec {
  globalId: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  mergeSha: string | null;
  mergedAt: string | null;
}
interface LabelRec {
  name: string;
  color: string;
}
interface Repo {
  dbId: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  refs: Map<string, string>;
  objects: Map<string, GitObj>;
  labels: Map<string, LabelRec>;
  issues: Map<number, IssueRec>;
  pulls: Map<number, PullRec>;
  nextNumber: number;
  nextCommentId: number;
}

const repos = new Map<string, Repo>();
let nextDbId = 5000;
let nextGlobalId = 100000;
let reqCounter = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}
function getRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return repos.get(repoKey(owner, name)) ?? null;
}
function gid(kind: string, ...parts: (string | number)[]): string {
  return b64encode([kind, ...parts].join(':'));
}
function parseGid(id: string): { kind: string; parts: string[] } | null {
  try {
    const s = Buffer.from(id, 'base64').toString('utf8');
    const p = s.split(':');
    if (p.length < 2) return null;
    return { kind: p[0] as string, parts: p.slice(1) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- git objects
function oidOf(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}
function storeObj(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = oidOf(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

interface ParsedCommit {
  tree: string;
  parents: string[];
  message: string;
  authorName: string;
  authorEmail: string;
  authorTs: number;
  committerName: string;
  committerEmail: string;
  committerTs: number;
}
function parsePerson(line: string): { name: string; email: string; ts: number } {
  const m = /^(.*) <([^>]*)> (\d+) [+-]\d{4}$/.exec(line.trim());
  if (!m) return { name: line.trim(), email: '', ts: 0 };
  return { name: m[1] as string, email: m[2] as string, ts: parseInt(m[3] as string, 10) };
}
function parseCommit(data: Buffer): ParsedCommit {
  const text = data.toString('utf8');
  const idx = text.indexOf('\n\n');
  const head = idx === -1 ? text : text.slice(0, idx);
  const message = idx === -1 ? '' : text.slice(idx + 2);
  let tree = '';
  const parents: string[] = [];
  let author = { name: '', email: '', ts: 0 };
  let committer = { name: '', email: '', ts: 0 };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = parsePerson(line.slice(7));
    else if (line.startsWith('committer ')) committer = parsePerson(line.slice(10));
  }
  return {
    tree,
    parents,
    message,
    authorName: author.name,
    authorEmail: author.email,
    authorTs: author.ts,
    committerName: committer.name,
    committerEmail: committer.email,
    committerTs: committer.ts,
  };
}
function buildCommit(tree: string, parents: string[], message: string, ts: number = COMMIT_TS): Buffer {
  let s = `tree ${tree}\n`;
  for (const p of parents) s += `parent ${p}\n`;
  s += `author ${SERVER_IDENTITY} ${ts} +0000\n`;
  s += `committer ${SERVER_IDENTITY} ${ts} +0000\n`;
  s += `\n${message}`;
  return Buffer.from(s, 'utf8');
}
function parseTagTarget(data: Buffer): string | null {
  const text = data.toString('utf8');
  const head = text.split('\n\n')[0] as string;
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) return line.slice(7).trim();
  }
  return null;
}
function peelTag(repo: Repo, oid: string): string | null {
  let cur = oid;
  for (let i = 0; i < 10; i++) {
    const obj = repo.objects.get(cur);
    if (!obj) return null;
    if (obj.type === 'commit') return cur;
    if (obj.type === 'tag') {
      const t = parseTagTarget(obj.data);
      if (!t) return null;
      cur = t;
      continue;
    }
    return cur;
  }
  return null;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp === -1) break;
    const nul = data.indexOf(0x00, sp);
    if (nul === -1 || nul + 21 > data.length) break;
    entries.push({
      mode: data.subarray(off, sp).toString('utf8'),
      name: data.subarray(sp + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}
function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

// Flatten a tree into path -> {oid, mode}.
function treeToMap(repo: Repo, treeOid: string): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, prefix: string): void => {
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'tree') return;
    for (const e of parseTree(obj.data)) {
      const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
      if (e.mode === '40000') walk(e.oid, path);
      else out.set(path, { oid: e.oid, mode: e.mode });
    }
  };
  walk(treeOid, '');
  return out;
}
// Build a root tree oid from a flat path map.
function mapToTree(repo: Repo, map: Map<string, { oid: string; mode: string }>): string {
  return buildFromMap(repo, map, '');
}
function buildFromMap(repo: Repo, map: Map<string, { oid: string; mode: string }>, prefix: string): string {
  const entries: TreeEntry[] = [];
  const dirs = new Map<string, Map<string, { oid: string; mode: string }>>();
  for (const [path, v] of map) {
    const rel = prefix === '' ? path : path.slice(prefix.length + 1);
    const slash = rel.indexOf('/');
    if (slash === -1) {
      entries.push({ mode: v.mode, name: rel, oid: v.oid });
    } else {
      const dir = rel.slice(0, slash);
      let sub = dirs.get(dir);
      if (!sub) {
        sub = new Map();
        dirs.set(dir, sub);
      }
      sub.set(path, v);
    }
  }
  for (const [dir, sub] of dirs) {
    const subPrefix = prefix === '' ? dir : `${prefix}/${dir}`;
    entries.push({ mode: '40000', name: dir, oid: buildFromMap(repo, sub, subPrefix) });
  }
  return storeObj(repo, 'tree', buildTree(entries));
}

function ancestors(repo: Repo, start: string): Set<string> {
  const seen = new Set<string>();
  const stack = [start];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    seen.add(oid);
    for (const p of parseCommit(obj.data).parents) stack.push(p);
  }
  return seen;
}
function isAncestor(repo: Repo, anc: string, desc: string): boolean {
  if (anc === desc) return true;
  return ancestors(repo, desc).has(anc);
}
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const setA = ancestors(repo, a);
  const seen = new Set<string>();
  const queue = [b];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (setA.has(oid)) return oid;
    const obj = repo.objects.get(oid);
    if (obj && obj.type === 'commit') {
      for (const p of parseCommit(obj.data).parents) queue.push(p);
    }
  }
  return null;
}
// Every object reachable from the given roots (commits, trees, blobs, tags).
function reachableObjects(repo: Repo, roots: string[], stopAt?: Set<string>): Set<string> {
  const out = new Set<string>();
  const queue = [...roots];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (out.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    out.add(oid);
    if (obj.type === 'commit') {
      const pc = parseCommit(obj.data);
      // A commit in stopAt (a client's shallow boundary) is held with its
      // tree, but its parents are NOT held — do not traverse past it.
      queue.push(pc.tree);
      if (!stopAt?.has(oid)) queue.push(...pc.parents);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) queue.push(e.oid);
    } else if (obj.type === 'tag') {
      const t = parseTagTarget(obj.data);
      if (t) queue.push(t);
    }
  }
  return out;
}
function commitTimestamp(repo: Repo, oid: string): number {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return 0;
  return parseCommit(obj.data).committerTs;
}
// Commits reachable from a tip, newest first (timestamp desc, discovery order breaks ties).
function listCommits(repo: Repo, tip: string): string[] {
  const order: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    seen.add(oid);
    order.push(oid);
    for (const p of parseCommit(obj.data).parents) stack.push(p);
  }
  const indexOf = new Map(order.map((oid, i) => [oid, i] as [string, number]));
  return order.sort((a, b) => {
    const dt = commitTimestamp(repo, b) - commitTimestamp(repo, a);
    if (dt !== 0) return dt;
    return (indexOf.get(a) as number) - (indexOf.get(b) as number);
  });
}

// ---------------------------------------------------------------- packfiles
const OBJ_TYPE_NUM: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const NUM_OBJ_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function writePack(repo: Repo, oids: string[]): Buffer {
  const parts: Buffer[] = [Buffer.from('PACK', 'ascii')];
  const ver = Buffer.alloc(4);
  ver.writeUInt32BE(2, 0);
  parts.push(ver);
  const cnt = Buffer.alloc(4);
  cnt.writeUInt32BE(oids.length, 0);
  parts.push(cnt);
  for (const oid of oids) {
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    const data = obj.data;
    const typeNum = OBJ_TYPE_NUM[obj.type];
    let size = data.length;
    let first = (typeNum << 4) | (size & 0x0f);
    size >>= 4;
    const hbytes: number[] = [];
    if (size > 0) first |= 0x80;
    hbytes.push(first);
    while (size > 0) {
      let b = size & 0x7f;
      size >>= 7;
      if (size > 0) b |= 0x80;
      hbytes.push(b);
    }
    parts.push(Buffer.from(hbytes));
    parts.push(deflateSync(data, { level: 6 }));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let p = 0;
  const readVarint = (): number => {
    let v = 0;
    let s = 0;
    let b = 0;
    do {
      b = delta[p++] as number;
      v |= (b & 0x7f) << s;
      s += 7;
    } while (b & 0x80);
    return v;
  };
  readVarint();
  readVarint();
  const out: Buffer[] = [];
  while (p < delta.length) {
    const op = delta[p++] as number;
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      if (op & 0x01) cpOff = delta[p++] as number;
      if (op & 0x02) cpOff |= (delta[p++] as number) << 8;
      if (op & 0x04) cpOff |= (delta[p++] as number) << 16;
      if (op & 0x08) cpOff |= (delta[p++] as number) << 24;
      if (op & 0x10) cpSize = delta[p++] as number;
      if (op & 0x20) cpSize |= (delta[p++] as number) << 8;
      if (op & 0x40) cpSize |= (delta[p++] as number) << 16;
      if (cpSize === 0) cpSize = 0x10000;
      out.push(base.subarray(cpOff, cpOff + cpSize));
    } else if (op !== 0) {
      out.push(delta.subarray(p, p + op));
      p += op;
    } else {
      throw new Error('bad delta opcode 0');
    }
  }
  return Buffer.concat(out);
}

interface PackEntry {
  type: ObjType;
  data: Buffer;
}
function parsePack(buf: Buffer): PackEntry[] {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('bad pack header');
  }
  const count = buf.readUInt32BE(8);
  let off = 12;
  const out: PackEntry[] = [];
  const byOffset = new Map<number, { oid: string; type: ObjType; data: Buffer }>();
  for (let i = 0; i < count; i++) {
    const entryStart = off;
    let b = buf[off++] as number;
    const typeNum = (b >> 4) & 0x07;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[off++] as number;
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    void size;
    let type: ObjType;
    let data: Buffer;
    const inflateAt = (start: number, expectedSize: number): { data: Buffer; consumed: number } => {
      const tail = buf.subarray(start);
      const consumed = inflateStreamLength(tail, expectedSize);
      return { data: inflateSync(tail.subarray(0, consumed)), consumed };
    };
    if (typeNum === 6) {
      // OFS_DELTA: base is at (entryStart - offset)
      let b2 = buf[off++] as number;
      let deltaOff = b2 & 0x7f;
      while (b2 & 0x80) {
        b2 = buf[off++] as number;
        deltaOff = ((deltaOff + 1) << 7) | (b2 & 0x7f);
      }
      const base = byOffset.get(entryStart - deltaOff);
      if (!base) throw new Error('ofs-delta base not found');
      const { data: delta, consumed } = inflateAt(off, size);
      off += consumed;
      data = applyDelta(base.data, delta);
      type = base.type;
    } else if (typeNum === 7) {
      // REF_DELTA: 20-byte base oid follows the header
      const baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
      const base = out.find((e) => oidOf(e.type, e.data) === baseOid);
      if (!base) throw new Error('ref-delta base not found');
      const { data: delta, consumed } = inflateAt(off, size);
      off += consumed;
      data = applyDelta(base.data, delta);
      type = base.type;
    } else {
      type = NUM_OBJ_TYPE[typeNum] as ObjType;
      if (!type) throw new Error(`unknown pack object type ${typeNum}`);
      const inflated = inflateAt(off, size);
      data = inflated.data;
      off += inflated.consumed;
    }
    out.push({ type, data });
    byOffset.set(entryStart, { oid: oidOf(type, data), type, data });
  }
  return out;
}
// Length in bytes of the zlib stream starting at buf[0]. inflateSync ignores
// trailing bytes and throws on a truncated stream, so the predicate "the prefix
// inflates" is monotonic: binary-search the smallest successful prefix.
function inflateStreamLength(buf: Buffer, uncompressedSize: number): number {
  const hi = Math.min(buf.length, uncompressedSize + 4096);
  let lo = 0;
  let high = hi;
  const ok = (len: number): boolean => {
    try {
      inflateSync(buf.subarray(0, len));
      return true;
    } catch {
      return false;
    }
  };
  if (!ok(high)) {
    // Fall back to the whole tail (should not happen for well-formed packs).
    if (!ok(buf.length)) throw new Error('bad zlib stream in pack');
    high = buf.length;
  }
  while (lo < high) {
    const mid = Math.floor((lo + high) / 2);
    if (ok(mid)) high = mid;
    else lo = mid + 1;
  }
  return lo;
}

// ---------------------------------------------------------------- git smart HTTP
function allRefs(repo: Repo): { name: string; oid: string }[] {
  const out: { name: string; oid: string }[] = [];
  for (const [name, oid] of repo.refs) out.push({ name, oid });
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return out;
}

function advertiseUploadPackV2(): Buffer {
  return Buffer.concat([
    pktLine('# service=git-upload-pack\n'),
    PKT_FLUSH,
    pktLine('version 2\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow wait-for-done filter\n'),
    pktLine('server-option\n'),
    pktLine('object-format=sha1\n'),
    pktLine(`agent=${AGENT_NAME}\n`),
    PKT_FLUSH,
  ]);
}

function advertiseReceivePack(repo: Repo): Buffer {
  const caps = `report-status side-band-64k delete-refs ofs-delta agent=${AGENT_NAME}`;
  const parts: Buffer[] = [pktLine('# service=git-receive-pack\n'), PKT_FLUSH];
  const refs = allRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    refs.forEach((r, i) => {
      parts.push(pktLine(i === 0 ? `${r.oid} ${r.name}\0${caps}\n` : `${r.oid} ${r.name}\n`));
    });
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function handleLsRefs(repo: Repo, args: string[]): Buffer {
  const prefixes: string[] = [];
  let peel = false;
  let symrefs = false;
  let unborn = false;
  for (const a of args) {
    if (a === 'peel') peel = true;
    else if (a === 'symrefs') symrefs = true;
    else if (a === 'unborn') unborn = true;
    else if (a.startsWith('ref-prefix ')) prefixes.push(a.slice('ref-prefix '.length));
  }
  const include = (name: string): boolean =>
    prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const out: Buffer[] = [];
  const mainTip = repo.refs.get('refs/heads/main');
  if (include('HEAD')) {
    if (mainTip) {
      out.push(pktLine(`${mainTip} HEAD symref-target:refs/heads/main\n`));
    } else if (unborn) {
      out.push(pktLine('unborn HEAD symref-target:refs/heads/main\n'));
    }
  }
  void symrefs;
  for (const r of allRefs(repo)) {
    if (!include(r.name)) continue;
    let line = `${r.oid} ${r.name}`;
    if (r.name.startsWith('refs/tags/')) {
      const peeled = peelTag(repo, r.oid);
      if (peeled) line += ` peeled:${peeled}`;
    }
    void peel;
    out.push(pktLine(`${line}\n`));
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}

// Commits within `depth` generations of the wants (depth 1 = wants only).
function commitsWithinDepth(
  repo: Repo,
  wants: string[],
  depth: number | null,
): { included: Set<string>; boundary: Set<string> } {
  const included = new Set<string>();
  const boundary = new Set<string>();
  const seen = new Set<string>();
  const queue: { oid: string; d: number }[] = wants.map((w) => ({ oid: w, d: 1 }));
  while (queue.length > 0) {
    const cur = queue.shift() as { oid: string; d: number };
    if (seen.has(cur.oid)) continue;
    seen.add(cur.oid);
    const obj = repo.objects.get(cur.oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      included.add(cur.oid);
      const target = parseTagTarget(obj.data);
      if (target) queue.push({ oid: target, d: cur.d });
      continue;
    }
    if (obj.type !== 'commit') continue;
    included.add(cur.oid);
    const pc = parseCommit(obj.data);
    if (depth === null || cur.d < depth) {
      for (const p of pc.parents) queue.push({ oid: p, d: cur.d + 1 });
    } else {
      boundary.add(cur.oid);
    }
  }
  return { included, boundary };
}

// Objects belonging to exactly these commits: the commits themselves, their
// trees and blobs, and any tag objects among them — but never a parent commit
// that is not itself in the set (a shallow fetch must not leak history).
function objectsForCommits(repo: Repo, commits: Set<string>): Set<string> {
  const out = new Set<string>();
  const addTree = (treeOid: string): void => {
    if (out.has(treeOid)) return;
    const obj = repo.objects.get(treeOid);
    if (!obj || obj.type !== 'tree') return;
    out.add(treeOid);
    for (const e of parseTree(obj.data)) {
      const child = repo.objects.get(e.oid);
      if (child?.type === 'tree') addTree(e.oid);
      else if (child) out.add(e.oid);
    }
  };
  for (const oid of commits) {
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    out.add(oid);
    if (obj.type === 'commit') {
      const treeOid = parseCommit(obj.data).tree;
      if (treeOid) addTree(treeOid);
    } else if (obj.type === 'tag') {
      const target = parseTagTarget(obj.data);
      if (target && commits.has(target)) {
        const t = repo.objects.get(target);
        if (t?.type === 'commit') {
          const treeOid = parseCommit(t.data).tree;
          if (treeOid) addTree(treeOid);
        }
      }
    }
  }
  return out;
}

function handleFetch(repo: Repo, args: string[]): Buffer {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallows: string[] = [];
  let deepen: number | null = null;
  for (const a of args) {
    if (a.startsWith('want ')) wants.push(a.slice(5).trim());
    else if (a.startsWith('have ')) haves.push(a.slice(5).trim());
    else if (a.startsWith('shallow ')) shallows.push(a.slice(8).trim());
    else if (a.startsWith('deepen ')) {
      const n = parseInt(a.slice(7), 10);
      if (Number.isFinite(n) && n > 0) deepen = n;
    }
    // ignored: thin-pack, no-progress, ofs-delta, filter, wait-for-done, done
  }

  const haveClosure = reachableObjects(repo, haves, new Set(shallows));
  let sendObjects: Set<string>;
  const shallowOut: string[] = [];
  const unshallowOut: string[] = [];
  if (deepen !== null) {
    const { included, boundary } = commitsWithinDepth(repo, wants, deepen);
    const fromIncluded = objectsForCommits(repo, included);
    sendObjects = new Set([...fromIncluded].filter((o) => !haveClosure.has(o)));
    for (const c of boundary) {
      if (!haveClosure.has(c)) shallowOut.push(c);
    }
    for (const s of shallows) {
      if (included.has(s) && !shallowOut.includes(s)) unshallowOut.push(s);
    }
  } else {
    const wantObjs = reachableObjects(repo, wants);
    sendObjects = new Set([...wantObjs].filter((o) => !haveClosure.has(o)));
    for (const s of shallows) shallowOut.push(s);
  }

  // acknowledgments: ACK every have that is an ancestor of a want, else NAK.
  // When the client said 'done' it skips ack processing entirely and goes
  // straight to the packfile (git fetch-pack: send_fetch_request returns true
  // on 'done', so FETCH_GET_PACK expects shallow-info / wanted-refs /
  // packfile — an 'acknowledgments' section there dies with
  // "expected 'packfile', received 'acknowledgments'"). The ack section is
  // only for a negotiation round without 'done', answered with acks + flush.
  const ackLines: string[] = [];
  for (const h of haves) {
    let isAnc = false;
    for (const w of wants) {
      if (isAncestor(repo, h, w)) {
        isAnc = true;
        break;
      }
    }
    if (isAnc) ackLines.push(`ACK ${h}\n`);
  }
  if (ackLines.length === 0) ackLines.push('NAK\n');
  const hasDone = args.includes('done');

  // wanted-refs: every want that matches a ref tip (or a tag's peeled commit),
  // each ref named once even when several wants resolve to it.
  const refLines: string[] = [];
  const seenRefs = new Set<string>();
  for (const w of wants) {
    for (const r of allRefs(repo)) {
      if (seenRefs.has(r.name)) continue;
      if (r.oid === w) {
        refLines.push(`${r.oid} ${r.name}\n`);
        seenRefs.add(r.name);
      } else if (r.name.startsWith('refs/tags/')) {
        const peeled = peelTag(repo, r.oid);
        if (peeled === w) {
          refLines.push(`${r.oid} ${r.name}\n`);
          seenRefs.add(r.name);
        }
      }
    }
  }

  const parts: Buffer[] = [];
  if (!hasDone) {
    parts.push(pktLine('acknowledgments\n'));
    for (const l of ackLines) parts.push(pktLine(l));
    parts.push(PKT_FLUSH);
    return Buffer.concat(parts);
  }
  if (shallowOut.length > 0 || unshallowOut.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of shallowOut) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallowOut) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(PKT_DELIM);
  }
  if (refLines.length > 0) {
    parts.push(pktLine('wanted-refs\n'));
    for (const l of refLines) parts.push(pktLine(l));
    parts.push(PKT_DELIM);
  }
  const pack = writePack(repo, [...sendObjects].sort());
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

// Minimal v0 upload-pack (the suite always speaks v2; real git falls back to v0).
// Response: NAK, flush, then the pack (sideband-framed when negotiated).
function handleUploadPackV0(repo: Repo, body: Buffer): Buffer {
  const { lines } = parsePktLines(body);
  const texts = pktTextLines(lines);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallows: string[] = [];
  let sideband64k = false;
  for (const t of texts) {
    if (t.startsWith('want ')) {
      const rest = t.slice(5);
      const sp = rest.indexOf(' ');
      wants.push(sp === -1 ? rest.trim() : rest.slice(0, sp));
      if (rest.includes('side-band-64k')) sideband64k = true;
    } else if (t.startsWith('have ')) {
      haves.push(t.slice(5).trim());
    } else if (t.startsWith('shallow ')) {
      shallows.push(t.slice(8).trim());
    }
  }
  const haveClosure = reachableObjects(repo, haves, new Set(shallows));
  const wantObjs = reachableObjects(repo, wants);
  const send = [...wantObjs].filter((o) => !haveClosure.has(o)).sort();
  const pack = writePack(repo, send);
  const out: Buffer[] = [pktLine('NAK\n'), PKT_FLUSH];
  if (sideband64k) out.push(sidebandPack(pack));
  else out.push(pack);
  return Buffer.concat(out);
}

// The advertisement git's HTTP transport asks for with a POST: the client sends
// bare ref lines (upload-pack) or refspecs (receive-pack) and the server echoes
// them, then a flush, then the ref advertisement, then a flush.
function probeUploadPackResponse(repo: Repo, echoLines: string[], v2: boolean): Buffer {
  const parts: Buffer[] = [];
  for (const l of echoLines) parts.push(pktLine(`${l}\n`));
  parts.push(PKT_FLUSH);
  if (v2) {
    parts.push(pktLine('version 2\n'));
    parts.push(pktLine('ls-refs=unborn\n'));
    parts.push(pktLine('fetch=shallow wait-for-done filter\n'));
    parts.push(pktLine('server-option\n'));
    parts.push(pktLine('object-format=sha1\n'));
    parts.push(pktLine(`agent=${AGENT_NAME}\n`));
  } else {
    const caps = 'multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not no-progress include-tag multi_ack_detailed no-done object-format=sha1';
    const refs = allRefs(repo);
    if (refs.length === 0) {
      parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps} agent=${AGENT_NAME}\n`));
    } else {
      refs.forEach((r, i) => {
        parts.push(pktLine(i === 0 ? `${r.oid} ${r.name}\0${caps} agent=${AGENT_NAME}\n` : `${r.oid} ${r.name}\n`));
      });
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}
function probeReceivePackResponse(repo: Repo, echoLines: string[]): Buffer {
  const parts: Buffer[] = [];
  for (const l of echoLines) parts.push(pktLine(`${l}\n`));
  parts.push(PKT_FLUSH);
  const caps = `report-status side-band-64k delete-refs ofs-delta agent=${AGENT_NAME}`;
  const refs = allRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    refs.forEach((r, i) => {
      parts.push(pktLine(i === 0 ? `${r.oid} ${r.name}\0${caps}\n` : `${r.oid} ${r.name}\n`));
    });
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

interface PushReport {
  ref: string;
  ok: boolean;
  reason: string;
}
function handleReceivePack(repo: Repo, body: Buffer): { status: number; body: Buffer } {
  const { lines, rest } = parsePktUntilFlush(body);
  const texts = pktTextLines(lines);
  const cmdRe = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)\s*$/;
  const probeRe = /^refs\/\S+(:refs\/\S+)?$/;
  const hasCommand = texts.some((t) => {
    const nul = t.indexOf('\0');
    return cmdRe.test((nul === -1 ? t : t.slice(0, nul)).trim());
  });
  if (!hasCommand) {
    // A probe (advertisement request): echo the refspecs, or 400 for garbage.
    if (texts.length > 0 && texts.every((t) => probeRe.test(t.trim()))) {
      return { status: 200, body: probeReceivePackResponse(repo, texts.map((t) => t.trim())) };
    }
    if (texts.length === 0) {
      return { status: 200, body: probeReceivePackResponse(repo, []) };
    }
    throw new Error('bad receive-pack command line');
  }
  const commands: { oldOid: string; newOid: string; ref: string }[] = [];
  let useSideband = false;
  for (const t of texts) {
    const nul = t.indexOf('\0');
    const cmdPart = nul === -1 ? t : t.slice(0, nul);
    if (nul !== -1 && t.includes('side-band-64k')) useSideband = true;
    const m = cmdRe.exec(cmdPart.trim());
    if (!m) throw new Error('bad receive-pack command line');
    commands.push({ oldOid: m[1] as string, newOid: m[2] as string, ref: m[3] as string });
  }
  if (rest.length > 0) {
    const objs = parsePack(rest);
    for (const o of objs) storeObj(repo, o.type, o.data);
  }
  const results: PushReport[] = [];
  for (const cmd of commands) {
    const current = repo.refs.get(cmd.ref);
    if (cmd.newOid === ZERO_OID) {
      // delete
      if (current === undefined) {
        results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      } else {
        repo.refs.delete(cmd.ref);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
    } else if (cmd.oldOid === ZERO_OID) {
      // create
      if (current !== undefined) {
        results.push({ ref: cmd.ref, ok: false, reason: 'already exists' });
      } else if (!repo.objects.has(cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'invalid object' });
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
    } else {
      if (current === undefined) {
        results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      } else if (current !== cmd.oldOid) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      } else if (!repo.objects.has(cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'invalid object' });
      } else if (cmd.ref.startsWith('refs/tags/')) {
        repo.refs.set(cmd.ref, cmd.newOid);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      } else if (isAncestor(repo, cmd.oldOid, cmd.newOid)) {
        repo.refs.set(cmd.ref, cmd.newOid);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      } else {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      }
    }
  }
  // The report-status stream is itself pkt-framed; with side-band-64k the whole
  // framed stream rides inside band 1, followed by an outer flush.
  const inner: Buffer[] = [pktLine('unpack ok\n')];
  for (const r of results) {
    inner.push(pktLine(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`));
  }
  inner.push(PKT_FLUSH);
  const innerBuf = Buffer.concat(inner);
  if (useSideband) {
    const parts: Buffer[] = [];
    const max = 65515;
    for (let off = 0; off < innerBuf.length; off += max) {
      parts.push(sideband(innerBuf.subarray(off, Math.min(innerBuf.length, off + max))));
    }
    parts.push(PKT_FLUSH);
    return { status: 200, body: Buffer.concat(parts) };
  }
  return { status: 200, body: innerBuf };
}

// ---------------------------------------------------------------- HTTP helpers
function sendJson(res: ServerResponse, status: number, obj: unknown, extra: Record<string, string> = {}): void {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': body.length,
    'X-GitHub-Request-Id': `req-${++reqCounter}`,
    ...extra,
  });
  res.end(body);
}
function sendErr(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string, extra: Record<string, string> = {}): void {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': body.length,
    'X-GitHub-Request-Id': `req-${++reqCounter}`,
    ...extra,
  });
  res.end(body);
}
function sendNoContent(res: ServerResponse): void {
  res.writeHead(204, { 'X-GitHub-Request-Id': `req-${++reqCounter}` });
  res.end();
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      chunks.push(c);
      if (Buffer.concat(chunks).length > 64 * 1024 * 1024) {
        reject(new Error('body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function parseJsonBody(buf: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: null };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function paginate<T>(items: T[], query: URLSearchParams): { page: T[]; pageNum: number; perPage: number; totalPages: number } {
  const perPage = Math.min(100, Math.max(1, parseInt(query.get('per_page') ?? '30', 10) || 30));
  const pageNum = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), pageNum, perPage, totalPages };
}
function linkHeader(req: IncomingMessage, pathname: string, query: URLSearchParams, pageNum: number, perPage: number, totalPages: number): Record<string, string> {
  if (pageNum >= totalPages) return {};
  const base = `http://${req.headers.host ?? 'localhost'}${pathname}`;
  const next = new URL(base);
  for (const [k, v] of query) next.searchParams.set(k, v);
  next.searchParams.set('page', String(pageNum + 1));
  next.searchParams.set('per_page', String(perPage));
  const last = new URL(base);
  for (const [k, v] of query) last.searchParams.set(k, v);
  last.searchParams.set('page', String(totalPages));
  last.searchParams.set('per_page', String(perPage));
  return { Link: `<${next.toString()}>; rel="next", <${last.toString()}>; rel="last"` };
}

// ---------------------------------------------------------------- shared model ops (REST, GraphQL and MCP share these)
function createRepoInternal(name: string, description: string, isPrivate: boolean): { repo: Repo } | { error: string; status: number } {
  if (typeof name !== 'string' || name.trim() === '') {
    return { error: 'name is required', status: 422 };
  }
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    return { error: 'invalid repository name', status: 422 };
  }
  if (repos.has(repoKey(VIEWER_LOGIN, name))) {
    return { error: 'Repository already exists', status: 422 };
  }
  const repo: Repo = {
    dbId: nextDbId++,
    name,
    owner: VIEWER_LOGIN,
    description: description ?? '',
    isPrivate,
    refs: new Map(),
    objects: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
  };
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return { repo };
}
function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.dbId,
    node_id: gid('Repository', repo.dbId),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: 'main',
    created_at: FIXED_TS,
    updated_at: FIXED_TS,
    pushed_at: FIXED_TS,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://example.invalid/${repo.owner}/${repo.name}.git`,
    git_url: `git://example.invalid/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@example.invalid:${repo.owner}/${repo.name}.git`,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
  };
}
function issueJson(repo: Repo, iss: IssueRec): Record<string, unknown> {
  return {
    id: iss.globalId,
    node_id: gid('Issue', repo.dbId, iss.number),
    number: iss.number,
    title: iss.title,
    body: iss.body,
    state: iss.state,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    labels: iss.labels.map((n) => {
      const l = repo.labels.get(n);
      return l ? { name: l.name, color: l.color } : { name: n, color: '000000' };
    }),
    comments: iss.comments.length,
    created_at: FIXED_TS,
    updated_at: FIXED_TS,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${iss.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${iss.number}`,
  };
}
function pullJson(repo: Repo, pr: PullRec): Record<string, unknown> {
  return {
    id: pr.globalId,
    node_id: gid('PullRequest', repo.dbId, pr.number),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeSha,
    head: { ref: pr.headRef, sha: pr.headSha, label: `${VIEWER_LOGIN}:${pr.headRef}` },
    base: { ref: pr.baseRef, sha: pr.baseSha, label: `${VIEWER_LOGIN}:${pr.baseRef}` },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: FIXED_TS,
    updated_at: FIXED_TS,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`,
  };
}
function createIssueInternal(
  repo: Repo,
  title: string,
  body: string,
  labelNames: string[],
): { issue: IssueRec } | { error: string; status: number } {
  if (typeof title !== 'string' || title === '') {
    return { error: 'title is required', status: 422 };
  }
  for (const n of labelNames) {
    if (!repo.labels.has(n)) return { error: `Label '${n}' does not exist`, status: 422 };
  }
  const issue: IssueRec = {
    globalId: nextGlobalId++,
    number: repo.nextNumber++,
    title,
    body: body ?? '',
    state: 'open',
    labels: [...labelNames],
    comments: [],
  };
  repo.issues.set(issue.number, issue);
  return { issue };
}
function shortBranch(ref: string): string {
  // Accepts "feature", "refs/heads/feature", "owner:feature".
  if (ref.startsWith('refs/heads/')) return ref.slice('refs/heads/'.length);
  const colon = ref.indexOf(':');
  if (colon !== -1) return ref.slice(colon + 1);
  return ref;
}
function createPullInternal(
  repo: Repo,
  head: string,
  base: string,
  title: string,
  body: string,
): { pr: PullRec } | { error: string; status: number } {
  const headRef = shortBranch(head);
  const baseRef = shortBranch(base);
  const headSha = repo.refs.get(`refs/heads/${headRef}`);
  const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
  if (!headSha) return { error: `head branch '${headRef}' not found`, status: 422 };
  if (!baseSha) return { error: `base branch '${baseRef}' not found`, status: 422 };
  if (typeof title !== 'string' || title === '') {
    return { error: 'title is required', status: 422 };
  }
  for (const pr of repo.pulls.values()) {
    if (pr.state === 'open' && pr.headRef === headRef && pr.baseRef === baseRef) {
      return { error: 'a pull request already exists for this head and base', status: 422 };
    }
  }
  const pr: PullRec = {
    globalId: nextGlobalId++,
    number: repo.nextNumber++,
    title,
    body: body ?? '',
    state: 'open',
    merged: false,
    headRef,
    baseRef,
    headSha,
    baseSha,
    mergeSha: null,
    mergedAt: null,
  };
  repo.pulls.set(pr.number, pr);
  return { pr };
}
// Three-way merge of head into base tip. Returns the merged tree oid, or null on conflict.
function threeWayMerge(repo: Repo, baseTip: string, headTip: string): { tree: string } | null {
  const mb = mergeBase(repo, headTip, baseTip);
  const baseMap = mb ? treeToMap(repo, parseCommit(repo.objects.get(mb)?.data as Buffer).tree) : new Map<string, { oid: string; mode: string }>();
  const headMap = treeToMap(repo, parseCommit(repo.objects.get(headTip)?.data as Buffer).tree);
  const tipMap = treeToMap(repo, parseCommit(repo.objects.get(baseTip)?.data as Buffer).tree);
  const out = new Map<string, { oid: string; mode: string }>();
  const paths = new Set<string>([...baseMap.keys(), ...headMap.keys(), ...tipMap.keys()]);
  for (const p of paths) {
    const b = baseMap.get(p);
    const h = headMap.get(p);
    const t = tipMap.get(p);
    if (h?.oid === b?.oid) {
      if (t) out.set(p, t);
    } else if (t?.oid === b?.oid) {
      if (h) out.set(p, h);
    } else if (h?.oid === t?.oid) {
      if (h) out.set(p, h);
    } else {
      return null;
    }
  }
  return { tree: mapToTree(repo, out) };
}
function mergePullInternal(
  repo: Repo,
  pr: PullRec,
  commitTitle?: string,
): { sha: string; message: string } | { error: string; status: number } {
  if (pr.state !== 'open') {
    return { error: 'pull request is already closed', status: 405 };
  }
  const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!headTip || !baseTip) {
    return { error: 'head or base branch not found', status: 405 };
  }
  const merged = threeWayMerge(repo, baseTip, headTip);
  if (!merged) {
    return { error: 'merge conflict', status: 405 };
  }
  const message = commitTitle ?? `${pr.title} (#${pr.number})`;
  const commitOid = storeObj(repo, 'commit', buildCommit(merged.tree, [baseTip], message));
  repo.refs.set(`refs/heads/${pr.baseRef}`, commitOid);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = FIXED_TS;
  pr.mergeSha = commitOid;
  pr.baseSha = commitOid;
  return { sha: commitOid, message };
}
// Line diff (LCS) between two texts; returns [additions, deletions].
function lineDiff(oldText: string, newText: string): [number, number] {
  const a = splitLines(oldText);
  const b = splitLines(newText);
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      const row = dp[i] as number[];
      const below = dp[i + 1] as number[];
      row[j] = a[i] === b[j] ? (below[j + 1] as number) + 1 : Math.max(below[j] as number, row[j + 1] as number);
    }
  }
  const lcs = (dp[0] as number[])[0] as number;
  return [m - lcs, n - lcs];
}
function splitLines(text: string): string[] {
  if (text === '') return [];
  const parts = text.split('\n');
  if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
  return parts;
}

// ---------------------------------------------------------------- REST v3
function resolveRefTip(repo: Repo, ref: string | null): string | null {
  if (ref === null || ref === '') {
    return repo.refs.get('refs/heads/main') ?? null;
  }
  if (isHex40(ref)) {
    return repo.objects.has(ref) ? ref : null;
  }
  const byBranch = repo.refs.get(`refs/heads/${ref}`);
  if (byBranch) return byBranch;
  if (ref.startsWith('refs/')) return repo.refs.get(ref) ?? null;
  return null;
}
function commitJson(repo: Repo, oid: string): Record<string, unknown> {
  const obj = repo.objects.get(oid);
  const pc = obj ? parseCommit(obj.data) : null;
  const authorDate = pc ? new Date(pc.authorTs * 1000).toISOString() : FIXED_TS;
  const committerDate = pc ? new Date(pc.committerTs * 1000).toISOString() : FIXED_TS;
  return {
    sha: oid,
    node_id: gid('Commit', repo.dbId, oid),
    commit: {
      message: pc?.message ?? '',
      author: { name: pc?.authorName ?? '', email: pc?.authorEmail ?? '', date: authorDate },
      committer: { name: pc?.committerName ?? '', email: pc?.committerEmail ?? '', date: committerDate },
      tree: { sha: pc?.tree ?? '' },
    },
    parents: (pc?.parents ?? []).map((p) => ({ sha: p })),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/commit/${oid}`,
  };
}

async function handleRest(
  req: IncomingMessage,
  res: ServerResponse,
  pathname: string,
  query: URLSearchParams,
): Promise<void> {
  const method = (req.method ?? 'GET').toUpperCase();
  const segs = pathname.split('/').filter((s) => s !== '');
  // segs[0] = 'api', segs[1] = 'v3'
  const bodyBuf = method === 'GET' || method === 'HEAD' ? Buffer.alloc(0) : await readBody(req);
  let body: unknown = null;
  if (bodyBuf.length > 0) {
    const parsed = parseJsonBody(bodyBuf);
    if (!parsed.ok) {
      sendErr(res, 400, 'Invalid JSON body');
      return;
    }
    body = parsed.value;
  }

  // GET /api/v3
  if (segs.length === 2 && method === 'GET') {
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      user_repositories_url: '/api/v3/user/repos',
      meta_url: '/api/v3/meta',
    }, { 'X-OAuth-Scopes': 'repo, read:org' });
    return;
  }
  // GET /api/v3/meta
  if (segs.length === 3 && segs[2] === 'meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: FORGE_VERSION, verifiable_password_authentication: false });
    return;
  }
  // GET /api/v3/user
  if (segs.length === 3 && segs[2] === 'user' && method === 'GET') {
    sendJson(res, 200, {
      login: VIEWER_LOGIN,
      id: VIEWER_ID,
      node_id: gid('User', VIEWER_ID),
      name: VIEWER_NAME,
      email: VIEWER_EMAIL,
      type: 'User',
      html_url: `https://example.invalid/${VIEWER_LOGIN}`,
      url: '/api/v3/user',
    });
    return;
  }
  // /api/v3/user/repos
  if (segs.length === 4 && segs[2] === 'user' && segs[3] === 'repos') {
    if (method === 'GET') {
      const list = [...repos.values()]
        .filter((r) => r.owner === VIEWER_LOGIN)
        .map((r) => repoJson(r));
      const { page, pageNum, perPage, totalPages } = paginate(list, query);
      sendJson(res, 200, page, linkHeader(req, pathname, query, pageNum, perPage, totalPages));
      return;
    }
    if (method === 'POST') {
      if (!isRecord(body)) {
        sendErr(res, 422, 'repository name is required');
        return;
      }
      const result = createRepoInternal(
        String(body.name ?? ''),
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      if ('error' in result) {
        sendErr(res, result.status, result.error);
        return;
      }
      sendJson(res, 201, repoJson(result.repo));
      return;
    }
  }
  // /api/v3/repos/{owner}/{repo}[...]
  if (segs.length >= 4 && segs[2] === 'repos') {
    const owner = decodeURIComponent(segs[3] as string);
    const repoName = decodeURIComponent(segs[4] as string);
    const repo = getRepo(owner, repoName);
    if (!repo) {
      sendErr(res, 404, 'Not Found');
      return;
    }
    const rest = segs.slice(5);
    // GET/PATCH/DELETE /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'PATCH') {
        if (isRecord(body)) {
          if (typeof body.description === 'string') repo.description = body.description;
          if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        }
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, repoName));
        sendNoContent(res);
        return;
      }
    }
    // branches
    if (rest.length === 1 && rest[0] === 'branches' && method === 'GET') {
      const list = allRefs(repo)
        .filter((r) => r.name.startsWith('refs/heads/'))
        .map((r) => ({ name: r.name.slice('refs/heads/'.length), commit: { sha: r.oid }, protected: false }));
      sendJson(res, 200, list);
      return;
    }
    if (rest.length === 2 && rest[0] === 'branches' && method === 'GET') {
      const branch = decodeURIComponent(rest[1] as string);
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (!tip) {
        sendErr(res, 404, 'Branch not found');
        return;
      }
      sendJson(res, 200, { name: branch, commit: { sha: tip }, protected: false });
      return;
    }
    // commits
    if (rest.length === 1 && rest[0] === 'commits' && method === 'GET') {
      const tip = resolveRefTip(repo, query.get('sha'));
      if (!tip) {
        sendErr(res, 404, 'No commits found');
        return;
      }
      const list = listCommits(repo, tip).map((oid) => commitJson(repo, oid));
      const { page, pageNum, perPage, totalPages } = paginate(list, query);
      sendJson(res, 200, page, linkHeader(req, pathname, query, pageNum, perPage, totalPages));
      return;
    }
    if (rest.length === 2 && rest[0] === 'commits' && method === 'GET') {
      const sha = decodeURIComponent(rest[1] as string);
      const obj = repo.objects.get(sha);
      if (!obj || obj.type !== 'commit') {
        sendErr(res, 404, 'Commit not found');
        return;
      }
      sendJson(res, 200, commitJson(repo, sha));
      return;
    }
    // git/refs
    if (rest.length === 2 && rest[0] === 'git' && rest[1] === 'refs' && method === 'POST') {
      if (!isRecord(body) || typeof body.ref !== 'string' || typeof body.sha !== 'string') {
        sendErr(res, 422, 'ref and sha are required');
        return;
      }
      const ref = body.ref as string;
      const sha = body.sha as string;
      if (!ref.startsWith('refs/')) {
        sendErr(res, 422, 'ref must start with refs/');
        return;
      }
      if (!repo.objects.has(sha)) {
        sendErr(res, 422, 'object does not exist');
        return;
      }
      if (repo.refs.has(ref)) {
        sendErr(res, 422, 'Reference already exists');
        return;
      }
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, object: { sha }, node_id: gid('Ref', repo.dbId, ref) });
      return;
    }
    if (rest.length === 4 && rest[0] === 'git' && rest[1] === 'refs' && rest[2] === 'heads' && method === 'GET') {
      const branch = decodeURIComponent(rest[3] as string);
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (!tip) {
        sendErr(res, 404, 'Reference not found');
        return;
      }
      sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha: tip } });
      return;
    }
    // contents
    if (rest[0] === 'contents') {
      await handleContents(req, res, repo, rest.slice(1), query, method, body);
      return;
    }
    // labels
    if (rest.length === 1 && rest[0] === 'labels') {
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color, description: null, default: false })));
        return;
      }
      if (method === 'POST') {
        if (!isRecord(body) || typeof body.name !== 'string' || body.name === '') {
          sendErr(res, 422, 'label name is required');
          return;
        }
        const name = body.name as string;
        const color = typeof body.color === 'string' ? body.color.replace(/^#/, '') : '000000';
        if (repo.labels.has(name)) {
          sendErr(res, 422, 'Label already exists');
          return;
        }
        repo.labels.set(name, { name, color });
        sendJson(res, 201, { name, color, description: null, default: false, url: `/api/v3/repos/${owner}/${repoName}/labels/${encodeURIComponent(name)}` });
        return;
      }
    }
    // issues / pulls
    if (rest[0] === 'issues' || rest[0] === 'pulls') {
      await handleIssuesPulls(req, res, repo, rest, query, method, body, pathname);
      return;
    }
  }
  sendErr(res, 404, 'Not Found');
}

async function handleContents(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  pathSegs: string[],
  query: URLSearchParams,
  method: string,
  body: unknown,
): Promise<void> {
  const path = pathSegs.map((s) => decodeURIComponent(s)).join('/');
  const branch = typeof query.get('branch') === 'string' ? (query.get('branch') as string) : 'main';
  const refParam = query.get('ref');
  if (method === 'GET') {
    const tip = resolveRefTip(repo, refParam ?? branch);
    if (!tip) {
      sendErr(res, 404, 'Not Found');
      return;
    }
    const pc = parseCommit((repo.objects.get(tip) as GitObj).data);
    const map = treeToMap(repo, pc.tree);
    if (path === '') {
      // root listing
      const entries: Record<string, unknown>[] = [];
      const seen = new Set<string>();
      for (const p of [...map.keys()].sort()) {
        const top = p.split('/')[0] as string;
        if (seen.has(top)) continue;
        seen.add(top);
        if (p === top) {
          const v = map.get(p) as { oid: string; mode: string };
          entries.push({ type: 'file', name: top, path: top, sha: v.oid, size: (repo.objects.get(v.oid) as GitObj).data.length });
        } else {
          entries.push({ type: 'dir', name: top, path: top, sha: dirTreeOid(repo, pc.tree, top) });
        }
      }
      sendJson(res, 200, entries);
      return;
    }
    const file = map.get(path);
    if (file) {
      const data = (repo.objects.get(file.oid) as GitObj).data;
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        size: data.length,
        name: path.split('/').pop(),
        path,
        content: data.toString('base64'),
        sha: file.oid,
        url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}`,
      });
      return;
    }
    // directory listing?
    const prefix = `${path}/`;
    const entries: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    for (const p of [...map.keys()].sort()) {
      if (!p.startsWith(prefix)) continue;
      const rel = p.slice(prefix.length);
      const top = rel.split('/')[0] as string;
      if (seen.has(top)) continue;
      seen.add(top);
      if (rel === top) {
        const v = map.get(p) as { oid: string; mode: string };
        entries.push({ type: 'file', name: top, path: `${path}/${top}`, sha: v.oid, size: (repo.objects.get(v.oid) as GitObj).data.length });
      } else {
        entries.push({ type: 'dir', name: top, path: `${path}/${top}`, sha: dirTreeOid(repo, pc.tree, path) });
      }
    }
    if (entries.length === 0) {
      sendErr(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, entries);
    return;
  }
  if (method === 'PUT') {
    if (!isRecord(body) || typeof body.content !== 'string' || typeof body.message !== 'string') {
      sendErr(res, 422, 'content and message are required');
      return;
    }
    const targetBranch = typeof body.branch === 'string' ? (body.branch as string) : 'main';
    const tip = repo.refs.get(`refs/heads/${targetBranch}`);
    const map = tip ? treeToMap(repo, parseCommit((repo.objects.get(tip) as GitObj).data).tree) : new Map<string, { oid: string; mode: string }>();
    const existing = map.get(path);
    const contentBuf = Buffer.from((body.content as string).replace(/[\r\n\t ]+/g, ''), 'base64');
    if (typeof body.sha === 'string') {
      if (!existing || existing.oid !== (body.sha as string)) {
        sendErr(res, 409, 'sha does not match the current file');
        return;
      }
    } else if (existing) {
      sendErr(res, 422, 'file already exists');
      return;
    }
    const blobOid = storeObj(repo, 'blob', contentBuf);
    map.set(path, { oid: blobOid, mode: '100644' });
    const treeOid = mapToTree(repo, map);
    const message = body.message as string;
    const commitOid = storeObj(repo, 'commit', buildCommit(treeOid, tip ? [tip] : [], message));
    repo.refs.set(`refs/heads/${targetBranch}`, commitOid);
    sendJson(res, existing ? 200 : 201, {
      content: {
        name: path.split('/').pop(),
        path,
        sha: blobOid,
        size: contentBuf.length,
        encoding: 'base64',
        content: contentBuf.toString('base64'),
      },
      commit: { sha: commitOid, message },
    });
    return;
  }
  if (method === 'DELETE') {
    if (!isRecord(body) || typeof body.sha !== 'string' || typeof body.message !== 'string') {
      sendErr(res, 422, 'sha and message are required');
      return;
    }
    const targetBranch = typeof body.branch === 'string' ? (body.branch as string) : 'main';
    const tip = repo.refs.get(`refs/heads/${targetBranch}`);
    if (!tip) {
      sendErr(res, 404, 'Not Found');
      return;
    }
    const map = treeToMap(repo, parseCommit((repo.objects.get(tip) as GitObj).data).tree);
    const existing = map.get(path);
    if (!existing) {
      sendErr(res, 404, 'Not Found');
      return;
    }
    if (existing.oid !== (body.sha as string)) {
      sendErr(res, 409, 'sha does not match the current file');
      return;
    }
    map.delete(path);
    const treeOid = mapToTree(repo, map);
    const message = body.message as string;
    const commitOid = storeObj(repo, 'commit', buildCommit(treeOid, [tip], message));
    repo.refs.set(`refs/heads/${targetBranch}`, commitOid);
    sendJson(res, 200, { commit: { sha: commitOid, message }, content: null });
    return;
  }
  sendErr(res, 404, 'Not Found');
}
function dirTreeOid(repo: Repo, rootTreeOid: string, dirPath: string): string {
  const parts = dirPath.split('/');
  let cur = rootTreeOid;
  for (const part of parts) {
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'tree') return ZERO_OID;
    const entry = parseTree(obj.data).find((e) => e.name === part && e.mode === '40000');
    if (!entry) return ZERO_OID;
    cur = entry.oid;
  }
  return cur;
}

async function handleIssuesPulls(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  rest: string[],
  query: URLSearchParams,
  method: string,
  body: unknown,
  pathname: string,
): Promise<void> {
  const kind = rest[0] as string; // 'issues' | 'pulls'
  if (kind === 'issues') {
    if (rest.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const direction = query.get('direction') ?? 'asc';
        let list = [...repo.issues.values()];
        if (state === 'open') list = list.filter((i) => i.state === 'open');
        else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
        list.sort((a, b) => (direction === 'desc' ? b.number - a.number : a.number - b.number));
        const { page, pageNum, perPage, totalPages } = paginate(list.map((i) => issueJson(repo, i)), query);
        sendJson(res, 200, page, linkHeader(req, pathname, query, pageNum, perPage, totalPages));
        return;
      }
      if (method === 'POST') {
        if (!isRecord(body)) {
          sendErr(res, 422, 'title is required');
          return;
        }
        const labels = Array.isArray(body.labels) ? (body.labels as unknown[]).map(String) : [];
        const result = createIssueInternal(
          repo,
          typeof body.title === 'string' ? body.title : '',
          typeof body.body === 'string' ? body.body : '',
          labels,
        );
        if ('error' in result) {
          sendErr(res, result.status, result.error);
          return;
        }
        sendJson(res, 201, issueJson(repo, result.issue));
        return;
      }
    }
    if (rest.length === 2) {
      const n = parseInt(rest[1] as string, 10);
      const iss = repo.issues.get(n);
      if (!iss) {
        sendErr(res, 404, 'Issue not found');
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, issueJson(repo, iss));
        return;
      }
      if (method === 'PATCH') {
        if (isRecord(body)) {
          if (body.state === 'open' || body.state === 'closed') iss.state = body.state;
          if (typeof body.title === 'string') iss.title = body.title;
          if (typeof body.body === 'string') iss.body = body.body;
        }
        sendJson(res, 200, issueJson(repo, iss));
        return;
      }
    }
    if (rest.length === 3 && rest[2] === 'comments') {
      const n = parseInt(rest[1] as string, 10);
      const iss = repo.issues.get(n);
      if (!iss) {
        sendErr(res, 404, 'Issue not found');
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, iss.comments.map((c) => ({
          id: c.id,
          node_id: gid('IssueComment', repo.dbId, iss.number, c.id),
          body: c.body,
          user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
          created_at: FIXED_TS,
          updated_at: FIXED_TS,
        })));
        return;
      }
      if (method === 'POST') {
        if (!isRecord(body) || typeof body.body !== 'string' || body.body === '') {
          sendErr(res, 422, 'body is required');
          return;
        }
        const comment: CommentRec = { id: repo.nextCommentId++, body: body.body as string };
        iss.comments.push(comment);
        sendJson(res, 201, {
          id: comment.id,
          node_id: gid('IssueComment', repo.dbId, iss.number, comment.id),
          body: comment.body,
          user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
          created_at: FIXED_TS,
          updated_at: FIXED_TS,
        });
        return;
      }
    }
    sendErr(res, 404, 'Not Found');
    return;
  }
  // pulls
  if (rest.length === 1) {
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      const direction = query.get('direction') ?? 'asc';
      let list = [...repo.pulls.values()];
      if (state === 'open') list = list.filter((p) => p.state === 'open');
      else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
      list.sort((a, b) => (direction === 'desc' ? b.number - a.number : a.number - b.number));
      const { page, pageNum, perPage, totalPages } = paginate(list.map((p) => pullJson(repo, p)), query);
      sendJson(res, 200, page, linkHeader(req, pathname, query, pageNum, perPage, totalPages));
      return;
    }
    if (method === 'POST') {
      if (!isRecord(body)) {
        sendErr(res, 422, 'title, head and base are required');
        return;
      }
      const result = createPullInternal(
        repo,
        typeof body.head === 'string' ? body.head : '',
        typeof body.base === 'string' ? body.base : '',
        typeof body.title === 'string' ? body.title : '',
        typeof body.body === 'string' ? body.body : '',
      );
      if ('error' in result) {
        sendErr(res, result.status, result.error);
        return;
      }
      sendJson(res, 201, pullJson(repo, result.pr));
      return;
    }
  }
  if (rest.length === 2) {
    const n = parseInt(rest[1] as string, 10);
    const pr = repo.pulls.get(n);
    if (!pr) {
      sendErr(res, 404, 'Pull request not found');
      return;
    }
    if (method === 'GET') {
      sendJson(res, 200, pullJson(repo, pr));
      return;
    }
  }
  if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
    const n = parseInt(rest[1] as string, 10);
    const pr = repo.pulls.get(n);
    if (!pr) {
      sendErr(res, 404, 'Pull request not found');
      return;
    }
    const files = pullFiles(repo, pr);
    if (!files) {
      sendErr(res, 404, 'Pull request not found');
      return;
    }
    sendJson(res, 200, files);
    return;
  }
  if (rest.length === 3 && rest[2] === 'merge') {
    const n = parseInt(rest[1] as string, 10);
    const pr = repo.pulls.get(n);
    if (method === 'GET') {
      if (!pr || !pr.merged) {
        sendErr(res, 404, 'Not Found');
        return;
      }
      sendNoContent(res);
      return;
    }
    if (method === 'PUT') {
      if (!pr) {
        sendErr(res, 404, 'Pull request not found');
        return;
      }
      const title = isRecord(body) && typeof body.commit_title === 'string' ? (body.commit_title as string) : undefined;
      const result = mergePullInternal(repo, pr, title);
      if ('error' in result) {
        sendErr(res, result.status, result.error);
        return;
      }
      sendJson(res, 200, { sha: result.sha, merged: true, message: result.message });
      return;
    }
  }
  sendErr(res, 404, 'Not Found');
}

// Files changed between a PR's merge-base and its head, with line counts.
function pullFiles(repo: Repo, pr: PullRec): Record<string, unknown>[] | null {
  const headTip = repo.refs.get(`refs/heads/${pr.headRef}`) ?? pr.headSha;
  const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`) ?? pr.baseSha;
  const headObj = repo.objects.get(headTip);
  const baseObj = repo.objects.get(baseTip);
  if (!headObj || headObj.type !== 'commit' || !baseObj || baseObj.type !== 'commit') return null;
  const mb = mergeBase(repo, headTip, baseTip);
  const baseMap = mb ? treeToMap(repo, parseCommit((repo.objects.get(mb) as GitObj).data).tree) : new Map<string, { oid: string; mode: string }>();
  const headMap = treeToMap(repo, parseCommit(headObj.data).tree);
  const paths = new Set<string>([...baseMap.keys(), ...headMap.keys()]);
  const out: Record<string, unknown>[] = [];
  for (const p of [...paths].sort()) {
    const b = baseMap.get(p);
    const h = headMap.get(p);
    if (b?.oid === h?.oid) continue;
    let status: string;
    let additions = 0;
    let deletions = 0;
    if (!b && h) {
      status = 'added';
      const text = (repo.objects.get(h.oid) as GitObj).data.toString('utf8');
      additions = splitLines(text).length;
    } else if (b && !h) {
      status = 'removed';
      const text = (repo.objects.get(b.oid) as GitObj).data.toString('utf8');
      deletions = splitLines(text).length;
    } else if (b && h) {
      status = 'modified';
      const oldText = (repo.objects.get(b.oid) as GitObj).data.toString('utf8');
      const newText = (repo.objects.get(h.oid) as GitObj).data.toString('utf8');
      [additions, deletions] = lineDiff(oldText, newText);
    } else {
      continue;
    }
    out.push({
      filename: p,
      status,
      additions,
      deletions,
      changes: additions + deletions,
      sha: h?.oid ?? b?.oid ?? '',
    });
  }
  return out;
}

// ---------------------------------------------------------------- GraphQL: parser
type GqlValue =
  | { kind: 'Variable'; name: string }
  | { kind: 'Int'; value: number }
  | { kind: 'Float'; value: number }
  | { kind: 'String'; value: string }
  | { kind: 'Boolean'; value: boolean }
  | { kind: 'Null' }
  | { kind: 'Enum'; value: string }
  | { kind: 'List'; values: GqlValue[] }
  | { kind: 'Object'; fields: { name: string; value: GqlValue }[] };
interface GqlArg {
  name: string;
  value: GqlValue;
}
interface GqlDirective {
  name: string;
  args: GqlArg[];
}
type GqlSelection =
  | { kind: 'Field'; alias: string | null; name: string; args: GqlArg[]; directives: GqlDirective[]; selectionSet: GqlSelection[] | null }
  | { kind: 'InlineFragment'; typeCondition: string | null; directives: GqlDirective[]; selectionSet: GqlSelection[] }
  | { kind: 'FragmentSpread'; name: string; directives: GqlDirective[] };
interface GqlOperation {
  operation: 'query' | 'mutation' | 'subscription';
  name: string | null;
  variables: { name: string; defaultValue: GqlValue | null }[];
  selectionSet: GqlSelection[];
}
interface GqlFragmentDef {
  name: string;
  typeCondition: string;
  selectionSet: GqlSelection[];
}
interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, GqlFragmentDef>;
}
interface GqlToken {
  type: 'name' | 'int' | 'float' | 'string' | 'punct' | 'eof';
  value: string;
}
function lexGql(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i] as string;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',' || c === '﻿') {
      i++;
      continue;
    }
    if (c === '#') {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '"') {
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        const raw = end === -1 ? src.slice(i + 3) : src.slice(i + 3, end);
        tokens.push({ type: 'string', value: raw.replace(/\\"""/g, '"""') });
        i = end === -1 ? n : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < n && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < n) {
          const e = src[j + 1] as string;
          if (e === 'n') out += '\n';
          else if (e === 't') out += '\t';
          else if (e === 'r') out += '\r';
          else if (e === 'b') out += '\b';
          else if (e === 'f') out += '\f';
          else if (e === 'u') {
            out += String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16));
            j += 4;
          } else out += e;
          j += 2;
        } else {
          out += src[j];
          j++;
        }
      }
      tokens.push({ type: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      if (src[j] === '-') j++;
      while (j < n && /[0-9]/.test(src[j] as string)) j++;
      let isFloat = false;
      if (src[j] === '.') {
        isFloat = true;
        j++;
        while (j < n && /[0-9]/.test(src[j] as string)) j++;
      }
      if (src[j] === 'e' || src[j] === 'E') {
        isFloat = true;
        j++;
        if (src[j] === '+' || src[j] === '-') j++;
        while (j < n && /[0-9]/.test(src[j] as string)) j++;
      }
      tokens.push({ type: isFloat ? 'float' : 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(c)) {
      let j = i;
      while (j < n && /[_0-9A-Za-z]/.test(src[j] as string)) j++;
      tokens.push({ type: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (c === '.' && src.startsWith('...', i)) {
      tokens.push({ type: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('!$():=@[]{}|&'.includes(c)) {
      tokens.push({ type: 'punct', value: c });
      i++;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(c)} in GraphQL document`);
  }
  tokens.push({ type: 'eof', value: '' });
  return tokens;
}
class GqlParser {
  private tokens: GqlToken[];
  private pos = 0;
  constructor(src: string) {
    this.tokens = lexGql(src);
  }
  private peek(): GqlToken {
    return this.tokens[this.pos] as GqlToken;
  }
  private next(): GqlToken {
    const t = this.tokens[this.pos] as GqlToken;
    if (this.pos < this.tokens.length - 1) this.pos++;
    return t;
  }
  private expectPunct(v: string): void {
    const t = this.next();
    if (t.type !== 'punct' || t.value !== v) throw new Error(`expected '${v}' in GraphQL document, got ${t.value}`);
  }
  private expectName(v?: string): string {
    const t = this.next();
    if (t.type !== 'name') throw new Error(`expected a name in GraphQL document, got ${t.value}`);
    if (v !== undefined && t.value !== v) throw new Error(`expected '${v}' in GraphQL document, got ${t.value}`);
    return t.value;
  }
  parseDocument(): GqlDocument {
    const doc: GqlDocument = { operations: [], fragments: new Map() };
    while (this.peek().type !== 'eof') {
      if (this.peek().type === 'punct' && this.peek().value === '{') {
        doc.operations.push({
          operation: 'query',
          name: null,
          variables: [],
          selectionSet: this.parseSelectionSet(),
        });
      } else if (this.peek().type === 'name' && ['query', 'mutation', 'subscription'].includes(this.peek().value)) {
        const op = this.next().value as 'query' | 'mutation' | 'subscription';
        let name: string | null = null;
        if (this.peek().type === 'name') name = this.next().value;
        const variables = this.peek().type === 'punct' && this.peek().value === '(' ? this.parseVariableDefinitions() : [];
        this.parseDirectives();
        doc.operations.push({ operation: op, name, variables, selectionSet: this.parseSelectionSet() });
      } else if (this.peek().type === 'name' && this.peek().value === 'fragment') {
        this.next();
        const name = this.expectName();
        this.expectName('on');
        const typeCondition = this.expectName();
        this.parseDirectives();
        doc.fragments.set(name, { name, typeCondition, selectionSet: this.parseSelectionSet() });
      } else {
        throw new Error(`unexpected token ${this.peek().value} in GraphQL document`);
      }
    }
    return doc;
  }
  private parseVariableDefinitions(): { name: string; defaultValue: GqlValue | null }[] {
    const out: { name: string; defaultValue: GqlValue | null }[] = [];
    this.expectPunct('(');
    while (!(this.peek().type === 'punct' && this.peek().value === ')')) {
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      this.parseType();
      let defaultValue: GqlValue | null = null;
      if (this.peek().type === 'punct' && this.peek().value === '=') {
        this.next();
        defaultValue = this.parseValue(true);
      }
      this.parseDirectives();
      out.push({ name, defaultValue });
    }
    this.expectPunct(')');
    return out;
  }
  private parseType(): void {
    if (this.peek().type === 'punct' && this.peek().value === '[') {
      this.next();
      this.parseType();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    if (this.peek().type === 'punct' && this.peek().value === '!') this.next();
  }
  private parseDirectives(): GqlDirective[] {
    const out: GqlDirective[] = [];
    while (this.peek().type === 'punct' && this.peek().value === '@') {
      this.next();
      const name = this.expectName();
      const args = this.peek().type === 'punct' && this.peek().value === '(' ? this.parseArguments() : [];
      out.push({ name, args });
    }
    return out;
  }
  private parseArguments(): GqlArg[] {
    const out: GqlArg[] = [];
    this.expectPunct('(');
    while (!(this.peek().type === 'punct' && this.peek().value === ')')) {
      const name = this.expectName();
      this.expectPunct(':');
      out.push({ name, value: this.parseValue(false) });
    }
    this.expectPunct(')');
    return out;
  }
  private parseValue(isConst: boolean): GqlValue {
    const t = this.peek();
    if (t.type === 'punct' && t.value === '$') {
      if (isConst) throw new Error('variable in const value');
      this.next();
      return { kind: 'Variable', name: this.expectName() };
    }
    if (t.type === 'punct' && t.value === '[') {
      this.next();
      const values: GqlValue[] = [];
      while (!(this.peek().type === 'punct' && this.peek().value === ']')) {
        values.push(this.parseValue(isConst));
      }
      this.expectPunct(']');
      return { kind: 'List', values };
    }
    if (t.type === 'punct' && t.value === '{') {
      this.next();
      const fields: { name: string; value: GqlValue }[] = [];
      while (!(this.peek().type === 'punct' && this.peek().value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue(isConst) });
      }
      this.expectPunct('}');
      return { kind: 'Object', fields };
    }
    if (t.type === 'int') {
      this.next();
      return { kind: 'Int', value: parseInt(t.value, 10) };
    }
    if (t.type === 'float') {
      this.next();
      return { kind: 'Float', value: parseFloat(t.value) };
    }
    if (t.type === 'string') {
      this.next();
      return { kind: 'String', value: t.value };
    }
    if (t.type === 'name') {
      this.next();
      if (t.value === 'true') return { kind: 'Boolean', value: true };
      if (t.value === 'false') return { kind: 'Boolean', value: false };
      if (t.value === 'null') return { kind: 'Null' };
      return { kind: 'Enum', value: t.value };
    }
    throw new Error(`unexpected value token ${t.value} in GraphQL document`);
  }
  private parseSelectionSet(): GqlSelection[] {
    const out: GqlSelection[] = [];
    this.expectPunct('{');
    while (!(this.peek().type === 'punct' && this.peek().value === '}')) {
      if (this.peek().type === 'punct' && this.peek().value === '...') {
        this.next();
        if (this.peek().type === 'name' && this.peek().value === 'on') {
          this.next();
          const typeCondition = this.expectName();
          const directives = this.parseDirectives();
          out.push({ kind: 'InlineFragment', typeCondition, directives, selectionSet: this.parseSelectionSet() });
        } else if (this.peek().type === 'name') {
          const name = this.next().value;
          const directives = this.parseDirectives();
          out.push({ kind: 'FragmentSpread', name, directives });
        } else {
          const directives = this.parseDirectives();
          out.push({ kind: 'InlineFragment', typeCondition: null, directives, selectionSet: this.parseSelectionSet() });
        }
        continue;
      }
      const first = this.expectName();
      let alias: string | null = null;
      let name = first;
      if (this.peek().type === 'punct' && this.peek().value === ':') {
        this.next();
        alias = first;
        name = this.expectName();
      }
      const args = this.peek().type === 'punct' && this.peek().value === '(' ? this.parseArguments() : [];
      const directives = this.parseDirectives();
      const selectionSet =
        this.peek().type === 'punct' && this.peek().value === '{' ? this.parseSelectionSet() : null;
      out.push({ kind: 'Field', alias, name, args, directives, selectionSet });
    }
    this.expectPunct('}');
    return out;
  }
}

// ---------------------------------------------------------------- GraphQL: execution
class GqlError extends Error {}
interface GqlValueObject {
  __typename: string;
  [key: string]: unknown;
}
const INTROSPECTION: Record<string, { kind: string; fields?: string[]; enumValues?: string[] }> = {
  Query: { kind: 'OBJECT', fields: ['viewer', 'repository', 'node', '__type', '__schema'] },
  Mutation: { kind: 'OBJECT', fields: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'isPrivate', 'url'] },
  Issue: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt'] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'url', 'createdAt'] },
  IssueConnection: { kind: 'OBJECT', fields: ['nodes', 'pageInfo', 'totalCount'] },
  PullRequestConnection: { kind: 'OBJECT', fields: ['nodes', 'pageInfo', 'totalCount'] },
  IssueComment: { kind: 'OBJECT', fields: ['id', 'body'] },
  IssueCommentConnection: { kind: 'OBJECT', fields: ['nodes', 'pageInfo', 'totalCount'] },
  PageInfo: { kind: 'OBJECT', fields: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'] },
  User: { kind: 'OBJECT', fields: ['login', 'id', 'name', 'email', 'url'] },
  Ref: { kind: 'OBJECT', fields: ['name', 'target'] },
  Commit: { kind: 'OBJECT', fields: ['oid', 'message'] },
  PullRequestFile: { kind: 'OBJECT', fields: ['path'] },
  PullRequestFileConnection: { kind: 'OBJECT', fields: ['nodes', 'pageInfo', 'totalCount'] },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE'] },
  IssueState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enumValues: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'] },
  __Type: { kind: 'OBJECT', fields: ['name', 'kind', 'description', 'fields', 'enumValues', 'inputFields', 'interfaces', 'possibleTypes'] },
  __Field: { kind: 'OBJECT', fields: ['name', 'description', 'args', 'type'] },
  __InputValue: { kind: 'OBJECT', fields: ['name', 'description', 'type', 'defaultValue'] },
  __EnumValue: { kind: 'OBJECT', fields: ['name', 'description'] },
  __Schema: { kind: 'OBJECT', fields: ['queryType', 'mutationType', 'subscriptionType', 'types', 'directives'] },
  __Directive: { kind: 'OBJECT', fields: ['name', 'description', 'locations', 'args'] },
};
function introspectionType(name: string): GqlValueObject | null {
  const def = INTROSPECTION[name];
  if (!def) return null;
  return {
    __typename: '__Type',
    name,
    kind: def.kind,
    description: null,
    fields: (def.fields ?? []).map((f) => ({
      __typename: '__Field',
      name: f,
      description: null,
      args: [],
      type: { __typename: '__Type', name: 'String', kind: 'SCALAR', description: null, fields: null, enumValues: null, inputFields: null, interfaces: null, possibleTypes: null },
    })),
    enumValues: (def.enumValues ?? []).map((v) => ({ __typename: '__EnumValue', name: v, description: null })),
    inputFields: null,
    interfaces: [],
    possibleTypes: null,
  };
}
function encodeCursor(n: number): string {
  return b64encode(`cursor:${n}`);
}
function decodeCursor(c: string): number | null {
  try {
    const s = Buffer.from(c, 'base64').toString('utf8');
    if (!s.startsWith('cursor:')) return null;
    const n = parseInt(s.slice('cursor:'.length), 10);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}
function repoValue(repo: Repo): GqlValueObject {
  return { __typename: 'Repository', repo };
}
function issueValue(repo: Repo, issue: IssueRec): GqlValueObject {
  return { __typename: 'Issue', repo, issue };
}
function pullValue(repo: Repo, pr: PullRec): GqlValueObject {
  return { __typename: 'PullRequest', repo, pr };
}
function userValue(): GqlValueObject {
  return { __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL };
}
function pageInfoValue(hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null): GqlValueObject {
  return { __typename: 'PageInfo', hasNextPage, hasPreviousPage, startCursor, endCursor };
}
function connectionValue(kind: string, nodes: GqlValueObject[], totalCount: number, pageInfo: GqlValueObject): GqlValueObject {
  return { __typename: kind, nodes, pageInfo, totalCount };
}
function issueConnection(repo: Repo, args: Record<string, unknown>): GqlValueObject {
  let list = [...repo.issues.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toUpperCase()));
    list = list.filter((i) => wanted.has(i.state.toUpperCase()));
  }
  const orderBy = isRecord(args.orderBy) ? args.orderBy : {};
  const dir = orderBy.direction === 'ASC' ? 1 : -1;
  list.sort((a, b) => (a.number - b.number) * dir);
  let start = 0;
  if (typeof args.after === 'string') {
    const n = decodeCursor(args.after);
    if (n !== null) {
      const idx = list.findIndex((i) => i.number === n);
      start = idx === -1 ? list.length : idx + 1;
    }
  }
  const first = typeof args.first === 'number' && args.first >= 0 ? Math.trunc(args.first) : list.length - start;
  const page = list.slice(start, start + first);
  const endCursor = page.length > 0 ? encodeCursor((page[page.length - 1] as IssueRec).number) : null;
  const startCursor = page.length > 0 ? encodeCursor((page[0] as IssueRec).number) : null;
  return connectionValue(
    'IssueConnection',
    page.map((i) => issueValue(repo, i)),
    list.length,
    pageInfoValue(start + page.length < list.length, start > 0, startCursor, endCursor),
  );
}
function pullConnection(repo: Repo, args: Record<string, unknown>): GqlValueObject {
  let list = [...repo.pulls.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toUpperCase()));
    list = list.filter((p) => wanted.has(p.state.toUpperCase() === 'MERGED' ? 'MERGED' : p.state.toUpperCase()));
  }
  const orderBy = isRecord(args.orderBy) ? args.orderBy : {};
  const dir = orderBy.direction === 'ASC' ? 1 : -1;
  list.sort((a, b) => (a.number - b.number) * dir);
  let start = 0;
  if (typeof args.after === 'string') {
    const n = decodeCursor(args.after);
    if (n !== null) {
      const idx = list.findIndex((p) => p.number === n);
      start = idx === -1 ? list.length : idx + 1;
    }
  }
  const first = typeof args.first === 'number' && args.first >= 0 ? Math.trunc(args.first) : list.length - start;
  const page = list.slice(start, start + first);
  const endCursor = page.length > 0 ? encodeCursor((page[page.length - 1] as PullRec).number) : null;
  const startCursor = page.length > 0 ? encodeCursor((page[0] as PullRec).number) : null;
  return connectionValue(
    'PullRequestConnection',
    page.map((p) => pullValue(repo, p)),
    list.length,
    pageInfoValue(start + page.length < list.length, start > 0, startCursor, endCursor),
  );
}
function prMergeable(repo: Repo, pr: PullRec): string {
  if (pr.state !== 'open') return 'UNKNOWN';
  const headTip = repo.refs.get(`refs/heads/${pr.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!headTip || !baseTip) return 'UNKNOWN';
  return threeWayMerge(repo, baseTip, headTip) ? 'MERGEABLE' : 'CONFLICTING';
}
function prFilesConnection(repo: Repo, pr: PullRec, args: Record<string, unknown>): GqlValueObject {
  const files = pullFiles(repo, pr) ?? [];
  const first = typeof args.first === 'number' && args.first >= 0 ? Math.trunc(args.first) : files.length;
  const page = files.slice(0, first);
  return connectionValue(
    'PullRequestFileConnection',
    page.map((f) => ({ __typename: 'PullRequestFile', path: f.filename as string })),
    files.length,
    pageInfoValue(page.length < files.length, false, null, null),
  );
}
function resolveArgValue(v: GqlValue, variables: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'Variable':
      return variables[v.name];
    case 'Int':
    case 'Float':
    case 'String':
    case 'Boolean':
    case 'Enum':
      return v.value;
    case 'Null':
      return null;
    case 'List':
      return v.values.map((x) => resolveArgValue(x, variables));
    case 'Object': {
      const out: Record<string, unknown> = {};
      for (const f of v.fields) out[f.name] = resolveArgValue(f.value, variables);
      return out;
    }
  }
}
function argsOf(field: { args: GqlArg[] }, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const a of field.args) out[a.name] = resolveArgValue(a.value, variables);
  return out;
}
function directiveSkip(field: { directives: GqlDirective[] }, variables: Record<string, unknown>): boolean {
  for (const d of field.directives) {
    const args = argsOf({ args: d.args }, variables);
    if (d.name === 'skip' && args.if === true) return true;
    if (d.name === 'include' && args.if === false) return true;
  }
  return false;
}
function resolveField(
  parentType: string,
  parent: GqlValueObject,
  field: { kind: 'Field'; name: string; args: GqlArg[] },
  variables: Record<string, unknown>,
): unknown {
  const args = argsOf(field, variables);
  const name = field.name;
  if (name === '__typename') return parentType;
  switch (parentType) {
    case 'Query': {
      if (name === 'viewer') return userValue();
      if (name === 'repository') {
        const owner = args.owner as string;
        const repoName = args.name as string;
        const repo = getRepo(owner, repoName);
        return repo ? repoValue(repo) : null;
      }
      if (name === 'node') {
        const id = args.id as string;
        const parsed = parseGid(id);
        if (!parsed) return null;
        if (parsed.kind === 'Repository') {
          const dbId = parseInt(parsed.parts[0] as string, 10);
          for (const r of repos.values()) if (r.dbId === dbId) return repoValue(r);
          return null;
        }
        if (parsed.kind === 'Issue') {
          const dbId = parseInt(parsed.parts[0] as string, 10);
          const num = parseInt(parsed.parts[1] as string, 10);
          for (const r of repos.values()) {
            if (r.dbId === dbId) {
              const iss = r.issues.get(num);
              return iss ? issueValue(r, iss) : null;
            }
          }
          return null;
        }
        if (parsed.kind === 'PullRequest') {
          const dbId = parseInt(parsed.parts[0] as string, 10);
          const num = parseInt(parsed.parts[1] as string, 10);
          for (const r of repos.values()) {
            if (r.dbId === dbId) {
              const pr = r.pulls.get(num);
              return pr ? pullValue(r, pr) : null;
            }
          }
          return null;
        }
        if (parsed.kind === 'IssueComment') {
          const dbId = parseInt(parsed.parts[0] as string, 10);
          const num = parseInt(parsed.parts[1] as string, 10);
          const cid = parseInt(parsed.parts[2] as string, 10);
          for (const r of repos.values()) {
            if (r.dbId === dbId) {
              const iss = r.issues.get(num);
              const c = iss?.comments.find((x) => x.id === cid);
              return c ? { __typename: 'IssueComment', id: gid('IssueComment', dbId, num, cid), body: c.body } : null;
            }
          }
          return null;
        }
        return null;
      }
      if (name === '__type') {
        return introspectionType(String(args.name ?? ''));
      }
      if (name === '__schema') {
        return {
          __typename: '__Schema',
          queryType: introspectionType('Query'),
          mutationType: introspectionType('Mutation'),
          subscriptionType: null,
          types: Object.keys(INTROSPECTION).map((n) => introspectionType(n)),
          directives: [],
        };
      }
      break;
    }
    case 'Mutation': {
      if (name === 'createIssue') {
        const input = isRecord(args.input) ? args.input : {};
        const repoId = String(input.repositoryId ?? '');
        const parsed = parseGid(repoId);
        const dbId = parsed ? parseInt(parsed.parts[0] as string, 10) : NaN;
        let repo: Repo | null = null;
        for (const r of repos.values()) if (r.dbId === dbId) repo = r;
        if (!repo) throw new GqlError('repository not found');
        const result = createIssueInternal(repo, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '', []);
        if ('error' in result) throw new GqlError(result.error);
        return { __typename: 'CreateIssuePayload', issue: issueValue(repo, result.issue) };
      }
      if (name === 'closeIssue') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = parseGid(String(input.issueId ?? ''));
        if (!parsed || parsed.kind !== 'Issue') throw new GqlError('issue not found');
        const dbId = parseInt(parsed.parts[0] as string, 10);
        const num = parseInt(parsed.parts[1] as string, 10);
        for (const r of repos.values()) {
          if (r.dbId === dbId) {
            const iss = r.issues.get(num);
            if (!iss) throw new GqlError('issue not found');
            iss.state = 'closed';
            return { __typename: 'CloseIssuePayload', issue: issueValue(r, iss) };
          }
        }
        throw new GqlError('issue not found');
      }
      if (name === 'createPullRequest') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = parseGid(String(input.repositoryId ?? ''));
        const dbId = parsed ? parseInt(parsed.parts[0] as string, 10) : NaN;
        let repo: Repo | null = null;
        for (const r of repos.values()) if (r.dbId === dbId) repo = r;
        if (!repo) throw new GqlError('repository not found');
        const result = createPullInternal(
          repo,
          String(input.headRefName ?? ''),
          String(input.baseRefName ?? ''),
          String(input.title ?? ''),
          typeof input.body === 'string' ? input.body : '',
        );
        if ('error' in result) throw new GqlError(result.error);
        return { __typename: 'CreatePullRequestPayload', pullRequest: pullValue(repo, result.pr) };
      }
      if (name === 'mergePullRequest') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = parseGid(String(input.pullRequestId ?? ''));
        if (!parsed || parsed.kind !== 'PullRequest') throw new GqlError('pull request not found');
        const dbId = parseInt(parsed.parts[0] as string, 10);
        const num = parseInt(parsed.parts[1] as string, 10);
        for (const r of repos.values()) {
          if (r.dbId === dbId) {
            const pr = r.pulls.get(num);
            if (!pr) throw new GqlError('pull request not found');
            const result = mergePullInternal(r, pr);
            if ('error' in result) throw new GqlError(result.error);
            return { __typename: 'MergePullRequestPayload', pullRequest: pullValue(r, pr) };
          }
        }
        throw new GqlError('pull request not found');
      }
      if (name === 'addComment') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = parseGid(String(input.subjectId ?? ''));
        if (!parsed || parsed.kind !== 'Issue') throw new GqlError('subject not found');
        const dbId = parseInt(parsed.parts[0] as string, 10);
        const num = parseInt(parsed.parts[1] as string, 10);
        for (const r of repos.values()) {
          if (r.dbId === dbId) {
            const iss = r.issues.get(num);
            if (!iss) throw new GqlError('issue not found');
            const comment: CommentRec = { id: r.nextCommentId++, body: String(input.body ?? '') };
            iss.comments.push(comment);
            return {
              __typename: 'AddCommentPayload',
              commentEdge: {
                __typename: 'IssueCommentEdge',
                node: { __typename: 'IssueComment', id: gid('IssueComment', dbId, num, comment.id), body: comment.body },
              },
            };
          }
        }
        throw new GqlError('issue not found');
      }
      break;
    }
    case 'Repository': {
      const repo = parent.repo as Repo;
      switch (name) {
        case 'id': return gid('Repository', repo.dbId);
        case 'databaseId': return repo.dbId;
        case 'name': return repo.name;
        case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
        case 'owner': return userValue();
        case 'description': return repo.description;
        case 'isPrivate': return repo.isPrivate;
        case 'url': return `https://example.invalid/${repo.owner}/${repo.name}`;
        case 'defaultBranchRef': {
          const tip = repo.refs.get('refs/heads/main');
          return tip ? { __typename: 'Ref', name: 'main', target: { __typename: 'Commit', oid: tip, message: '' } } : null;
        }
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': return true;
        case 'issue': {
          const iss = repo.issues.get(typeof args.number === 'number' ? args.number : -1);
          return iss ? issueValue(repo, iss) : null;
        }
        case 'issues': return issueConnection(repo, args);
        case 'pullRequests': return pullConnection(repo, args);
        case 'pullRequest': {
          const pr = repo.pulls.get(typeof args.number === 'number' ? args.number : -1);
          return pr ? pullValue(repo, pr) : null;
        }
        default: break;
      }
      break;
    }
    case 'Issue': {
      const issue = parent.issue as IssueRec;
      const repo = parent.repo as Repo;
      switch (name) {
        case 'id': return gid('Issue', repo.dbId, issue.number);
        case 'number': return issue.number;
        case 'title': return issue.title;
        case 'state': return issue.state.toUpperCase();
        case 'body': return issue.body;
        case 'url': return `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`;
        case 'createdAt': return FIXED_TS;
        case 'comments': {
          const nodes = issue.comments.map((c) => ({ __typename: 'IssueComment', id: gid('IssueComment', repo.dbId, issue.number, c.id), body: c.body }));
          return connectionValue('IssueCommentConnection', nodes, nodes.length, pageInfoValue(false, false, null, null));
        }
        default: break;
      }
      break;
    }
    case 'PullRequest': {
      const pr = parent.pr as PullRec;
      const repo = parent.repo as Repo;
      switch (name) {
        case 'id': return gid('PullRequest', repo.dbId, pr.number);
        case 'number': return pr.number;
        case 'title': return pr.title;
        case 'body': return pr.body;
        case 'state': return pr.merged ? 'MERGED' : pr.state.toUpperCase();
        case 'merged': return pr.merged;
        case 'headRefName': return pr.headRef;
        case 'baseRefName': return pr.baseRef;
        case 'mergeable': return prMergeable(repo, pr);
        case 'files': return prFilesConnection(repo, pr, args);
        case 'url': return `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`;
        case 'createdAt': return FIXED_TS;
        default: break;
      }
      break;
    }
    case 'User': {
      if (name === 'login') return VIEWER_LOGIN;
      if (name === 'id') return gid('User', VIEWER_ID);
      if (name === 'name') return VIEWER_NAME;
      if (name === 'email') return VIEWER_EMAIL;
      if (name === 'url') return `https://example.invalid/${VIEWER_LOGIN}`;
      break;
    }
    case 'Ref': {
      if (name === 'name') return parent.name as string;
      if (name === 'target') return parent.target as GqlValueObject;
      break;
    }
    case 'Commit': {
      if (name === 'oid') return parent.oid as string;
      if (name === 'message') return parent.message as string;
      break;
    }
    default: break;
  }
  // Generic fallback: plain property on the value object.
  if (name in parent && typeof (parent as Record<string, unknown>)[name] !== 'function') {
    return (parent as Record<string, unknown>)[name];
  }
  throw new GqlError(`Cannot query field "${name}" on type "${parentType}".`);
}
function executeSelectionSet(
  parentType: string,
  parent: GqlValueObject,
  selections: GqlSelection[],
  variables: Record<string, unknown>,
  fragments: Map<string, GqlFragmentDef>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'Field') {
      if (directiveSkip(sel, variables)) continue;
      const value = resolveField(parentType, parent, sel, variables);
      const key = sel.alias ?? sel.name;
      if (sel.selectionSet && value !== null && value !== undefined) {
        out[key] = resolveValue(value, sel.selectionSet, variables, fragments);
      } else {
        out[key] = value ?? null;
      }
    } else if (sel.kind === 'InlineFragment') {
      if (directiveSkip(sel, variables)) continue;
      if (sel.typeCondition === null || sel.typeCondition === parentType) {
        Object.assign(out, executeSelectionSet(parentType, parent, sel.selectionSet, variables, fragments));
      }
    } else if (sel.kind === 'FragmentSpread') {
      if (directiveSkip(sel, variables)) continue;
      const def = fragments.get(sel.name);
      if (!def) throw new GqlError(`Unknown fragment "${sel.name}".`);
      if (def.typeCondition === parentType) {
        Object.assign(out, executeSelectionSet(parentType, parent, def.selectionSet, variables, fragments));
      }
    }
  }
  return out;
}
function resolveValue(
  value: unknown,
  selections: GqlSelection[],
  variables: Record<string, unknown>,
  fragments: Map<string, GqlFragmentDef>,
): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => resolveValue(item, selections, variables, fragments));
  }
  if (typeof value === 'object' && value !== null && '__typename' in (value as Record<string, unknown>)) {
    const obj = value as GqlValueObject;
    return executeSelectionSet(obj.__typename, obj, selections, variables, fragments);
  }
  return value;
}
function executeOperation(
  doc: GqlDocument,
  operationName: string | undefined,
  variables: Record<string, unknown>,
): { data: Record<string, unknown> | null; errors: { message: string }[] } {
  let op: GqlOperation | undefined;
  if (operationName) {
    op = doc.operations.find((o) => o.name === operationName);
  } else if (doc.operations.length === 1) {
    op = doc.operations[0];
  } else {
    op = doc.operations[0];
  }
  if (!op) {
    return { data: null, errors: [{ message: `Unknown operation ${operationName ?? ''}` }] };
  }
  const vars: Record<string, unknown> = {};
  for (const v of op.variables) {
    if (v.name in variables && variables[v.name] !== undefined) vars[v.name] = variables[v.name];
    else if (v.defaultValue !== null) vars[v.name] = resolveArgValue(v.defaultValue, {});
  }
  for (const [k, val] of Object.entries(variables)) {
    if (!(k in vars)) vars[k] = val;
  }
  const rootType = op.operation === 'mutation' ? 'Mutation' : 'Query';
  const root: GqlValueObject = { __typename: rootType };
  try {
    const data = executeSelectionSet(rootType, root, op.selectionSet, vars, doc.fragments);
    return { data, errors: [] };
  } catch (err) {
    if (err instanceof GqlError) {
      return { data: null, errors: [{ message: err.message }] };
    }
    throw err;
  }
}
async function handleGraphQL(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const bodyBuf = await readBody(req);
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) {
    sendJson(res, 400, { errors: [{ message: 'Invalid JSON body' }] });
    return;
  }
  const runOne = (op: unknown): { data: unknown; errors: { message: string }[] } => {
    if (!isRecord(op) || typeof op.query !== 'string') {
      return { data: null, errors: [{ message: 'query is required' }] };
    }
    let doc: GqlDocument;
    try {
      doc = new GqlParser(op.query).parseDocument();
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
    }
    const variables = isRecord(op.variables) ? (op.variables as Record<string, unknown>) : {};
    const operationName = typeof op.operationName === 'string' ? op.operationName : undefined;
    try {
      return executeOperation(doc, operationName, variables);
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
    }
  };
  // Omit the errors key entirely when there are no errors (standard GraphQL
  // shape; the suite treats a present errors array as a failure).
  const clean = (r: { data: unknown; errors: { message: string }[] }): unknown =>
    r.errors.length > 0 ? r : { data: r.data };
  if (Array.isArray(parsed.value)) {
    sendJson(res, 200, parsed.value.map((op) => clean(runOne(op))));
  } else {
    sendJson(res, 200, clean(runOne(parsed.value)));
  }
}

// ---------------------------------------------------------------- MCP
const MCP_TOOLS: Record<string, unknown>[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];
function mcpToolResult(obj: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj };
}
function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}
function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const need = (keys: string[]): string | null => {
    for (const k of keys) {
      if (args[k] === undefined || args[k] === null || args[k] === '') return `Missing required argument: ${k}`;
    }
    return null;
  };
  if (name === 'create_repo') {
    const missing = need(['name']);
    if (missing) return mcpToolError(missing);
    const result = createRepoInternal(
      String(args.name),
      typeof args.description === 'string' ? args.description : '',
      args.private === true,
    );
    if ('error' in result) return mcpToolError(result.error);
    return mcpToolResult(repoJson(result.repo));
  }
  if (name === 'get_repo') {
    const missing = need(['owner', 'repo']);
    if (missing) return mcpToolError(missing);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (!repo) return mcpToolError('Repository not found');
    return mcpToolResult(repoJson(repo));
  }
  if (name === 'create_issue') {
    const missing = need(['owner', 'repo', 'title']);
    if (missing) return mcpToolError(missing);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (!repo) return mcpToolError('Repository not found');
    const result = createIssueInternal(repo, String(args.title), typeof args.body === 'string' ? args.body : '', []);
    if ('error' in result) return mcpToolError(result.error);
    return mcpToolResult(issueJson(repo, result.issue));
  }
  if (name === 'list_issues') {
    const missing = need(['owner', 'repo']);
    if (missing) return mcpToolError(missing);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (!repo) return mcpToolError('Repository not found');
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.issues.values()];
    if (state === 'open') list = list.filter((i) => i.state === 'open');
    else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
    list.sort((a, b) => a.number - b.number);
    const issues = list.map((i) => issueJson(repo, i));
    return mcpToolResult({ issues });
  }
  if (name === 'create_pull_request') {
    const missing = need(['owner', 'repo', 'title', 'head', 'base']);
    if (missing) return mcpToolError(missing);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (!repo) return mcpToolError('Repository not found');
    const result = createPullInternal(repo, String(args.head), String(args.base), String(args.title), typeof args.body === 'string' ? args.body : '');
    if ('error' in result) return mcpToolError(result.error);
    return mcpToolResult(pullJson(repo, result.pr));
  }
  if (name === 'merge_pull_request') {
    const missing = need(['owner', 'repo', 'pull_number']);
    if (missing) return mcpToolError(missing);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (!repo) return mcpToolError('Repository not found');
    const pr = repo.pulls.get(Number(args.pull_number));
    if (!pr) return mcpToolError('Pull request not found');
    const result = mergePullInternal(repo, pr);
    if ('error' in result) return mcpToolError(result.error);
    return mcpToolResult({ ...pullJson(repo, pr), sha: result.sha });
  }
  return mcpToolError(`Unknown tool: ${name}`);
}
async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const bodyBuf = await readBody(req);
  let msg: unknown;
  try {
    msg = JSON.parse(bodyBuf.toString('utf8'));
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!isRecord(msg) || typeof msg.method !== 'string') {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const id = msg.id === undefined ? null : msg.id;
  const method = msg.method as string;
  if (method.startsWith('notifications/')) {
    res.writeHead(202, { 'X-GitHub-Request-Id': `req-${++reqCounter}` });
    res.end();
    return;
  }
  const params = isRecord(msg.params) ? (msg.params as Record<string, unknown>) : {};
  if (method === 'ping') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (method === 'server/discover') {
    const serverInfo = { name: 'github-forge', version: FORGE_VERSION };
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'],
        capabilities: { tools: {} },
        serverInfo,
        _meta: { 'io.modelcontextprotocol/serverInfo': serverInfo },
      },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    const supported = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: supported.includes(offered) ? offered : '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: { name: 'github-forge', version: FORGE_VERSION },
      },
    });
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const known = MCP_TOOLS.some((t) => t.name === toolName);
    if (!known) {
      sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${toolName}` } });
      return;
    }
    try {
      const result = mcpCallTool(toolName, args);
      sendJson(res, 200, { jsonrpc: '2.0', id, result });
    } catch (err) {
      sendJson(res, 200, { jsonrpc: '2.0', id, result: mcpToolError(err instanceof Error ? err.message : String(err)) });
    }
    return;
  }
  sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
}

// ---------------------------------------------------------------- routing + lifecycle
function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const h = req.headers.authorization ?? '';
  return h === `Bearer ${TOKEN}`;
}
async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const pathname = url.pathname;
    const query = url.searchParams;
    const method = (req.method ?? 'GET').toUpperCase();

    if (pathname === '/healthz' && method === 'GET') {
      sendJson(res, 200, { ok: true });
      return;
    }
    // Git smart HTTP: /{owner}/{repo}.git/info/refs | git-upload-pack | git-receive-pack
    const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(pathname);
    if (gitMatch) {
      const owner = decodeURIComponent(gitMatch[1] as string);
      const repoName = decodeURIComponent(gitMatch[2] as string);
      const action = gitMatch[3] as string;
      const repo = getRepo(owner, repoName);
      if (!repo) {
        sendErr(res, 404, 'Repository not found');
        return;
      }
      if (action === 'info/refs' && method === 'GET') {
        const service = query.get('service');
        if (service === 'git-upload-pack') {
          sendRaw(res, 200, advertiseUploadPackV2(), 'application/x-git-upload-pack-advertisement');
          return;
        }
        if (service === 'git-receive-pack') {
          sendRaw(res, 200, advertiseReceivePack(repo), 'application/x-git-receive-pack-advertisement');
          return;
        }
        sendErr(res, 404, 'Not Found');
        return;
      }
      if (action === 'git-upload-pack' && method === 'POST') {
        const body = await readBody(req);
        const protocol = req.headers['git-protocol'] ?? '';
        try {
          if (String(protocol).includes('version=2')) {
            const { lines } = parsePktLines(body);
            const texts = pktTextLines(lines);
            const command = texts.find((t) => t.startsWith('command='))?.slice('command='.length);
            const args = texts.filter((t) => !t.startsWith('command=') && !t.startsWith('agent=') && t !== 'object-format=sha1');
            if (command === 'ls-refs') {
              sendRaw(res, 200, handleLsRefs(repo, args), 'application/x-git-upload-pack-result');
              return;
            }
            if (command === 'fetch') {
              sendRaw(res, 200, handleFetch(repo, args), 'application/x-git-upload-pack-result');
              return;
            }
            // No command: a probe (bare ref lines) or garbage.
            const refLineRe = /^[0-9a-f]{40} \S+$/;
            if (texts.length > 0 && texts.every((t) => refLineRe.test(t.trim()))) {
              sendRaw(res, 200, probeUploadPackResponse(repo, texts.map((t) => t.trim()), true), 'application/x-git-upload-pack-result');
              return;
            }
            sendErr(res, 400, 'unknown upload-pack command');
            return;
          }
          // v0: a probe (bare ref lines) echoes the advertisement; else a want/have fetch.
          const { lines } = parsePktLines(body);
          const texts = pktTextLines(lines);
          const refLineRe = /^[0-9a-f]{40} \S+$/;
          if (texts.length > 0 && texts.every((t) => refLineRe.test(t.trim()))) {
            sendRaw(res, 200, probeUploadPackResponse(repo, texts.map((t) => t.trim()), false), 'application/x-git-upload-pack-result');
            return;
          }
          sendRaw(res, 200, handleUploadPackV0(repo, body), 'application/x-git-upload-pack-result');
        } catch (err) {
          sendErr(res, 400, err instanceof Error ? err.message : 'bad upload-pack request');
        }
        return;
      }
      if (action === 'git-receive-pack' && method === 'POST') {
        const body = await readBody(req);
        try {
          const out = handleReceivePack(repo, body);
          sendRaw(res, out.status, out.body, 'application/x-git-receive-pack-result');
        } catch (err) {
          sendErr(res, 400, err instanceof Error ? err.message : 'bad receive-pack request');
        }
        return;
      }
      sendErr(res, 404, 'Not Found');
      return;
    }
    // REST v3
    if (pathname === '/api/v3' || pathname.startsWith('/api/v3/')) {
      if (!authed(req)) {
        sendErr(res, 401, 'Unauthorized');
        return;
      }
      await handleRest(req, res, pathname, query);
      return;
    }
    // GraphQL
    if (pathname === '/api/graphql') {
      if (method !== 'POST') {
        sendErr(res, 404, 'Not Found');
        return;
      }
      if (!authed(req)) {
        sendJson(res, 401, { data: null, errors: [{ message: 'Unauthorized' }] });
        return;
      }
      await handleGraphQL(req, res);
      return;
    }
    // MCP
    if (pathname === '/mcp') {
      if (method !== 'POST') {
        sendErr(res, 405, 'Method Not Allowed');
        return;
      }
      if (!authed(req)) {
        sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Unauthorized' } });
        return;
      }
      await handleMcp(req, res);
      return;
    }
    sendErr(res, 404, 'Not Found');
  } catch (err) {
    if (!res.headersSent) {
      try {
        sendErr(res, 500, err instanceof Error ? err.message : 'internal error');
      } catch {
        res.end();
      }
    } else {
      res.end();
    }
  }
}

const server = createServer((req, res) => {
  void handleRequest(req, res);
});
server.listen(0, '0.0.0.0', () => {
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  process.stderr.write(`[forge] listening on ${port}\n`);
  const envUrl = process.env.MAKEFUN_ENV_URL;
  if (!envUrl) {
    process.stderr.write('[forge] no MAKEFUN_ENV_URL set; serving without a trial\n');
    return;
  }
  const base = envUrl.replace(/\/+$/, '');
  void (async () => {
    let registered = false;
    for (let attempt = 0; attempt < 30 && !registered; attempt++) {
      try {
        const r = await fetch(`${base}/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ port }),
        });
        if (r.status === 200) {
          registered = true;
          process.stderr.write('[forge] registered\n');
        } else if (r.status === 409) {
          await sleep(1000);
        } else {
          await sleep(1000);
        }
      } catch {
        await sleep(1000);
      }
    }
    if (!registered) {
      process.stderr.write('[forge] register failed; exiting\n');
      process.exit(1);
    }
    while (true) {
      try {
        const r = await fetch(`${base}/done`);
        const j = (await r.json()) as { done?: boolean };
        if (j.done === true) break;
      } catch {
        // env briefly unreachable; keep polling
      }
      await sleep(500);
    }
    process.stderr.write('[forge] trial done; exiting 0\n');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  })();
});
