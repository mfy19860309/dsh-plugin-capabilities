/**
 * Connect to a single MCP server and list its tools — the data behind the
 * “查看工具” modal on each MCP card. Implements just the slice of the JSON-RPC
 * MCP handshake needed to reach `tools/list`:
 *
 *   streamable-http: POST `initialize` → `notifications/initialized` →
 *                    `tools/list`, threading the `Mcp-Session-Id` header the
 *                    server returns and tolerating both JSON and SSE replies.
 *   stdio:           spawn the command, drive the same three JSON-RPC messages
 *                    over newline-delimited stdout/stdin, then kill it.
 *
 * The probe is bounded by an idle timeout and is read-only (no tool is ever
 * invoked), so it is safe to run from the Settings page. A stdio spawn can
 * surface console windows on Windows, so `windowsHide` is set.
 */

import { spawn, type ChildProcess } from 'node:child_process'
import type { McpRow } from './mcp.ts'

/** One tool as the browser renders it. */
export interface McpTool {
  name: string
  title?: string
  description?: string
}

/** Outcome of a tools probe, as the route serializes it. */
export interface McpToolsResult {
  ok: boolean
  tools?: McpTool[]
  error?: string
}

/** Parse a body that is either JSON or an SSE stream; returns the last usable JSON event. */
function parseRpcBody(text: string): unknown {
  const trimmed = text.trim()
  if (trimmed === '') return null
  if (trimmed.includes('\n') || trimmed.startsWith('event:') || trimmed.startsWith('data:')) {
    let last: unknown = null
    for (const line of trimmed.split(/\r?\n/)) {
      const clean = line.trim()
      if (!clean.startsWith('data:')) continue
      const data = clean.slice(5).trim()
      if (data === '') continue
      try {
        last = JSON.parse(data)
      } catch {
        // A non-JSON data line (e.g. `: keep-alive`) — skip, keep the previous.
      }
    }
    return last
  }
  return JSON.parse(trimmed)
}

/**
 * Read one JSON-RPC response off an HTTP response without blocking on the full
 * body. Streamable-HTTP servers answer `initialize`/`tools/list` with an SSE
 * stream that STAYS OPEN (the server keeps it for later server→client
 * messages); awaiting `response.text()` would hang forever. Instead we read the
 * stream chunk-by-chunk and resolve as soon as the message with the expected
 * `id` appears (plain JSON bodies are read whole as before).
 */
async function readRpcMessage(
  response: Response,
  id: number,
): Promise<{ result?: { tools?: unknown }; error?: { message: string } } | null> {
  const contentType = response.headers.get('content-type') ?? ''
  if (!contentType.toLowerCase().includes('text/event-stream')) {
    return parseRpcBody(await response.text().catch(() => '')) as
      | { result?: { tools?: unknown }; error?: { message: string } }
      | null
  }
  const reader = response.body?.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let found: { result?: { tools?: unknown }; error?: { message: string } } | null = null
  if (reader !== undefined) {
    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const match = extractSseMessage(buffer, id)
        if (match !== null) { found = match; break }
      }
    } finally {
      try { await reader.cancel() } catch { /* stream already gone */ }
    }
  }
  // Stream ended before a match (or no reader): best-effort parse of what we have.
  return found ?? extractSseMessage(buffer, id)
}

/** Find the first complete JSON-RPC message with the given id in a (possibly partial) SSE buffer. */
function extractSseMessage(
  buffer: string,
  id: number,
): { result?: { tools?: unknown }; error?: { message: string } } | null {
  for (const rawLine of buffer.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line.startsWith('data:')) continue
    const data = line.slice(5).trim()
    if (data === '') continue
    let parsed: { id?: unknown; result?: { tools?: unknown }; error?: { message: string } }
    try {
      parsed = JSON.parse(data)
    } catch {
      continue // incomplete JSON mid-stream — wait for more bytes
    }
    if (parsed !== null && typeof parsed === 'object' && parsed.id === id) {
      return parsed as { result?: { tools?: unknown }; error?: { message: string } }
    }
  }
  return null
}

/** Drive the streamable-http transport end to end. */
async function listToolsHttp(row: McpRow, timeoutMs: number): Promise<McpToolsResult> {
  if (typeof row.url !== 'string') return { ok: false, error: 'row has no http url' }
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
  }
  if (row.headers !== undefined) {
    for (const [key, value] of Object.entries(row.headers)) headers[key.toLowerCase()] = value
  }
  let sessionId: string | undefined
  const call = async (method: string, params: unknown, id: number | null): Promise<unknown> => {
    const reqHeaders = { ...headers }
    if (sessionId !== undefined) reqHeaders['mcp-session-id'] = sessionId
    const response = await fetch(row.url as string, {
      method: 'POST',
      headers: reqHeaders,
      body: JSON.stringify(id === null
        ? { jsonrpc: '2.0', method, params }
        : { jsonrpc: '2.0', id, method, params }),
      signal: AbortSignal.timeout(timeoutMs),
    })
    const sid = response.headers.get('mcp-session-id')
    if (sid !== null && sid !== '') sessionId = sid
    if (id === null) {
      // A notification: servers may answer 202, or keep an open SSE stream.
      // Never block on the body for it.
      if (!response.ok && response.status !== 202) {
        throw new Error(`HTTP ${response.status}`)
      }
      try { await response.body?.cancel() } catch { /* nothing to cancel */ }
      return undefined
    }
    if (!response.ok && response.status !== 202) {
      const detail = await response.text().catch(() => '')
      throw new Error(`HTTP ${response.status}${detail ? `: ${detail.slice(0, 200)}` : ''}`)
    }
    return readRpcMessage(response, id)
  }
  try {
    await call('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'dsh-capabilities', version: '1.0' },
    }, 1)
    await call('notifications/initialized', {}, null)
    const result = (await call('tools/list', {}, 2)) as
      { result?: { tools?: unknown }; error?: { message: string } } | null
    if (result !== null && 'error' in result && result.error !== undefined) {
      return { ok: false, error: result.error.message }
    }
    const tools = Array.isArray(result?.result?.tools)
      ? (result?.result?.tools as unknown[]).map(toTool)
      : []
    return { ok: true, tools }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }
}

/** Drive the stdio transport end to end by spawning the server once. */
function listToolsStdio(row: McpRow, timeoutMs: number): Promise<McpToolsResult> {
  return new Promise<McpToolsResult>((resolve) => {
    if (typeof row.command !== 'string' || row.command.trim() === '') {
      resolve({ ok: false, error: 'row has no command' })
      return
    }
    let settled = false
    const finish = (result: McpToolsResult): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { child.kill() } catch { /* already gone */ }
      resolve(result)
    }
    const timer = setTimeout(() => finish({ ok: false, error: t('timeout') }), timeoutMs)
    const env = { ...process.env, ...(row.env ?? {}) }
    let child: ChildProcess
    try {
      child = spawn(row.command, row.args ?? [], {
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      })
    } catch (error) {
      clearTimeout(timer)
      resolve({ ok: false, error: error instanceof Error ? error.message : String(error) })
      return
    }
    let buffer = ''
    const pending = new Map<number, (msg: RpcMessage) => void>()
    const stdin = child.stdin
    const stdout = child.stdout
    if (stdin === null || stdout === null) {
      finish({ ok: false, error: 'could not open stdio pipes' })
      return
    }
    const send = (obj: unknown): void => {
      try { stdin.write(`${JSON.stringify(obj)}\n`) } catch { /* pipe closed */ }
    }
    child.on('error', (err: Error) => finish({ ok: false, error: err.message }))
    child.on('exit', () => finish({ ok: false, error: t('exited') }))
    stdout.on('data', (chunk: Buffer) => {
      buffer += chunk.toString()
      let idx = buffer.indexOf('\n')
      while (idx >= 0) {
        const line = buffer.slice(0, idx).trim()
        buffer = buffer.slice(idx + 1)
        if (line !== '') {
          let msg: RpcMessage
          try { msg = JSON.parse(line) } catch { msg = undefined as unknown as RpcMessage }
          if (msg !== undefined && msg.id !== undefined && pending.has(msg.id)) {
            const cb = pending.get(msg.id) as (m: RpcMessage) => void
            pending.delete(msg.id)
            cb(msg)
          }
        }
        idx = buffer.indexOf('\n')
      }
    })

    const initId = 1
    const listId = 2
    pending.set(initId, (msg) => {
      if (msg.error !== undefined) return finish({ ok: false, error: msg.error.message })
      send({ jsonrpc: '2.0', method: 'notifications/initialized' })
      pending.set(listId, (m2) => {
        if (m2.error !== undefined) return finish({ ok: false, error: m2.error.message })
        const tools = Array.isArray(m2.result?.tools)
          ? (m2.result?.tools as unknown[]).map(toTool)
          : []
        finish({ ok: true, tools })
      })
      send({ jsonrpc: '2.0', id: listId, method: 'tools/list', params: {} })
    })
    send({
      jsonrpc: '2.0',
      id: initId,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'dsh-capabilities', version: '1.0' },
      },
    })
  })
}

/** Shape of a decoded JSON-RPC message we care about. */
interface RpcMessage {
  id?: number
  result?: { tools?: unknown }
  error?: { code: number; message: string }
}

/** Normalize a raw tool entry into the browser-facing shape. */
function toTool(raw: unknown): McpTool {
  const entry = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
  return {
    name: typeof entry.name === 'string' ? entry.name : '',
    ...(typeof entry.title === 'string' ? { title: entry.title } : {}),
    ...(typeof entry.description === 'string' ? { description: entry.description } : {}),
  }
}

/** Tiny locale-free message helper (errors travel to the UI, which translates them). */
function t(key: 'timeout' | 'exited'): string {
  return key === 'timeout' ? 'timed out waiting for tools/list' : 'mcp process exited before responding'
}

/**
 * List the tools an MCP server exposes. Resolves (never throws) with either
 * `{ ok: true, tools }` or `{ ok: false, error }`, so the route can always
 * serialize a clean answer.
 */
export function listToolsMcp(row: McpRow, options: { timeoutMs?: number } = {}): Promise<McpToolsResult> {
  const timeoutMs = options.timeoutMs ?? 15_000
  if (row.transport === 'stdio') return listToolsStdio(row, timeoutMs)
  return listToolsHttp(row, timeoutMs)
}
