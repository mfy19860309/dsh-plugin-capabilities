/**
 * OAuth 2.1 授权码 + PKCE(S256) 客户端：移植自 xz-dsh-mcp-oauth 的 lib/oauth.js，
 * 适配本插件基于「文件凭证库 + YAML 配置」的存储模型。
 *
 * 与参考项目的差异：
 *   - 参考项目把令牌存进 DSH 凭证库（按卡片命名空间），由传输层注入 Bearer；
 *     本插件把令牌存进插件状态目录下的 oauth/ 子目录（每个 serverName 一个 JSON
 *     文件），并把 `Authorization: Bearer <token>` 写入 MCP 行的 `headers`——因为
 *     `@deepseek-ai/dsh-mcp-client` 只从 YAML 配置读取 headers，无法在运行时注入。
 *   - 端点一律按卡片 `url` 推导出的 baseUrl 拼接，绝不跟随元数据发现的绝对地址，
 *     以绕开服务端 OAuth 元数据与卡片地址不一致的问题（同参考项目经验）。
 *
 * 端点约定（与参考项目一致）：
 *   `${baseUrl}/oauth/authorize`、`/oauth/token`、`/oauth/register`。
 * @module dsh-oauth-plugin-capabilities/oauth
 */

import { randomBytes, createHash } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { pluginStateDir } from './state.ts'

/** Loopback 回调路径。 */
export const REDIRECT_PATH = '/callback'

/** 一次交互式授权允许的最大耗时（慢 SSO + 同意）。 */
export const OAUTH_BUDGET_MS = 5 * 60_000

/** 提前 60 秒刷新，避免请求途中过期。 */
const REFRESH_SKEW_MS = 60 * 1000

/** 持久化的 OAuth 文档（含令牌与客户端信息）。 */
export interface OAuthDoc {
  client_id?: string
  redirect_uri?: string
  access_token?: string
  refresh_token?: string
  expires_at?: number
  scope?: string
  baseUrl?: string
}

/** 凭证库外观：按引用读写文档（引用即 serverName）。 */
export interface CredentialStore {
  read(ref: string): Promise<OAuthDoc | null>
  write(ref: string, doc: OAuthDoc): Promise<void>
}

/** base64url 编码（Node 直接支持）。 */
function b64u(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

/**
 * 由 MCP 端点 URL 推导 OAuth baseUrl。
 * `https://host/mcp` → `https://host`；其他路径去掉末段兜底。
 * @param mcpUrl - 卡片 MCP 端点 URL。
 * @returns OAuth baseUrl（scheme + host，可能含前缀路径）。
 */
export function baseUrlFromMcpUrl(mcpUrl: string): string {
  const u = String(mcpUrl || '').replace(/\/+$/, '')
  const idx = u.toLowerCase().lastIndexOf('/mcp')
  if (idx > 0) return u.slice(0, idx)
  const s = u.lastIndexOf('/')
  return s > 8 ? u.slice(0, s) : u
}

/** 由 baseUrl 推导三个 OAuth 端点。 */
export function endpoints(baseUrl: string): { authorizeUrl: string; tokenUrl: string; registerUrl: string } {
  const root = String(baseUrl || '').replace(/\/+$/, '')
  return {
    authorizeUrl: `${root}/oauth/authorize`,
    tokenUrl: `${root}/oauth/token`,
    registerUrl: `${root}/oauth/register`,
  }
}

/** PKCE S256 challenge。 */
export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url')
}

/** 推导回调候选端口（保留以兼容旧测试与「固定端口更稳」的偏好）。 */
export function portForServer(serverName: string): number {
  let hash = 0
  for (let index = 0; index < serverName.length; index += 1) {
    hash = (Math.imul(hash, 31) + serverName.charCodeAt(index)) >>> 0
  }
  return 49152 + (hash % 16384)
}

/** 在用的回调监听器，按 serverName 共享。 */
const listeners = new Map<string, ListenerEntry>()

/** 一个 loopback 监听轮次的存活状态。 */
interface ListenerEntry {
  server: Server
  url: string
  state: string | undefined
  settle: { resolve: (code: string) => void; reject: (error: Error) => void }
  timer: NodeJS.Timeout | null
}

/** 绑定一个 loopback 端口，任何错误都转为 rejected（绝不冒泡炸掉宿主）。 */
function bindServer(port: number): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    const onError = (error: Error): void => {
      server.removeListener('error', onError)
      server.on('error', () => {})
      server.close()
      reject(error)
    }
    server.once('error', onError)
    server.once('listening', () => {
      server.removeListener('error', onError)
      server.on('error', () => {})
      resolve(server)
    })
    server.listen(port, '127.0.0.1')
  })
}

/**
 * 绑定卡片的 loopback 回调监听器，返回回调地址与等待授权码 / 关闭的句柄。
 * @param serverName - 卡片名（serverName）。
 * @param candidates - 候选端口，末尾应为 `0`（OS 随机分配）。
 * @param log - 诊断日志。
 */
async function ensureListener(
  serverName: string,
  candidates: number[],
  log?: (message: string) => void,
): Promise<{ url: string; wait(): Promise<string>; close(): void }> {
  const existing = listeners.get(serverName)
  if (existing !== undefined) {
    return { url: existing.url, wait: () => waitForCode(existing), close: () => closeEntry(serverName) }
  }

  for (const candidate of candidates) {
    try {
      const server = await bindServer(candidate)
      const address = server.address()
      const port = typeof address === 'object' && address !== null ? address.port : candidate
      const url = `http://127.0.0.1:${port}${REDIRECT_PATH}`
      let settle: { resolve: (code: string) => void; reject: (error: Error) => void } | null = null
      const codePromise = new Promise<string>((resolve, reject) => {
        settle = { resolve, reject }
      })
      const entry: ListenerEntry = { server, url, state: undefined, settle: settle!, timer: null }

      server.on('request', (req, res) => {
        const reqUrl = new URL(req.url ?? '/', url)
        const code = reqUrl.searchParams.get('code')
        const error = reqUrl.searchParams.get('error')
        const backState = reqUrl.searchParams.get('state')
        const ok = Boolean(code) && backState === entry.state
        res.writeHead(ok ? 200 : 400, {
          'Content-Type': 'text/html; charset=utf-8',
          Connection: 'close',
        })
        res.end(
          ok
            ? '<html><body><p>OAuth 授权完成，可关闭此标签页。</p></body></html>'
            : `<html><body><p>授权失败：${error || '缺少授权码或 state 不匹配'}</p></body></html>`,
        )
        try {
          server.close()
        } catch {
          // 关闭失败不影响流程
        }
        closeEntry(serverName)
        if (entry.timer !== null) clearTimeout(entry.timer)
        if (ok) entry.settle.resolve(code as string)
        else if (error) entry.settle.reject(new Error(`授权失败：${error}`))
        else entry.settle.reject(new Error('回调缺少 code 或 state 不匹配'))
      })

      listeners.set(serverName, entry)
      if (candidate !== 0 && candidate !== port) {
        log?.(`dsh-oauth-plugin-capabilities: '${serverName}' 回调端口 ${candidate} 不可用，改用 ${port}`)
      }
      return { url, wait: () => waitForCode(entry), close: () => closeEntry(serverName) }
    } catch (error) {
      const reason = (error as { code?: unknown })?.code ?? (error as { message?: unknown })?.message ?? 'bind failed'
      if (candidate !== 0) {
        log?.(`dsh-oauth-plugin-capabilities: '${serverName}' 回调端口 ${candidate} 绑定失败：${reason}，尝试下一个`)
      }
    }
  }
  throw new Error(`无法为 '${serverName}' 绑定 OAuth 回调端口`)
}

/** 等待授权码（带超时）。 */
function waitForCode(entry: ListenerEntry): Promise<string> {
  entry.timer = setTimeout(() => {
    try {
      entry.server.close()
    } catch {
      // 忽略
    }
    entry.settle.reject(new Error('等待授权超时，请重新发起授权'))
  }, OAUTH_BUDGET_MS)
  return new Promise<string>((resolve, reject) => {
    const originalReject = entry.settle.reject
    entry.settle.reject = (error: Error) => {
      originalReject(error)
      reject(error)
    }
    const originalResolve = entry.settle.resolve
    entry.settle.resolve = (code: string) => {
      originalResolve(code)
      resolve(code)
    }
  })
}

/** 关闭并清理一个卡片的回调监听器。 */
function closeEntry(serverName: string): void {
  const entry = listeners.get(serverName)
  if (entry === undefined) return
  listeners.delete(serverName)
  if (entry.timer !== null) clearTimeout(entry.timer)
  try {
    entry.server.close()
  } catch {
    // 忽略
  }
}

/** 释放卡片的回调监听器（导出，便于异常时清理）。 */
export function closeOAuthListener(serverName: string): void {
  closeEntry(serverName)
}

/** 默认浏览器唤起：依次尝试多种平台命令，任一成功即返回；全部失败则抛出带 URL 的错误。 */
export async function defaultOpenBrowser(url: string): Promise<void> {
  const candidates: Array<[string, string[]]> = []
  if (process.platform === 'win32') {
    candidates.push(['rundll32.exe', ['url.dll,FileProtocolHandler', url]])
    candidates.push(['explorer.exe', [url]])
  } else if (process.platform === 'darwin') {
    candidates.push(['open', [url]])
  } else {
    candidates.push(['xdg-open', [url]])
    candidates.push(['gnome-open', [url]])
    candidates.push(['kde-open', [url]])
  }
  for (const [command, args] of candidates) {
    if (await trySpawn(command, args)) return
  }
  throw new Error(`无法自动打开浏览器，请手动在浏览器访问以下地址完成授权：\n${url}`)
}

/** 拉起一个分离进程；等 spawn 事件确认成功；error 则返回 false 以便回退下一个候选。 */
function trySpawn(command: string, args: string[]): Promise<boolean> {
  return new Promise((resolve) => {
    let child
    try {
      child = spawn(command, args, { stdio: 'ignore', detached: true })
    } catch {
      resolve(false)
      return
    }
    child.once('error', () => resolve(false))
    child.once('spawn', () => {
      child.unref()
      resolve(true)
    })
  })
}

// ------------------------------- HTTP 辅助 -------------------------------

/** POST application/x-www-form-urlencoded。 */
async function httpForm(url: string, params: Record<string, string>, timeoutMs: number): Promise<{ status: number; data: Record<string, unknown> }> {
  const body = new URLSearchParams(params).toString()
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: controller.signal,
    })
    const text = await resp.text()
    let data: Record<string, unknown> = {}
    try {
      data = JSON.parse(text) as Record<string, unknown>
    } catch {
      // 非 JSON 响应体按空对象处理
    }
    return { status: resp.status, data }
  } finally {
    clearTimeout(timer)
  }
}

/** POST application/json。 */
async function httpJson(url: string, json: unknown, timeoutMs: number): Promise<{ status: number; data: Record<string, unknown> }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(json),
      signal: controller.signal,
    })
    const text = await resp.text()
    let data: Record<string, unknown> = {}
    try {
      data = JSON.parse(text) as Record<string, unknown>
    } catch {
      // 非 JSON 响应体
    }
    return { status: resp.status, data }
  } finally {
    clearTimeout(timer)
  }
}

// -------------------------- 动态客户端注册 --------------------------

/** 动态客户端注册（RFC 7591），同时发送 snake_case 与 camelCase 字段兼容新旧版。 */
async function registerClient(options: { registerUrl: string; redirectUri: string; clientName?: string }): Promise<string> {
  const { registerUrl, redirectUri, clientName = 'dsh-oauth-plugin-capabilities' } = options
  const resp = await httpJson(
    registerUrl,
    {
      client_name: clientName,
      clientName,
      redirect_uris: [redirectUri],
      redirectUris: [redirectUri],
      scope: 'mcp',
    },
    15_000,
  )
  if (resp.status >= 400 || !resp.data || typeof resp.data.client_id !== 'string') {
    const desc = (resp.data?.error_description as string) ?? (resp.data?.error as string)
    throw new Error(
      `动态客户端注册失败（HTTP ${resp.status}）：${desc || '未知错误'}；` +
        '请确认服务端 McpOAuth:AllowDynamicRegistration=true',
    )
  }
  return resp.data.client_id
}

// ----------------------------- 令牌交换 -----------------------------

/** 用授权码换 token。 */
async function exchangeCode(options: {
  tokenUrl: string
  code: string
  redirectUri: string
  clientId: string
  codeVerifier: string
}): Promise<Record<string, unknown>> {
  const { tokenUrl, code, redirectUri, clientId, codeVerifier } = options
  const resp = await httpForm(
    tokenUrl,
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
    },
    15_000,
  )
  if (resp.status >= 400 || !resp.data || typeof resp.data.access_token !== 'string') {
    const desc = (resp.data?.error_description as string) ?? (resp.data?.error as string)
    throw new Error(`换取访问令牌失败（HTTP ${resp.status}）：${desc || '未知错误'}`)
  }
  return resp.data
}

/** 用 refresh_token 刷新（消费式轮换）。 */
async function refreshTokens(options: { tokenUrl: string; refreshToken: string; clientId: string }): Promise<Record<string, unknown>> {
  const { tokenUrl, refreshToken, clientId } = options
  const resp = await httpForm(
    tokenUrl,
    {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    },
    15_000,
  )
  if (resp.status >= 400 || !resp.data || typeof resp.data.access_token !== 'string') {
    const desc = (resp.data?.error_description as string) ?? (resp.data?.error as string)
    throw new Error(`刷新令牌失败（HTTP ${resp.status}）：${desc || '未知错误'}`)
  }
  return resp.data
}

// ----------------------------- 完整授权流程 -----------------------------

/**
 * 执行一次完整的交互式授权（注册 → 打开浏览器 → 等回调 → 换 token）。
 * @returns 持久化后的 OAuth 文档（含 access_token）。
 */
export async function authorize(options: {
  serverName: string
  baseUrl: string
  store: CredentialStore
  openBrowser?: (url: string) => Promise<void>
  log?: (message: string) => void
  callbackPort?: number
}): Promise<OAuthDoc> {
  const { serverName, baseUrl, store, openBrowser, log, callbackPort } = options
  const ref = serverName
  const { authorizeUrl, tokenUrl, registerUrl } = endpoints(baseUrl)

  const state = b64u(randomBytes(16))
  const codeVerifier = b64u(randomBytes(32))
  const codeChallenge = pkceChallenge(codeVerifier)

  const existing = (await store.read(ref)) ?? {}
  const candidates = [...new Set([callbackPort, 0].filter((candidate): candidate is number => typeof candidate === 'number' && candidate >= 0))]
  const bound = await ensureListener(serverName, candidates, log)
  const redirectUri = bound.url

  let clientId: string | undefined =
    existing.client_id !== undefined && existing.redirect_uri === redirectUri ? existing.client_id : undefined
  if (clientId === undefined) clientId = await registerClient({ registerUrl, redirectUri })
  await store.write(ref, { ...existing, client_id: clientId, redirect_uri: redirectUri })

  const live = listeners.get(serverName)
  if (live !== undefined) live.state = state

  const url =
    `${authorizeUrl}?` +
    new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'mcp',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    }).toString()

  log?.(`dsh-oauth-plugin-capabilities: authorize '${serverName}' -> ${url}`)

  const open = openBrowser ?? defaultOpenBrowser
  await open(url)

  let code: string
  try {
    code = await bound.wait()
  } catch (error) {
    bound.close()
    log?.(`dsh-oauth-plugin-capabilities: 等待授权回调失败：${(error as Error)?.message ?? error}`)
    throw error
  }
  log?.('dsh-oauth-plugin-capabilities: 收到授权回调，正在换取访问令牌')

  const tokenData = await exchangeCode({ tokenUrl, code, redirectUri, clientId, codeVerifier })
  log?.('dsh-oauth-plugin-capabilities: 授权成功，已持久化访问令牌')
  const doc: OAuthDoc = {
    ...existing,
    client_id: clientId,
    redirect_uri: redirectUri,
    access_token: tokenData.access_token as string,
    refresh_token: tokenData.refresh_token as string | undefined,
    expires_at: Date.now() + (Number(tokenData.expires_in) || 3600) * 1000,
    scope: (tokenData.scope as string) || 'mcp',
    baseUrl,
  }
  await store.write(ref, doc)
  return doc
}

/** 刷新令牌（消费式轮换，覆盖写回）。 */
export async function refreshOAuth(serverName: string, baseUrl: string, store: CredentialStore, log?: (message: string) => void): Promise<OAuthDoc> {
  const ref = serverName
  const doc = await store.read(ref)
  if (doc === null || !doc.refresh_token) {
    throw new Error('无 refresh_token，需要重新授权')
  }
  const { tokenUrl } = endpoints(baseUrl)
  const data = await refreshTokens({
    tokenUrl,
    refreshToken: doc.refresh_token,
    clientId: doc.client_id ?? '',
  })
  const updated: OAuthDoc = {
    ...doc,
    access_token: data.access_token as string,
    refresh_token: (data.refresh_token as string) || doc.refresh_token,
    expires_at: Date.now() + (Number(data.expires_in) || 3600) * 1000,
    scope: (data.scope as string) || doc.scope,
  }
  await store.write(ref, updated)
  return updated
}

/**
 * 取得可用 access token，按优先级：
 *   1. 已缓存且未过期；
 *   2. 已过期但有 refresh_token → 静默刷新；
 *   3. 无令牌且 `interactive` → 打开浏览器走完整授权；
 *   4. 无令牌且非交互 → 返回 null。
 */
export async function getValidToken(options: {
  serverName: string
  baseUrl: string
  store: CredentialStore
  openBrowser?: (url: string) => Promise<void>
  log?: (message: string) => void
  callbackPort?: number
  interactive?: boolean
}): Promise<string | null> {
  const { serverName, baseUrl, store, openBrowser, log, callbackPort, interactive = false } = options
  const ref = serverName
  const doc = await store.read(ref)
  const now = Date.now()
  if (doc !== null && doc.access_token !== undefined) {
    const expiresAt = doc.expires_at ?? 0
    if (expiresAt === 0 || expiresAt - REFRESH_SKEW_MS > now) {
      return doc.access_token
    }
    if (doc.refresh_token !== undefined) {
      try {
        return (await refreshOAuth(serverName, baseUrl, store, log)).access_token
      } catch (error) {
        log?.(`dsh-oauth-plugin-capabilities: '${serverName}' 刷新失败，转入重新授权：${(error as Error)?.message ?? error}`)
      }
    }
  }
  if (!interactive) return null
  const entry = await authorize({ serverName, baseUrl, store, openBrowser, log, callbackPort })
  return entry.access_token
}

/** 清空卡片的 OAuth 文档（用于「解除授权」）。 */
export async function clearOAuthDocument(store: CredentialStore, serverName: string): Promise<void> {
  await store.write(serverName, {})
}

/** 读取卡片的 OAuth 文档（null = 未授权）。 */
export async function readOAuthDoc(store: CredentialStore, serverName: string): Promise<OAuthDoc | null> {
  return store.read(serverName)
}

// ----------------------------- 文件凭证库 -----------------------------

/** 文件名安全化（serverName 仅含 [A-Za-z0-9_-]，仍做一次兜底转义）。 */
function safeName(serverName: string): string {
  return String(serverName).replace(/[^A-Za-z0-9_-]/g, '_')
}

/** 基于插件状态目录的文件凭证库工厂。 */
export function createFileCredentialStore(dshHome?: string): CredentialStore {
  const dir = join(pluginStateDir(dshHome), 'oauth')
  return {
    async read(ref: string): Promise<OAuthDoc | null> {
      const path = join(dir, `${safeName(ref)}.json`)
      if (!existsSync(path)) return null
      try {
        const parsed = JSON.parse(readFileSync(path, 'utf8')) as OAuthDoc
        return parsed && typeof parsed === 'object' ? parsed : null
      } catch {
        return null
      }
    },
    async write(ref: string, doc: OAuthDoc): Promise<void> {
      mkdirSync(dir, { recursive: true })
      writeFileSync(join(dir, `${safeName(ref)}.json`), JSON.stringify(doc, null, 2) + '\n', 'utf8')
    },
  }
}
