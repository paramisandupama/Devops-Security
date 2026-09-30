/*
 * Shared helpers for the IE3142 exploit proof-of-concept scripts.
 *
 * Every PoC prints a single verdict:
 *   EXPLOITED -> the unmodified application has the vulnerability
 *   BLOCKED   -> the hardened application defeated the identical attack
 *
 * Usage:  node poc/<script>.mjs --url http://localhost:3000
 */

export function parseArgs (argv = process.argv.slice(2)) {
  const args = {
    url: process.env.TARGET_URL ?? 'http://localhost:3000',
    ssrfHost: process.env.SSRF_HOST ?? '127.0.0.1',
    ssrfPort: Number(process.env.SSRF_PORT ?? 9999),
    baseline: process.env.BASELINE_PATH ?? '../app/lib/insecurity.ts'
  }
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i].replace(/^--/, '')
    if (key === 'help' || key === 'h') {
      console.log('Options: --url <baseUrl> --ssrf-host <host> --ssrf-port <port> --baseline <path to source>')
      process.exit(0)
    }
    args[key.replace(/-(\w)/g, (_, c) => c.toUpperCase())] = argv[i + 1]
    i++
  }
  args.url = args.url.replace(/\/$/, '')
  return args
}

/** Perform an HTTP request and return { status, headers, text, json }. */
export async function request (path, {
  method = 'GET',
  headers = {},
  body = null,
  json = false,
  redirect = 'manual',
  cookie = null,
  timeoutMs = 15000
} = {}) {
  const url = path.startsWith('http') ? path : `${ARGS.url}${path}`
  const finalHeaders = { ...headers }
  if (cookie) finalHeaders.Cookie = `token=${cookie}`
  if (json) finalHeaders['Content-Type'] = 'application/json'
  if (body && !json) finalHeaders['Content-Type'] = 'application/x-www-form-urlencoded'

  const response = await fetch(url, {
    method,
    headers: finalHeaders,
    body: body ?? undefined,
    redirect,
    signal: AbortSignal.timeout(timeoutMs)
  })
  const text = await response.text()
  let parsed = null
  try { parsed = JSON.parse(text) } catch { /* not JSON, keep raw text */ }
  return { status: response.status, headers: response.headers, text, json: parsed }
}

export const ARGS = parseArgs()

/** Register a fresh customer account and return its credentials. */
export async function registerUser (email, password) {
  return await request('/api/Users', {
    method: 'POST',
    json: true,
    body: JSON.stringify({
      email,
      password,
      passwordRepeat: password,
      securityQuestion: { id: 1 },
      securityAnswer: 'IE3142'
    })
  })
}

/** Log in and return { token, bid, email } or null. */
export async function login (email, password) {
  const res = await request('/rest/user/login', {
    method: 'POST',
    json: true,
    body: JSON.stringify({ email, password })
  })
  if (res.status !== 200 || !res.json?.authentication?.token) return null
  return {
    token: res.json.authentication.token,
    bid: res.json.authentication.bid,
    email
  }
}

export function decodeJwtPayload (token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(Buffer.from(part, 'base64').toString('utf8'))
  } catch {
    return null
  }
}

const GREEN = '\x1b[32m'; const RED = '\x1b[31m'; const YELLOW = '\x1b[33m'
const BOLD = '\x1b[1m'; const RESET = '\x1b[0m'

/**
 * Print the result of a PoC.
 * @param {object} o
 * @param {string} o.id        e.g. 'V1'
 * @param {string} o.title     e.g. 'SQL Injection - authentication bypass'
 * @param {string} o.cwe       e.g. 'CWE-89'
 * @param {boolean} o.exploited true when the attack succeeded
 * @param {string[]} o.evidence lines of evidence to print
 */
export function verdict ({ id, title, cwe, exploited, evidence = [] }) {
  const colour = exploited ? RED : GREEN
  const label = exploited ? 'EXPLOITED' : 'BLOCKED'
  console.log('')
  console.log(`${BOLD}${'='.repeat(78)}${RESET}`)
  console.log(`${BOLD}${id} - ${title}${RESET}  ${YELLOW}(${cwe})${RESET}`)
  console.log(`${BOLD}Target:${RESET} ${ARGS.url}`)
  console.log(`${BOLD}${'='.repeat(78)}${RESET}`)
  for (const line of evidence) console.log('  ' + line)
  console.log('')
  console.log(`${colour}${BOLD}  >>> ${label}${RESET}`)
  console.log(`${BOLD}${'='.repeat(78)}${RESET}`)
  console.log('')
  // Exit code 0 = exploit worked (used by run-before.sh), 1 = it was blocked.
  process.exit(exploited ? 0 : 1)
}
