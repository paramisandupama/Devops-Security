/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * SSRF guard for the avatar endpoint (V3, CWE-918).
 *
 * The route used to call fetch() on any URL a user supplied and, when the
 * fetch failed, stored that URL as the profile image - which turned the
 * application into a proxy for its own network: loopback services, peer
 * containers on the compose network, and the cloud metadata endpoint at
 * 169.254.169.254.
 *
 * The guard resolves the host name FIRST and rejects the request if ANY
 * resolved address falls inside a private, loopback, link-local or otherwise
 * reserved range. Checking the literal in the URL alone would not be enough:
 * an attacker-controlled name that resolves to 127.0.0.1 would sail through.
 * Redirects are refused by the caller, so the check cannot be bypassed by
 * answering with a public address that redirects somewhere internal.
 */

import dns from 'node:dns/promises'
import net from 'node:net'

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:'])
const MAX_BYTES = 2 * 1024 * 1024
const FETCH_TIMEOUT_MS = 5000

const BLOCKED_HOSTNAMES = new Set([
  'localhost', 'metadata', 'metadata.google.internal', 'instance-data'
])

const BLOCKED_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '224.0.0.0/4', '240.0.0.0/4'
]

function ipv4ToInt (ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0
}

function inRange (ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split('/')
  const bits = Number(bitsRaw)
  if (bits === 0) return true
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask)
}

export function isBlockedAddress (address: string): boolean {
  let ip = address.trim().toLowerCase()

  // ::ffff:10.0.0.1 is an IPv4 address wearing an IPv6 disguise.
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  if (mapped) ip = mapped[1]

  if (net.isIPv4(ip)) return BLOCKED_V4.some(cidr => inRange(ip, cidr))

  if (net.isIPv6(ip)) {
    if (ip === '::' || ip === '::1') return true
    const head = ip.split(':')[0]
    if (/^f[cd]/.test(head)) return true        // fc00::/7  unique local
    if (/^fe[89ab]/.test(head)) return true     // fe80::/10 link local
    if (head === '2002') return true             // 6to4, embeds an IPv4 address
    return false
  }

  // Not a literal address at all - refuse rather than guess.
  return true
}

export class UnsafeUrlError extends Error {}

export async function assertSafeImageUrl (rawUrl: string): Promise<URL> {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 2048) {
    throw new UnsafeUrlError('imageUrl is missing or implausibly long')
  }

  let target: URL
  try {
    target = new URL(rawUrl)
  } catch {
    throw new UnsafeUrlError('imageUrl is not a valid absolute URL')
  }

  if (!ALLOWED_PROTOCOLS.has(target.protocol)) {
    throw new UnsafeUrlError(`refusing protocol ${target.protocol}`)
  }

  const hostname = target.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.internal') || hostname.endsWith('.local')) {
    throw new UnsafeUrlError(`refusing internal host name ${hostname}`)
  }

  let addresses: string[]
  if (net.isIP(hostname)) {
    addresses = [hostname]
  } else {
    try {
      addresses = (await dns.lookup(hostname, { all: true })).map(a => a.address)
    } catch {
      throw new UnsafeUrlError(`cannot resolve ${hostname}`)
    }
  }

  if (addresses.length === 0) throw new UnsafeUrlError(`cannot resolve ${hostname}`)

  for (const address of addresses) {
    if (isBlockedAddress(address)) {
      throw new UnsafeUrlError(`refusing ${hostname} -> ${address} (private, loopback or reserved)`)
    }
  }

  return target
}

export const IMAGE_FETCH_LIMITS = { MAX_BYTES, FETCH_TIMEOUT_MS }
