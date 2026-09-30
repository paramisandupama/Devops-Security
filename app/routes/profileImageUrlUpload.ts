/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { assertSafeImageUrl, IMAGE_FETCH_LIMITS } from '../lib/urlSafety'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          // V3 fix (CWE-918). Validate before fetching: scheme allow-list,
          // internal names rejected, DNS resolution with every answer checked
          // against private and reserved ranges, redirects refused, timeout
          // and size caps.
          const response = await fetch(await assertSafeImageUrl(url), {
            redirect: 'manual',
            signal: AbortSignal.timeout(IMAGE_FETCH_LIMITS.FETCH_TIMEOUT_MS)
          })
          if (response.status >= 300 && response.status < 400) {
            throw new Error('refusing to follow a redirect: the target could be internal')
          }
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const contentType = response.headers.get('content-type') ?? ''
          if (!contentType.startsWith('image/')) {
            throw new Error(`refusing non-image content-type: ${contentType}`)
          }
          const declaredLength = Number(response.headers.get('content-length') ?? '0')
          if (Number.isFinite(declaredLength) && declaredLength > IMAGE_FETCH_LIMITS.MAX_BYTES) {
            throw new Error('image exceeds the size limit')
          }
          const safePath = (await assertSafeImageUrl(url)).pathname
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(safePath.split('.').slice(-1)[0].toLowerCase()) ? safePath.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: (await assertSafeImageUrl(url)).toString() })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
