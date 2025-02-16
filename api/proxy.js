import { IncomingMessage, ServerResponse } from 'http'
import fetch, { Headers } from 'node-fetch'

import microCors from 'micro-cors'
import { send } from 'micro'
import url from 'url'

const middleware = CorsProxyMiddleware({
  origin: '*',
  insecureOrigins: [],
  authorization: noop,
  urlParamName: 'url',
  customUserAgent: 'app/noteshub'
})

/**
 * 
 * @param {IncomingMessage} request 
 * @param {ServerResponse} response 
 */
export default async function(request, response) {
  middleware(request, response, () => {
    const u = url.parse(request.url, true)

    if (!u.search) {
      response.setHeader('content-type', 'text/html')
      const html = `<h2>CORS Proxy</h2><p><strong>Usage:</strong> ${u.pathname}?url=url-to-proxy</p>`
      return send(response, 400, html);
    }

    // Don't waste my precious bandwidth
    return send(response, 403, '');
  })
}


// Utils
/**
 * 
 * @param {url.UrlWithParsedQuery} u 
 * @param {string} paramName 
 * @returns 
 */
function getProxyUrlFromParam(u, paramName) {
  const decodedProxyUrl = decodeURIComponent(u.query[paramName])
  return url.parse(decodedProxyUrl, true)
}

// Midleware
/**
 * @typedef {(req: IncomingMessage, res?: ServerResponse) => boolean} Predicate
 * @typedef {(err?: string) => void} Next
 * @typedef {(req: IncomingMessage, res: ServerResponse, next: Next) => void} Middleware
 */

/**
 * 
 * @param {Predicate} predicate 
 * @param {Middleware} middleware 
 * @returns 
 */
function filter(predicate, middleware) {
  /**
   * 
   * @param {IncomingMessage} req 
   * @param {ServerResponse} res 
   * @param {Next} next 
   */
  function corsProxyMiddleware (req, res, next) {
    if (predicate(req, res)) {
      middleware(req, res, next)
    } else {
      next()
    }
  }

  return corsProxyMiddleware
}

/**
 * 
 * @param  {...Middleware} handlers 
 */
function compose(...handlers) {
  /**
   * 
   * @param {Middleware} handler1 
   * @param {Middleware} handler2 
   */
  const composeTwo = (handler1, handler2) => {
    /**
     * 
     * @param {IncomingMessage} req 
     * @param {ServerResponse} res 
     * @param {Next} next 
     */
    function composed (req, res, next) {
      handler1(req, res, (err) => {
        if (err) {
          return next(err)
        } else {
          return handler2(req, res, next)
        }
      })
    }
    return composed
  }

  let result = handlers.pop()

  while(handlers.length) {
    result = composeTwo(handlers.pop(), result)
  }

  return result
}

/**
 * 
 * @param {IncomingMessage} _req 
 * @param {ServerResponse} _res 
 * @param {Next} next 
 */
function noop (_req, _res, next) {
  next()
}

/**
 * @typedef {{
*   origin: string
*   customUserAgent: string
*   insecureOrigins: string[]
*   authorization: Middleware
*   urlParamName?: string
* }} CorsProxyMiddlewareParams
 */

/**
 * 
 * @param {CorsProxyMiddlewareParams} param0 
 * @returns 
 */
function CorsProxyMiddleware({
  origin,
  insecureOrigins,
  authorization,
  customUserAgent,
  urlParamName
}) {
  const allowHeaders = [
    'accept-encoding',
    'accept-language',
    'accept',
    'access-control-allow-origin',
    'authorization',
    'cache-control',
    'connection',
    'content-length',
    'content-type',
    'dnt',
    'git-protocol',
    'pragma',
    'range',
    'referer',
    'user-agent',
    'x-authorization',
    'x-http-method-override',
    'x-requested-with',
  ]

  const exposeHeaders = [
    'accept-ranges',
    'age',
    'cache-control',
    'content-length',
    'content-language',
    'content-type',
    'date',
    'etag',
    'expires',
    'last-modified',
    'location',
    'pragma',
    'server',
    'transfer-encoding',
    'vary',
    'x-github-request-id',
    'x-redirected-url',
  ]

  const allowMethods = [
    'POST',
    'GET',
    'OPTIONS'
  ]

  function predicate() {
    return true
  }

  /**
   * 
   * @param {IncomingMessage} req 
   * @param {ServerResponse} res 
   * @param {Next} next 
   */
  function sendCorsOK(req, res, next) {
    // Handle CORS preflight request
    if (req.method === 'OPTIONS') {
      return send(res, 200, '')
    } else {
      next()
    }
  }

  /**
   * 
   * @param {IncomingMessage} req 
   * @param {ServerResponse} res 
   */
  function middleware(req, res) {
    const headers = new Headers()
    for (const allowedHeader of allowHeaders) {
      const reqHeader = req.headers[allowedHeader]

      if (reqHeader) {
        if (Array.isArray(reqHeader)) {
          for (const reqHeaderValue of reqHeader) {
            headers.append(allowedHeader, reqHeaderValue)
          }
        } else {
          headers.set(allowedHeader, reqHeader)
        }
      }
    }

    if (customUserAgent) {
      headers.set('user-agent', customUserAgent)
    }

    const u = url.parse(req.url, true)
    
    /**
     * @type {string}
     */
    let proxyUrl
    if (urlParamName) {
      proxyUrl = getProxyUrlFromParam(u, urlParamName).href
    } else {
      const p = u.path
      const parts = p.match(/\/([^/]*)\/(.*)/)
      const pathdomain = parts[1]
      const remainingpath = parts[2]
      const protocol = insecureOrigins.includes(pathdomain) ? 'http' : 'https'
      proxyUrl = `${protocol}://${pathdomain}/${remainingpath}`
    }

    console.log(`Fetching response for Url: ${proxyUrl}`)
    fetch(proxyUrl, {
      method: req.method,
      redirect: 'manual',
      headers,
      body: (req.method !== 'GET' && req.method !== 'HEAD') ? req : undefined
    }).then(f => {
      if (f.headers.has('location')) {
        const originalLocation = f.headers.get('location')

        // Modify the location so the client continues to use the proxy
        let newLocation = ''
        if (urlParamName) {
          const tempUrl = url.parse(req.url, true)
          tempUrl.query[urlParamName] = encodeURIComponent(originalLocation)
          newLocation = url.format({
            protocol: tempUrl.protocol,
            hostname: tempUrl.hostname,
            pathname: tempUrl.pathname,
            query: tempUrl.query
          })
        } else {
          newLocation = originalLocation.replace(/^https?:\//, '')
        }

        console.log(`Redirecting to: ${newLocation}`)
        f.headers.set('location', newLocation)
      }

      res.statusCode = f.status
      for (const h of exposeHeaders) {
        if (h === 'content-length') continue
        if (f.headers.has(h)) {
          res.setHeader(h, f.headers.get(h))
        }
      }

      if (f.redirected) {
        res.setHeader('x-redirected-url', f.url)
      }
      f.body.pipe(res)
    })
    .catch(err => {
      console.error(err)
      send(res, 400, 'Something broke!')
    })
  }

  const cors = microCors({
    allowHeaders,
    exposeHeaders,
    allowMethods,
    allowCredentials: false,
    origin
  })

  return filter(predicate, cors(compose(sendCorsOK, authorization, middleware)))
}
