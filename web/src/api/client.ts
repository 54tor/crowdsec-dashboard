export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly retryAfterSeconds?: number
  readonly details?: Record<string, unknown>

  constructor(code: string, status: number, retryAfterSeconds?: number, details?: Record<string, unknown>) {
    super(code)
    this.name = 'ApiError'
    this.code = code
    this.status = status
    this.retryAfterSeconds = retryAfterSeconds
    this.details = details
  }
}

type UnauthenticatedHandler = () => void

let unauthenticatedHandler: UnauthenticatedHandler | null = null
let hasNotifiedUnauthenticated = false

export function setUnauthenticatedHandler(handler: UnauthenticatedHandler | null): void {
  unauthenticatedHandler = handler
}

export function resetUnauthenticatedGuard(): void {
  hasNotifiedUnauthenticated = false
}

function notifyUnauthenticatedOnce(): void {
  if (hasNotifiedUnauthenticated) {
    return
  }
  hasNotifiedUnauthenticated = true
  unauthenticatedHandler?.()
}

interface ErrorBody {
  code: string
  details?: Record<string, unknown>
}

async function readErrorBody(response: Response): Promise<ErrorBody> {
  const fallbackCode = response.status === 429 ? 'too_many_attempts' : 'unknown'
  try {
    const body: unknown = await response.json()
    if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') {
      return { code: body.error, details: body as Record<string, unknown> }
    }
  } catch {
    return { code: fallbackCode }
  }
  return { code: fallbackCode }
}

function readRetryAfterSeconds(response: Response): number | undefined {
  const headerValue = response.headers.get('Retry-After')
  const retryAfterSeconds = headerValue === null ? Number.NaN : Number(headerValue)
  return Number.isInteger(retryAfterSeconds) && retryAfterSeconds > 0 ? retryAfterSeconds : undefined
}

export async function apiFetchResponse(path: string, init?: RequestInit): Promise<Response> {
  let response: Response
  try {
    response = await fetch(path, {
      credentials: 'same-origin',
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    })
  } catch {
    throw new ApiError('network', 0)
  }
  if (!response.ok) {
    const { code, details } = await readErrorBody(response)
    if (code === 'unauthenticated') {
      notifyUnauthenticatedOnce()
    }
    throw new ApiError(code, response.status, readRetryAfterSeconds(response), details)
  }
  return response
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await apiFetchResponse(path, init)
  if (response.status === 204) {
    return undefined as T
  }
  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError('unknown', response.status)
  }
}
