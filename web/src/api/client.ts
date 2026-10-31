export class ApiError extends Error {
  readonly code: string
  readonly status: number

  constructor(code: string, status: number) {
    super(code)
    this.name = 'ApiError'
    this.code = code
    this.status = status
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

async function readErrorCode(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json()
    if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') {
      return body.error
    }
  } catch {
    return 'unknown'
  }
  return 'unknown'
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
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
    const code = await readErrorCode(response)
    if (code === 'unauthenticated') {
      notifyUnauthenticatedOnce()
    }
    throw new ApiError(code, response.status)
  }
  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}
