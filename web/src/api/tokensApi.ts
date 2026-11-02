import { apiFetch } from '@/api/client'

export type TokenScope = 'read' | 'write'

export interface ApiToken {
  token_id: number
  name: string
  scope: TokenScope
  created_at: string
  expires_at: string
  revoked_at: string | null
}

export interface CreatedToken {
  token_id: number
  name: string
  scope: TokenScope
  expires_at: string
  token: string
}

export interface NewTokenInput {
  name: string
  scope: TokenScope
  expiresInDays: number
}

export const TOKENS_QUERY_KEY = ['api-tokens']

const TOKENS_PATH = '/api/tokens'

export const listTokens = () => apiFetch<ApiToken[]>(TOKENS_PATH)

export const createToken = (input: NewTokenInput) =>
  apiFetch<CreatedToken>(TOKENS_PATH, {
    method: 'POST',
    body: JSON.stringify({ name: input.name, scope: input.scope, expires_in_days: input.expiresInDays }),
  })

export const revokeToken = (tokenId: number) =>
  apiFetch<void>(`${TOKENS_PATH}/${tokenId}`, { method: 'DELETE', body: JSON.stringify({ confirm: String(tokenId) }) })
