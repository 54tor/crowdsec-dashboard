import { apiFetch } from '@/api/client'
import { requireCredentialsApi, getWebAuthnAssertion } from '@/auth/webauthn'
import type { SecondFactorFlow } from '@/api/secondFactorApi'

export type LoginStage = 'second_factor' | 'setup'
export type LoginSecondFactorMethod = 'totp' | 'recovery_code' | 'webauthn'

export interface LoginProgress {
  stage: LoginStage
  methods: string[]
}

export const LOGIN_SETUP_FLOW: SecondFactorFlow = { basePath: '/api/auth/login/setup', extraBody: {} }

interface LoginResponse {
  status: 'second_factor_required' | 'second_factor_setup_required'
  methods: string[]
}

function postJson<Response>(path: string, body: unknown) {
  return apiFetch<Response>(path, { method: 'POST', body: JSON.stringify(body) })
}

export async function beginLogin(accountName: string, password: string): Promise<LoginProgress> {
  const loginResponse = await postJson<LoginResponse>('/api/auth/login', { account_name: accountName, password })
  return {
    stage: loginResponse.status === 'second_factor_setup_required' ? 'setup' : 'second_factor',
    methods: loginResponse.methods ?? [],
  }
}

async function verifyWebAuthn(): Promise<void> {
  requireCredentialsApi()
  const assertionOptions = await postJson<{ publicKey: PublicKeyCredentialRequestOptionsJSON }>(
    '/api/auth/login/webauthn/options',
    {},
  )
  const credential = await getWebAuthnAssertion(assertionOptions)
  await postJson('/api/auth/login/webauthn', { credential })
}

export async function verifyLoginSecondFactor(method: LoginSecondFactorMethod, value = ''): Promise<void> {
  if (method === 'webauthn') {
    return verifyWebAuthn()
  }
  const path = method === 'totp' ? '/api/auth/login/totp' : '/api/auth/login/recovery-code'
  await postJson(path, { code: value })
}

export async function completeLoginSetup(): Promise<void> {
  await postJson('/api/auth/login/setup/complete', {})
}
