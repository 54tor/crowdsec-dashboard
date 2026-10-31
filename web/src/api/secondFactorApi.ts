import { apiFetch } from '@/api/client'

export interface SecondFactorFlow {
  basePath: string
  extraBody: Record<string, string>
}

export interface TotpEnrollmentDetails {
  secret: string
  otpauth_url: string
}

export interface WebAuthnCreationResponse {
  publicKey: PublicKeyCredentialCreationOptionsJSON
}

function postToFlow<Response>(flow: SecondFactorFlow, suffix: string, extraFields: Record<string, unknown> = {}) {
  return apiFetch<Response>(`${flow.basePath}${suffix}`, {
    method: 'POST',
    body: JSON.stringify({ ...flow.extraBody, ...extraFields }),
  })
}

export function beginTotp(flow: SecondFactorFlow): Promise<TotpEnrollmentDetails> {
  return postToFlow(flow, '/totp')
}

export function confirmTotp(flow: SecondFactorFlow, code: string): Promise<void> {
  return postToFlow(flow, '/totp/confirm', { code })
}

export function webAuthnRegistrationOptions(flow: SecondFactorFlow): Promise<WebAuthnCreationResponse> {
  return postToFlow(flow, '/webauthn/options')
}

export function confirmWebAuthn(flow: SecondFactorFlow, credential: unknown): Promise<void> {
  return postToFlow(flow, '/webauthn/confirm', { credential })
}

export async function fetchRecoveryCodes(flow: SecondFactorFlow): Promise<string[]> {
  const recoveryResponse = await postToFlow<{ recovery_codes: string[] }>(flow, '/recovery-codes')
  return recoveryResponse.recovery_codes
}

export function completeSetup(flow: SecondFactorFlow): Promise<void> {
  return postToFlow(flow, '/complete')
}
