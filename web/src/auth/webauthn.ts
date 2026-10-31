import { ApiError } from '@/api/client'

function decodeBase64Url(encodedValue: string): ArrayBuffer {
  const base64Value = encodedValue.replace(/-/g, '+').replace(/_/g, '/')
  const paddedValue = base64Value.padEnd(Math.ceil(base64Value.length / 4) * 4, '=')
  const binaryValue = atob(paddedValue)
  const bytes = new Uint8Array(binaryValue.length)
  for (let byteIndex = 0; byteIndex < binaryValue.length; byteIndex += 1) {
    bytes[byteIndex] = binaryValue.charCodeAt(byteIndex)
  }
  return bytes.buffer
}

function decodeDescriptors(descriptors: PublicKeyCredentialDescriptorJSON[] | undefined) {
  return descriptors?.map((descriptor) => ({ ...descriptor, id: decodeBase64Url(descriptor.id) }))
}

export function requireCredentialsApi(): CredentialsContainer {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new ApiError('webauthn_unsupported', 0)
  }
  return navigator.credentials
}

async function runCeremony(operation: () => Promise<Credential | null>): Promise<unknown> {
  let credential: Credential | null
  try {
    credential = await operation()
  } catch {
    throw new ApiError('webauthn_failed', 0)
  }
  if (!credential || !('toJSON' in credential) || typeof credential.toJSON !== 'function') {
    throw new ApiError('webauthn_unsupported', 0)
  }
  return credential.toJSON()
}

export function createWebAuthnCredential(options: { publicKey: PublicKeyCredentialCreationOptionsJSON }): Promise<unknown> {
  const credentials = requireCredentialsApi()
  const { publicKey } = options
  return runCeremony(() =>
    credentials.create({
      publicKey: {
        ...publicKey,
        challenge: decodeBase64Url(publicKey.challenge),
        user: { ...publicKey.user, id: decodeBase64Url(publicKey.user.id) },
        excludeCredentials: decodeDescriptors(publicKey.excludeCredentials),
      },
    } as CredentialCreationOptions),
  )
}

export function getWebAuthnAssertion(options: { publicKey: PublicKeyCredentialRequestOptionsJSON }): Promise<unknown> {
  const credentials = requireCredentialsApi()
  const { publicKey } = options
  return runCeremony(() =>
    credentials.get({
      publicKey: {
        ...publicKey,
        challenge: decodeBase64Url(publicKey.challenge),
        allowCredentials: decodeDescriptors(publicKey.allowCredentials),
      },
    } as CredentialRequestOptions),
  )
}
