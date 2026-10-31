import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RecoveryCodesStep } from '@/components/RecoveryCodesStep'
import { SecondFactorStep } from '@/components/SecondFactorStep'
import { TotpEnrollment } from '@/components/TotpEnrollment'
import { initI18n, setLanguage } from '@/i18n'
import en from '@/i18n/en.json'
import { stubFetch } from '@/test/fetchStub'
import type { SecondFactorFlow } from '@/api/secondFactorApi'

const FLOW: SecondFactorFlow = { basePath: '/api/auth/enroll', extraBody: { token: 'enrollment-token-value' } }
const TOTP_SECRET = 'JBSWY3DPEHPK3PXP'
const TOTP_BEGIN = {
  status: 200,
  body: { secret: TOTP_SECRET, otpauth_url: `otpauth://totp/dashboard:alice?secret=${TOTP_SECRET}` },
}
const OK = { status: 200, body: { status: 'ok' } }
const RECOVERY_CODES = ['aaaa-bbbb-cccc', 'dddd-eeee-ffff', 'gggg-hhhh-iiii']

function requestBodyOf(fetchMock: ReturnType<typeof stubFetch>, requestedPath: string): unknown {
  const matchingCall = fetchMock.mock.calls.find(([calledPath]) => calledPath === requestedPath)
  return JSON.parse(String(matchingCall?.[1]?.body))
}

function installCredentials(credentials: unknown) {
  Object.defineProperty(navigator, 'credentials', { value: credentials, configurable: true })
}

describe('second factor enrolment components', () => {
  beforeEach(async () => {
    await initI18n()
    await setLanguage('en')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    Reflect.deleteProperty(navigator, 'credentials')
    Reflect.deleteProperty(navigator, 'clipboard')
  })

  it('TotpEnrollmentShowsTheQrCodeAndTheSecretThenConfirmsTheCode', async () => {
    const fetchMock = stubFetch({ 'POST /api/auth/enroll/totp': TOTP_BEGIN, 'POST /api/auth/enroll/totp/confirm': OK })
    const onConfirmed = vi.fn()
    const user = userEvent.setup()
    const { container } = render(<TotpEnrollment flow={FLOW} onConfirmed={onConfirmed} />)

    const qrImage = await screen.findByRole('img', { name: en.enroll.secondFactor.qrLabel })
    expect(qrImage.tagName.toLowerCase()).toBe('svg')
    expect(container.querySelector('[style]')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText(TOTP_SECRET)).toBeInTheDocument()
    expect(requestBodyOf(fetchMock, '/api/auth/enroll/totp')).toEqual({ token: 'enrollment-token-value' })

    const codeInput = screen.getByLabelText(en.enroll.secondFactor.codeLabel)
    expect(codeInput).toHaveAttribute('inputmode', 'numeric')
    expect(codeInput).toHaveAttribute('autocomplete', 'one-time-code')
    await user.type(codeInput, '123456')
    await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.confirm }))

    await waitFor(() => expect(onConfirmed).toHaveBeenCalledTimes(1))
    expect(requestBodyOf(fetchMock, '/api/auth/enroll/totp/confirm')).toEqual({
      token: 'enrollment-token-value',
      code: '123456',
    })
  })

  it('TotpEnrollmentTranslatesInvalidCode', async () => {
    stubFetch({
      'POST /api/auth/enroll/totp': TOTP_BEGIN,
      'POST /api/auth/enroll/totp/confirm': { status: 400, body: { error: 'invalid_code' } },
    })
    const onConfirmed = vi.fn()
    const user = userEvent.setup()
    render(<TotpEnrollment flow={FLOW} onConfirmed={onConfirmed} />)
    await user.type(await screen.findByLabelText(en.enroll.secondFactor.codeLabel), '000000')
    await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.confirm }))

    const alertElement = await screen.findByRole('alert')
    expect(alertElement).toHaveTextContent(en.errors.invalid_code)
    expect(alertElement).toHaveFocus()
    expect(onConfirmed).not.toHaveBeenCalled()
  })

  it('TotpEnrollmentReportsADatabaseOutageWithoutLeavingTheStep', async () => {
    stubFetch({ 'POST /api/auth/enroll/totp': { status: 503, body: { error: 'database_unavailable' } } })
    render(<TotpEnrollment flow={FLOW} onConfirmed={vi.fn()} />)
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
  })

  it('SecondFactorStepHidesWebAuthnWhenMethodsDoNotContainIt', async () => {
    stubFetch({ 'POST /api/auth/enroll/totp': TOTP_BEGIN })
    render(<SecondFactorStep flow={FLOW} methods={['totp']} onConfirmed={vi.fn()} />)
    expect(await screen.findByRole('img', { name: en.enroll.secondFactor.qrLabel })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.enroll.secondFactor.methodWebauthn })).not.toBeInTheDocument()
  })

  it('SecondFactorStepRegistersAWebAuthnKeyThroughTheSimulatedCredentialsApi', async () => {
    const serializedCredential = { id: 'credential-id', type: 'public-key', response: { clientDataJSON: 'abc' } }
    const createCredential = vi.fn(async () => ({ toJSON: () => serializedCredential }))
    installCredentials({ create: createCredential })
    const fetchMock = stubFetch({
      'POST /api/auth/enroll/webauthn/options': {
        status: 200,
        body: {
          publicKey: {
            challenge: 'AQID',
            rp: { name: 'Dashboard' },
            user: { id: 'BAUG', name: 'alice', displayName: 'alice' },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            excludeCredentials: [{ type: 'public-key', id: 'Bw-_' }],
          },
        },
      },
      'POST /api/auth/enroll/webauthn/confirm': OK,
    })
    const onConfirmed = vi.fn()
    const user = userEvent.setup()
    render(<SecondFactorStep flow={FLOW} methods={['totp', 'webauthn']} onConfirmed={onConfirmed} />)

    await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.methodWebauthn }))

    await waitFor(() => expect(onConfirmed).toHaveBeenCalledTimes(1))
    expect(requestBodyOf(fetchMock, '/api/auth/enroll/webauthn/options')).toEqual({ token: 'enrollment-token-value' })
    const creationArgument = (createCredential.mock.calls[0] as unknown as [CredentialCreationOptions])[0]
    const publicKey = creationArgument.publicKey!
    expect(Array.from(new Uint8Array(publicKey.challenge as ArrayBuffer))).toEqual([1, 2, 3])
    expect(Array.from(new Uint8Array(publicKey.user.id as ArrayBuffer))).toEqual([4, 5, 6])
    expect(Array.from(new Uint8Array(publicKey.excludeCredentials![0].id as ArrayBuffer))).toEqual([7, 15, 191])
    expect(requestBodyOf(fetchMock, '/api/auth/enroll/webauthn/confirm')).toEqual({
      token: 'enrollment-token-value',
      credential: serializedCredential,
    })
  })

  it('SecondFactorStepOffersTotpWhenWebAuthnIsNotSupported', async () => {
    stubFetch({ 'POST /api/auth/enroll/totp': TOTP_BEGIN })
    const onConfirmed = vi.fn()
    const user = userEvent.setup()
    render(<SecondFactorStep flow={FLOW} methods={['totp', 'webauthn']} onConfirmed={onConfirmed} />)

    await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.methodWebauthn }))
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.webauthn_unsupported)
    expect(onConfirmed).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.methodTotp }))
    expect(await screen.findByRole('img', { name: en.enroll.secondFactor.qrLabel })).toBeInTheDocument()
  })

  it('SecondFactorStepTranslatesAWebAuthnRefusalByTheUser', async () => {
    installCredentials({ create: vi.fn(async () => Promise.reject(new DOMException('denied', 'NotAllowedError'))) })
    stubFetch({
      'POST /api/auth/enroll/webauthn/options': {
        status: 200,
        body: { publicKey: { challenge: 'AQID', rp: { name: 'D' }, user: { id: 'BAUG', name: 'a', displayName: 'a' }, pubKeyCredParams: [] } },
      },
    })
    const user = userEvent.setup()
    render(<SecondFactorStep flow={FLOW} methods={['totp', 'webauthn']} onConfirmed={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: en.enroll.secondFactor.methodWebauthn }))
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.webauthn_failed)
  })

  it('RecoveryCodesStepDisablesFinishUntilTheCodesAreAcknowledged', async () => {
    const fetchMock = stubFetch({ 'POST /api/auth/enroll/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } } })
    const onFinish = vi.fn(async () => undefined)
    const user = userEvent.setup()
    render(<RecoveryCodesStep flow={FLOW} onFinish={onFinish} />)

    for (const recoveryCode of RECOVERY_CODES) {
      expect(await screen.findByText(recoveryCode)).toBeInTheDocument()
    }
    expect(requestBodyOf(fetchMock, '/api/auth/enroll/recovery-codes')).toEqual({ token: 'enrollment-token-value' })
    const finishButton = screen.getByRole('button', { name: en.enroll.recoveryCodes.finish })
    expect(finishButton).toBeDisabled()
    await user.click(screen.getByRole('checkbox', { name: en.enroll.recoveryCodes.acknowledge }))
    expect(finishButton).toBeEnabled()
    await user.click(finishButton)
    await waitFor(() => expect(onFinish).toHaveBeenCalledTimes(1))
  })

  it('RecoveryCodesStepCopiesTheCodesToTheClipboard', async () => {
    stubFetch({ 'POST /api/auth/enroll/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } } })
    const user = userEvent.setup()
    render(<RecoveryCodesStep flow={FLOW} onFinish={vi.fn()} />)
    await screen.findByText(RECOVERY_CODES[0])
    const writeText = vi.fn(async () => undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    await user.click(screen.getByRole('button', { name: en.enroll.recoveryCodes.copy }))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(RECOVERY_CODES.join('\n')))
  })

  it('RecoveryCodesStepDownloadsTheCodesAsATextFile', async () => {
    stubFetch({ 'POST /api/auth/enroll/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } } })
    const createObjectUrl = vi.fn(() => 'blob:codes')
    const revokeObjectUrl = vi.fn()
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: createObjectUrl, revokeObjectURL: revokeObjectUrl }))
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    const user = userEvent.setup()
    render(<RecoveryCodesStep flow={FLOW} onFinish={vi.fn()} />)
    await screen.findByText(RECOVERY_CODES[0])
    await user.click(screen.getByRole('button', { name: en.enroll.recoveryCodes.download }))

    expect(createObjectUrl).toHaveBeenCalledTimes(1)
    const downloadedBlob = (createObjectUrl.mock.calls[0] as unknown as [Blob])[0]
    expect(await downloadedBlob.text()).toBe(RECOVERY_CODES.join('\n'))
    expect(clickSpy).toHaveBeenCalledTimes(1)
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:codes')
    clickSpy.mockRestore()
  })

  it('RecoveryCodesStepShowsTheErrorWhenCompletionFails', async () => {
    stubFetch({ 'POST /api/auth/enroll/recovery-codes': { status: 200, body: { recovery_codes: RECOVERY_CODES } } })
    const onFinish = vi.fn(async () => Promise.reject({ code: 'database_unavailable' }))
    const user = userEvent.setup()
    render(<RecoveryCodesStep flow={FLOW} onFinish={onFinish} />)
    await screen.findByText(RECOVERY_CODES[0])
    await user.click(screen.getByRole('checkbox', { name: en.enroll.recoveryCodes.acknowledge }))
    await user.click(screen.getByRole('button', { name: en.enroll.recoveryCodes.finish }))
    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
  })
})
