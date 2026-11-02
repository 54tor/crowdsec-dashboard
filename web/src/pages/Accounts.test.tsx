import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeDecision, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const ACCOUNTS_URL = '/api/accounts'
const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }

const ACCOUNT_ALICE = { account_name: 'alice', account_role: 'admin', created_at: '2026-10-01T10:00:00Z', second_factor_enrolled: true, locked: false }
const ACCOUNT_CAROL = { account_name: 'carol', account_role: 'read_only', created_at: '2026-10-02T10:00:00Z', second_factor_enrolled: false, locked: true }

function accountRoutes(extraRoutes = {}, session = ADMIN_SESSION) {
  return {
    'GET /api/auth/me': session,
    [`GET ${ACCOUNTS_URL}`]: { status: 200, body: [ACCOUNT_ALICE, ACCOUNT_CAROL] },
    ...extraRoutes,
  }
}

async function typeIntoConfirmation(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement, target: string) {
  await user.type(within(dialog).getByLabelText(`Type ${target} to confirm`), target)
}

describe('accounts page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('hidesTheAccountsEntryFromAReadOnlyAccountAndRedirectsToAlerts', async () => {
    stubFetch({
      ...accountRoutes({}, READ_ONLY_SESSION),
      'GET /api/alerts?page=1&per_page=20': { status: 200, body: makePage([]) },
    })
    renderApp('/accounts')

    await screen.findByRole('heading', { name: en.alerts.title })
    expect(screen.queryByRole('link', { name: en.nav.accounts })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: en.accounts.title })).not.toBeInTheDocument()
  })

  it('showsTheAccountsEntryToAnAdministrator', async () => {
    stubFetch(accountRoutes())
    renderApp('/accounts')

    expect(await screen.findByRole('link', { name: en.nav.accounts })).toBeInTheDocument()
    expect(await screen.findByText('carol', { selector: 'td' })).toBeInTheDocument()
  })

  it('createsAnAccountWithARoleAndNeverPutsThePasswordInTheUrl', async () => {
    const fetchMock = stubFetch(accountRoutes({ [`POST ${ACCOUNTS_URL}`]: { status: 201, body: { account_name: 'dave' } } }))
    const user = userEvent.setup()
    renderApp('/accounts')

    await user.click(await screen.findByRole('button', { name: en.accounts.add }))
    const dialog = await screen.findByRole('dialog', { name: en.accounts.addTitle })
    await user.type(within(dialog).getByLabelText(en.accounts.nameLabel), 'dave')
    await user.type(within(dialog).getByLabelText(en.accounts.passwordLabel), 'a-long-test-password')
    await user.selectOptions(within(dialog).getByLabelText(en.accounts.roleLabel), 'admin')
    await user.click(within(dialog).getByRole('button', { name: en.accounts.create }))

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', ACCOUNTS_URL)).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', ACCOUNTS_URL)[0].body))).toEqual({
      account_name: 'dave',
      password: 'a-long-test-password',
      account_role: 'admin',
    })
    expect(fetchMock.mock.calls.every(([requestedUrl]) => !String(requestedUrl).includes('a-long-test-password'))).toBe(true)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.body.innerHTML).not.toContain('a-long-test-password')

    await user.click(screen.getByRole('button', { name: en.accounts.add }))
    const reopenedDialog = await screen.findByRole('dialog', { name: en.accounts.addTitle })
    expect(within(reopenedDialog).getByLabelText(en.accounts.passwordLabel)).toHaveValue('')
    expect(within(reopenedDialog).getByLabelText(en.accounts.nameLabel)).toHaveValue('')
  })

  it('translatesAccountExists', async () => {
    stubFetch(accountRoutes({ [`POST ${ACCOUNTS_URL}`]: { status: 409, body: { error: 'account_exists' } } }))
    const user = userEvent.setup()
    renderApp('/accounts')

    await user.click(await screen.findByRole('button', { name: en.accounts.add }))
    const dialog = await screen.findByRole('dialog', { name: en.accounts.addTitle })
    await user.type(within(dialog).getByLabelText(en.accounts.nameLabel), 'carol')
    await user.type(within(dialog).getByLabelText(en.accounts.passwordLabel), 'a-long-test-password')
    await user.click(within(dialog).getByRole('button', { name: en.accounts.create }))

    expect(await within(dialog).findByText(en.errors.account_exists)).toBeInTheDocument()
  })

  it('changesTheRoleOfAnAccount', async () => {
    const fetchMock = stubFetch(accountRoutes({ [`POST ${ACCOUNTS_URL}/carol/role`]: { status: 200, body: { status: 'ok' } } }))
    const user = userEvent.setup()
    renderApp('/accounts')

    await user.selectOptions(await screen.findByLabelText('Role of carol'), 'admin')

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', `${ACCOUNTS_URL}/carol/role`)).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', `${ACCOUNTS_URL}/carol/role`)[0].body))).toEqual({ account_role: 'admin' })
  })

  it('translatesLastAdminWhenDemoting', async () => {
    const otherAdministrator = { ...ACCOUNT_ALICE, account_name: 'erin' }
    stubFetch(
      accountRoutes({
        [`GET ${ACCOUNTS_URL}`]: { status: 200, body: [ACCOUNT_ALICE, otherAdministrator] },
        [`POST ${ACCOUNTS_URL}/erin/role`]: { status: 409, body: { error: 'last_admin' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/accounts')

    await user.selectOptions(await screen.findByLabelText('Role of erin'), 'read_only')

    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.last_admin)
  })

  it('resetsTheSecondFactorAfterConfirmation', async () => {
    const fetchMock = stubFetch(accountRoutes({ [`POST ${ACCOUNTS_URL}/alice/second-factor/reset`]: { status: 200, body: { status: 'ok' } } }))
    const user = userEvent.setup()
    renderApp('/accounts')

    await user.click(await screen.findByRole('button', { name: 'Reset second factor of alice' }))
    const dialog = await screen.findByRole('dialog')
    const confirmButton = within(dialog).getByRole('button', { name: en.accounts.resetSecondFactor })
    expect(confirmButton).toBeDisabled()
    expect(requestsTo(fetchMock, 'POST', `${ACCOUNTS_URL}/alice/second-factor/reset`)).toHaveLength(0)
    await typeIntoConfirmation(user, dialog, 'alice')
    await user.click(confirmButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', `${ACCOUNTS_URL}/alice/second-factor/reset`)).toHaveLength(1))
  })

  it('revokesSessionsOnlyAfterConfirmationAndUnlocksInOneClick', async () => {
    const fetchMock = stubFetch(
      accountRoutes({
        [`POST ${ACCOUNTS_URL}/carol/sessions/revoke`]: { status: 200, body: { status: 'ok' } },
        [`POST ${ACCOUNTS_URL}/carol/unlock`]: { status: 200, body: { status: 'ok' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/accounts')

    await user.click(await screen.findByRole('button', { name: 'Revoke sessions of carol' }))
    const dialog = await screen.findByRole('dialog')
    expect(requestsTo(fetchMock, 'POST', `${ACCOUNTS_URL}/carol/sessions/revoke`)).toHaveLength(0)
    await user.click(within(dialog).getByRole('button', { name: en.dialog.cancel }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(requestsTo(fetchMock, 'POST', `${ACCOUNTS_URL}/carol/sessions/revoke`)).toHaveLength(0)

    await user.click(screen.getByRole('button', { name: 'Revoke sessions of carol' }))
    const secondDialog = await screen.findByRole('dialog')
    await user.click(within(secondDialog).getByRole('button', { name: en.accounts.revokeSessions }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', `${ACCOUNTS_URL}/carol/sessions/revoke`)).toHaveLength(1))

    await user.click(screen.getByRole('button', { name: 'Unlock carol' }))
    await waitFor(() => expect(requestsTo(fetchMock, 'POST', `${ACCOUNTS_URL}/carol/unlock`)).toHaveLength(1))
    expect(screen.queryByRole('button', { name: 'Unlock alice' })).not.toBeInTheDocument()
  })

  it('protectsTheRowOfTheSignedInAccountButStillAllowsSessionRevocation', async () => {
    stubFetch(accountRoutes())
    renderApp('/accounts')

    expect(await screen.findByLabelText('Role of alice')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete alice' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete alice' })).toHaveAttribute('title', en.accounts.ownAccountProtected)
    expect(screen.getByLabelText('Role of alice')).toHaveAttribute('title', en.accounts.ownAccountProtected)
    expect(screen.getByRole('button', { name: 'Revoke sessions of alice' })).toBeEnabled()
    expect(screen.getByLabelText('Role of carol')).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Delete carol' })).toBeEnabled()
  })

  it('deletesAfterTypingTheAccountName', async () => {
    const fetchMock = stubFetch(accountRoutes({ [`DELETE ${ACCOUNTS_URL}/carol`]: { status: 200, body: { status: 'ok' } } }))
    const user = userEvent.setup()
    renderApp('/accounts')

    await user.click(await screen.findByRole('button', { name: 'Delete carol' }))
    const dialog = await screen.findByRole('dialog')
    const deleteButton = within(dialog).getByRole('button', { name: en.accounts.delete })
    expect(deleteButton).toBeDisabled()
    await typeIntoConfirmation(user, dialog, 'carol')
    await user.click(deleteButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', `${ACCOUNTS_URL}/carol`)).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'DELETE', `${ACCOUNTS_URL}/carol`)[0].body))).toEqual({ confirm: 'carol' })
  })

  it('aWriteRefusedWith403ShowsForbiddenWithoutSigningOut', async () => {
    const fetchMock = stubFetch({
      'GET /api/auth/me': ADMIN_SESSION,
      'GET /api/decisions?page=1&per_page=20': { status: 200, body: makePage([makeDecision({ id: 10, alert_id: 1 })]) },
      'DELETE /api/decisions/10?scope=Ip&value=203.0.113.7': { status: 403, body: { error: 'forbidden' } },
    })
    const user = userEvent.setup()
    renderApp('/decisions')

    await user.click(await screen.findByRole('button', { name: 'Unban 203.0.113.7' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Type 203.0.113.7 to confirm'), '203.0.113.7')
    await user.click(within(dialog).getByRole('button', { name: en.decisions.unban }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(en.errors.forbidden)
    expect(requestsTo(fetchMock, 'GET', '/api/auth/me').length).toBe(1)
    expect(screen.queryByRole('heading', { name: en.login.title })).not.toBeInTheDocument()
  })
})
