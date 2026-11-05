import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const FAKE_TOKEN = 'csd_fake_token_value_for_tests'
const TOKENS_URL = '/api/tokens'
const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }

const EXISTING_TOKEN = {
  token_id: 7,
  name: 'ci-reader',
  scope: 'read',
  created_at: '2026-10-01T10:00:00Z',
  expires_at: '2027-01-01T10:00:00Z',
  revoked_at: null,
}

function tokenRoutes(extraRoutes = {}, session = ADMIN_SESSION) {
  return {
    'GET /api/auth/me': session,
    [`GET ${TOKENS_URL}`]: { status: 200, body: [EXISTING_TOKEN] },
    ...extraRoutes,
  }
}

async function openCreationDialog(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: en.tokens.add }))
  return screen.findByRole('dialog', { name: en.tokens.addTitle })
}

async function submitToken(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement, name: string) {
  await user.type(within(dialog).getByLabelText(en.tokens.nameLabel), name)
  await user.click(within(dialog).getByRole('button', { name: en.tokens.create }))
}

describe('api tokens page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('listsNameScopeAndExpirationWithoutTheTokenValue', async () => {
    stubFetch(tokenRoutes())
    renderApp('/tokens')

    const nameCell = await screen.findByText('ci-reader', { selector: 'td' })
    const row = nameCell.closest('tr') as HTMLElement
    expect(within(row).getByText(en.tokens.scopes.read)).toBeInTheDocument()
    expect(within(row).getByText(/2027/)).toBeInTheDocument()
    expect(document.body.innerHTML).not.toContain('csd_')
  })

  it('filtersTokensByAnyDisplayedText', async () => {
    const writerToken = { ...EXISTING_TOKEN, token_id: 8, name: 'deploy-writer', scope: 'write' }
    stubFetch(tokenRoutes({ [`GET ${TOKENS_URL}`]: { status: 200, body: [EXISTING_TOKEN, writerToken] } }))
    const user = userEvent.setup()
    renderApp('/tokens')
    await screen.findByText('deploy-writer', { selector: 'td' })

    // The scope is matched on its translated label, as shown in the table.
    await user.type(screen.getByLabelText(en.clientFilter.label), 'and write')

    expect(screen.queryByText('ci-reader', { selector: 'td' })).toBeNull()
    expect(screen.getByText('deploy-writer', { selector: 'td' })).toBeInTheDocument()
    expect(await screen.findByText('1 of 2')).toBeInTheDocument()

    await user.clear(screen.getByLabelText(en.clientFilter.label))
    await user.type(screen.getByLabelText(en.clientFilter.label), 'no-such-token')

    expect(screen.getByText(en.clientFilter.noMatch)).toBeInTheDocument()
    expect(screen.queryByText(en.tokens.empty)).toBeNull()
  })

  it('showsTheTokenOnceThenRemovesItWhenTheDialogCloses', async () => {
    const fetchMock = stubFetch(
      tokenRoutes({
        [`POST ${TOKENS_URL}`]: { status: 201, body: { token_id: 8, name: 'deploy', scope: 'read', expires_at: '2027-01-01T10:00:00Z', token: FAKE_TOKEN } },
      }),
    )
    const user = userEvent.setup()
    const { queryClient } = renderApp('/tokens')

    const dialog = await openCreationDialog(user)
    await submitToken(user, dialog, 'deploy')

    expect(await within(dialog).findByText(FAKE_TOKEN)).toBeInTheDocument()
    expect(within(dialog).getByText(en.secret.warning)).toBeInTheDocument()
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', TOKENS_URL)[0].body))).toEqual({ name: 'deploy', scope: 'read', expires_in_days: 90 })
    const everythingStored = JSON.stringify([
      queryClient.getQueryCache().getAll().map((cachedQuery) => cachedQuery.state.data),
      { ...localStorage },
      { ...sessionStorage },
      window.location.href,
    ])
    expect(everythingStored).not.toContain(FAKE_TOKEN)

    await user.click(within(dialog).getByRole('button', { name: en.secret.done }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.body.innerHTML).not.toContain(FAKE_TOKEN)
    expect(requestsTo(fetchMock, 'GET', TOKENS_URL).length).toBeGreaterThanOrEqual(1)
    expect(fetchMock.mock.calls.every(([, init]) => !String((init as RequestInit | undefined)?.body ?? '').includes(FAKE_TOKEN))).toBe(true)
  })

  // The mutation result holds the plaintext token; TanStack keeps finished
  // mutations in its MutationCache for gcTime (5 minutes by default), so every
  // way of closing the dialog must leave no copy of it there.
  it.each([
    ['the done button', async (user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement) => user.click(within(dialog).getByRole('button', { name: en.secret.done }))],
    ['the escape key', async (user: ReturnType<typeof userEvent.setup>) => user.keyboard('{Escape}')],
  ])('leavesNoTokenInTheMutationCacheAfterClosingWith %s', async (_closingWay, closeDialog) => {
    stubFetch(
      tokenRoutes({
        [`POST ${TOKENS_URL}`]: { status: 201, body: { token_id: 8, name: 'deploy', scope: 'read', expires_at: '2027-01-01T10:00:00Z', token: FAKE_TOKEN } },
      }),
    )
    const user = userEvent.setup()
    const { queryClient } = renderApp('/tokens')
    const dialog = await openCreationDialog(user)
    await submitToken(user, dialog, 'deploy')
    await within(dialog).findByText(FAKE_TOKEN)

    await closeDialog(user, dialog)

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => {
      const cachedMutationResults = JSON.stringify(queryClient.getMutationCache().getAll().map((cachedMutation) => cachedMutation.state.data))
      expect(cachedMutationResults).not.toContain(FAKE_TOKEN)
    })
  })

  it('offersOnlyTheReadScopeToAReadOnlyAccount', async () => {
    stubFetch(tokenRoutes({}, READ_ONLY_SESSION))
    const user = userEvent.setup()
    renderApp('/tokens')

    const dialog = await openCreationDialog(user)

    const scopeSelect = within(dialog).getByLabelText(en.tokens.scopeLabel)
    const offeredScopes = within(scopeSelect).getAllByRole('option').map((option) => option.textContent)
    expect(offeredScopes).toEqual([en.tokens.scopes.read])
  })

  it('offersBothScopesToAnAdministrator', async () => {
    stubFetch(tokenRoutes())
    const user = userEvent.setup()
    renderApp('/tokens')

    const dialog = await openCreationDialog(user)

    const scopeSelect = within(dialog).getByLabelText(en.tokens.scopeLabel)
    const offeredScopes = within(scopeSelect).getAllByRole('option').map((option) => option.textContent)
    expect(offeredScopes).toEqual([en.tokens.scopes.read, en.tokens.scopes.write])
  })

  it('translatesScopeNotAllowed', async () => {
    stubFetch(tokenRoutes({ [`POST ${TOKENS_URL}`]: { status: 403, body: { error: 'scope_not_allowed' } } }))
    const user = userEvent.setup()
    renderApp('/tokens')

    const dialog = await openCreationDialog(user)
    await submitToken(user, dialog, 'deploy')

    expect(await within(dialog).findByText(en.errors.scope_not_allowed)).toBeInTheDocument()
  })

  it('translatesTokenNameTaken', async () => {
    stubFetch(tokenRoutes({ [`POST ${TOKENS_URL}`]: { status: 409, body: { error: 'token_name_taken' } } }))
    const user = userEvent.setup()
    renderApp('/tokens')

    const dialog = await openCreationDialog(user)
    await submitToken(user, dialog, 'ci-reader')

    expect(await within(dialog).findByText(en.errors.token_name_taken)).toBeInTheDocument()
  })

  it('revokesATokenAfterTypedConfirmation', async () => {
    const fetchMock = stubFetch(tokenRoutes({ [`DELETE ${TOKENS_URL}/7`]: { status: 200, body: { status: 'ok' } } }))
    const user = userEvent.setup()
    renderApp('/tokens')

    await user.click(await screen.findByRole('button', { name: 'Revoke ci-reader' }))
    const dialog = await screen.findByRole('dialog')
    const revokeButton = within(dialog).getByRole('button', { name: en.tokens.revoke })
    expect(revokeButton).toBeDisabled()
    await user.type(within(dialog).getByLabelText(/ci-reader/), 'ci-reader')
    await user.click(revokeButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', `${TOKENS_URL}/7`)).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'DELETE', `${TOKENS_URL}/7`)[0].body))).toEqual({ confirm: '7' })
  })
})
