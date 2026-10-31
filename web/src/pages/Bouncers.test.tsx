import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeBouncer, makeHealth } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const FAKE_KEY = 'fake-bouncer-key-for-tests'

function bouncerRoutes(extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/health': { status: 200, body: makeHealth({ bouncers: [makeBouncer({ name: 'firewall-one' })] }) },
    ...extraRoutes,
  }
}

async function createBouncerNamed(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(await screen.findByRole('button', { name: en.bouncers.add }))
  const dialog = await screen.findByRole('dialog', { name: en.bouncers.addTitle })
  await user.type(within(dialog).getByLabelText(en.bouncers.nameLabel), name)
  await user.click(within(dialog).getByRole('button', { name: en.secret.create }))
  return dialog
}

function everythingStoredInBrowser(queryClient: { getQueryCache: () => { getAll: () => { state: { data: unknown } }[] }; getMutationCache: () => { getAll: () => unknown[] } }): string {
  const cachedQueries = queryClient.getQueryCache().getAll().map((cachedQuery) => cachedQuery.state.data)
  const cachedMutations = queryClient.getMutationCache().getAll()
  return JSON.stringify([cachedQueries, cachedMutations, { ...localStorage }, { ...sessionStorage }, window.location.href])
}

describe('bouncers page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('listsBouncersFromHealth', async () => {
    stubFetch(bouncerRoutes())
    renderApp('/bouncers')

    expect(await screen.findByText('firewall-one', { selector: 'td' })).toBeInTheDocument()
  })

  it('bouncerKeyIsClearedWhenDialogCloses', async () => {
    const fetchMock = stubFetch(bouncerRoutes({ 'POST /api/bouncers': { status: 200, body: { name: 'new-one', key: FAKE_KEY } } }))
    const user = userEvent.setup()
    const { queryClient } = renderApp('/bouncers')

    const dialog = await createBouncerNamed(user, 'new-one')

    expect(await within(dialog).findByText(FAKE_KEY)).toBeInTheDocument()
    expect(within(dialog).getByText(en.secret.warning)).toBeInTheDocument()
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/bouncers')[0].body))).toEqual({ name: 'new-one' })
    expect(everythingStoredInBrowser(queryClient)).not.toContain(FAKE_KEY)

    await user.click(within(dialog).getByRole('button', { name: en.secret.done }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.body.innerHTML).not.toContain(FAKE_KEY)
    expect(everythingStoredInBrowser(queryClient)).not.toContain(FAKE_KEY)
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/health').length).toBeGreaterThan(1))
  })

  it('keyIsClearedWhenDialogIsClosedWithEscapeAndReopenedEmpty', async () => {
    stubFetch(bouncerRoutes({ 'POST /api/bouncers': { status: 200, body: { name: 'new-one', key: FAKE_KEY } } }))
    const user = userEvent.setup()
    renderApp('/bouncers')

    const dialog = await createBouncerNamed(user, 'new-one')
    await within(dialog).findByText(FAKE_KEY)
    await user.keyboard('{Escape}')

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.body.innerHTML).not.toContain(FAKE_KEY)
    await user.click(screen.getByRole('button', { name: en.bouncers.add }))
    expect(screen.queryByText(FAKE_KEY)).not.toBeInTheDocument()
  })

  it('copyButtonCopiesKeyAndAnnouncesSuccess', async () => {
    stubFetch(bouncerRoutes({ 'POST /api/bouncers': { status: 200, body: { name: 'new-one', key: FAKE_KEY } } }))
    const user = userEvent.setup()
    renderApp('/bouncers')

    const dialog = await createBouncerNamed(user, 'new-one')
    await user.click(await within(dialog).findByRole('button', { name: en.secret.copy }))

    expect(await within(dialog).findByText(en.secret.copied)).toBeInTheDocument()
    expect(await navigator.clipboard.readText()).toBe(FAKE_KEY)
    expect(within(dialog).getByText(en.secret.copied).closest('[aria-live]')).not.toBeNull()
  })

  it('createErrorIsTranslatedAndDialogIsNotStuckPending', async () => {
    stubFetch(bouncerRoutes({ 'POST /api/bouncers': { status: 502, body: { error: 'cscli_failed' } } }))
    const user = userEvent.setup()
    renderApp('/bouncers')

    const dialog = await createBouncerNamed(user, 'new-one')

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(en.errors.cscli_failed)
    expect(within(dialog).getByRole('button', { name: en.secret.create })).toBeEnabled()
  })

  it('rejectsInvalidNameInlineWithoutRequest', async () => {
    const fetchMock = stubFetch(bouncerRoutes())
    const user = userEvent.setup()
    renderApp('/bouncers')

    await user.click(await screen.findByRole('button', { name: en.bouncers.add }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(en.bouncers.nameLabel), 'bad name')

    expect(within(dialog).getByRole('button', { name: en.secret.create })).toBeDisabled()
    expect(within(dialog).getByLabelText(en.bouncers.nameLabel)).toHaveAccessibleDescription(en.errors.invalid_name)
    expect(requestsTo(fetchMock, 'POST', '/api/bouncers')).toHaveLength(0)
  })

  it('deleteBouncerSendsConfirmWithNameOnly', async () => {
    const fetchMock = stubFetch(bouncerRoutes({ 'DELETE /api/bouncers/firewall-one': { status: 200, body: { status: 'deleted' } } }))
    const user = userEvent.setup()
    renderApp('/bouncers')

    await user.click(await screen.findByRole('button', { name: 'Delete firewall-one' }))
    const dialog = await screen.findByRole('dialog')
    const submitButton = within(dialog).getByRole('button', { name: en.common.delete })
    expect(submitButton).toBeDisabled()
    await user.type(within(dialog).getByLabelText('Type firewall-one to confirm'), 'firewall-one')
    await user.click(submitButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/bouncers/firewall-one')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'DELETE', '/api/bouncers/firewall-one')[0].body).toBe('{"confirm":"firewall-one"}')
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/health').length).toBeGreaterThan(1))
  })
})
