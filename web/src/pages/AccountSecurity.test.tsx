import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { setLanguage } from '@/i18n'
import { stubFetch, type RouteTable } from '@/test/fetchStub'
import { INJECTED_IMAGE_SELECTOR, prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const RULES_URL = '/api/account/access-rules'

const LIST_WITH_RULES = {
  status: 200,
  body: {
    rules: [
      { id: 1, kind: 'ip', value: '203.0.113.0/24' },
      { id: 2, kind: 'country', value: 'FR' },
    ],
    client_ip: '203.0.113.7',
    client_country: 'FR',
  },
}

const EMPTY_LIST = { status: 200, body: { rules: [], client_ip: '203.0.113.7', client_country: null } }

function accessRoutes(listResponse: RouteTable[string], extraRoutes: RouteTable = {}): RouteTable {
  return { 'GET /api/auth/me': SESSION_OK, [`GET ${RULES_URL}`]: listResponse, ...extraRoutes }
}

async function addRule(user: ReturnType<typeof userEvent.setup>, kindLabel: string, value: string) {
  await user.selectOptions(await screen.findByLabelText(en.accountSecurity.kindLabel), kindLabel)
  await user.type(screen.getByLabelText(en.accountSecurity.valueLabel), value)
  await user.click(screen.getByRole('button', { name: en.accountSecurity.add }))
}

describe('account security page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('showsTheClientAddressAndTheRulesAsATable', async () => {
    stubFetch(accessRoutes(LIST_WITH_RULES))
    renderApp('/account/security')

    const table = await screen.findByRole('table', { name: en.accountSecurity.tableCaption })
    expect(within(table).getByText('203.0.113.0/24')).toBeInTheDocument()
    expect(within(table).getByText(/France/)).toBeInTheDocument()
    expect(screen.getByText(/203\.0\.113\.7/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete 203.0.113.0/24' })).toBeInTheDocument()
  })

  it('explainsThatNoRuleAllowsEverythingWhenTheListIsEmpty', async () => {
    stubFetch(accessRoutes(EMPTY_LIST))
    renderApp('/account/security')

    expect(await screen.findByText(en.accountSecurity.emptyAllowsAll)).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.getByText(en.accountSecurity.explanation)).toBeInTheDocument()
  })

  it('addsAnIpRuleAndRefetchesTheList', async () => {
    let created = false
    const fetchMock = stubFetch(
      accessRoutes(() => (created ? LIST_WITH_RULES : EMPTY_LIST), {
        [`POST ${RULES_URL}`]: () => {
          created = true
          return { status: 201, body: { id: 1, kind: 'ip', value: '203.0.113.0/24' } }
        },
      }),
    )
    const user = userEvent.setup()
    renderApp('/account/security')

    await addRule(user, en.accountSecurity.kinds.ip, ' 203.0.113.0/24 ')

    expect(await screen.findByText('203.0.113.0/24')).toBeInTheDocument()
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', RULES_URL)[0].body))).toEqual({ kind: 'ip', value: '203.0.113.0/24' })
    expect(requestsTo(fetchMock, 'GET', RULES_URL).length).toBeGreaterThan(1)
    expect(screen.getByLabelText(en.accountSecurity.valueLabel)).toHaveValue('')
    expect(screen.getByLabelText(en.accountSecurity.valueLabel)).toHaveFocus()
  })

  it('uppercasesACountryCodeBeforeSending', async () => {
    const fetchMock = stubFetch(accessRoutes(EMPTY_LIST, { [`POST ${RULES_URL}`]: { status: 201, body: { id: 3, kind: 'country', value: 'DE' } } }))
    const user = userEvent.setup()
    renderApp('/account/security')

    await addRule(user, en.accountSecurity.kinds.country, 'de')

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', RULES_URL)).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', RULES_URL)[0].body))).toEqual({ kind: 'country', value: 'DE' })
  })

  it.each([
    ['invalid_access_rule', 400],
    ['prefix_too_broad', 400],
    ['access_rule_exists', 409],
    ['would_lock_out_current_client', 409],
    ['geolocation_unavailable', 409],
    ['database_unavailable', 503],
  ])('translatesTheErrorCode_%s', async (errorCode, status) => {
    stubFetch(accessRoutes(EMPTY_LIST, { [`POST ${RULES_URL}`]: { status, body: { error: errorCode } } }))
    const user = userEvent.setup()
    renderApp('/account/security')

    await addRule(user, en.accountSecurity.kinds.ip, '198.51.100.0/24')

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(en.errors[errorCode as keyof typeof en.errors])
    expect(alert).toHaveFocus()
    expect(screen.queryByText(en.errors.unknown)).not.toBeInTheDocument()
  })

  it('deletesARuleAfterConfirmationAndRefetches', async () => {
    let deleted = false
    const fetchMock = stubFetch(
      accessRoutes(() => (deleted ? EMPTY_LIST : LIST_WITH_RULES), {
        [`DELETE ${RULES_URL}/1`]: () => {
          deleted = true
          return { status: 204 }
        },
      }),
    )
    const user = userEvent.setup()
    renderApp('/account/security')

    await user.click(await screen.findByRole('button', { name: 'Delete 203.0.113.0/24' }))
    const dialog = await screen.findByRole('dialog')
    expect(requestsTo(fetchMock, 'DELETE', `${RULES_URL}/1`)).toHaveLength(0)
    await user.type(within(dialog).getByLabelText(/203\.0\.113\.0\/24/), '203.0.113.0/24')
    await user.click(within(dialog).getByRole('button', { name: en.common.delete }))

    expect(await screen.findByText(en.accountSecurity.emptyAllowsAll)).toBeInTheDocument()
    expect(requestsTo(fetchMock, 'DELETE', `${RULES_URL}/1`)).toHaveLength(1)
  })

  it('cancellingTheConfirmationDeletesNothing', async () => {
    const fetchMock = stubFetch(accessRoutes(LIST_WITH_RULES))
    const user = userEvent.setup()
    renderApp('/account/security')

    await user.click(await screen.findByRole('button', { name: 'Delete 203.0.113.0/24' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: en.dialog.cancel }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(requestsTo(fetchMock, 'DELETE', `${RULES_URL}/1`)).toHaveLength(0)
    expect(screen.getByText('203.0.113.0/24')).toBeInTheDocument()
  })

  it('translatesALockOutRefusalOnDelete', async () => {
    stubFetch(accessRoutes(LIST_WITH_RULES, { [`DELETE ${RULES_URL}/1`]: { status: 409, body: { error: 'would_lock_out_current_client' } } }))
    const user = userEvent.setup()
    renderApp('/account/security')

    await user.click(await screen.findByRole('button', { name: 'Delete 203.0.113.0/24' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(/203\.0\.113\.0\/24/), '203.0.113.0/24')
    await user.click(within(dialog).getByRole('button', { name: en.common.delete }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(en.errors.would_lock_out_current_client)
  })

  it('rendersRuleValuesContainingHtmlAsPlainText', async () => {
    const hostile = '<img src=x onerror=alert(1)>'
    stubFetch(accessRoutes({ status: 200, body: { rules: [{ id: 9, kind: 'ip', value: hostile }], client_ip: '<b>x</b>', client_country: '<i>y</i>' } }))
    const { container } = renderApp('/account/security')

    expect(await screen.findByText(hostile)).toBeInTheDocument()
    expect(container.querySelector(INJECTED_IMAGE_SELECTOR)).toBeNull()
    expect(container.querySelector('b, i')).toBeNull()
  })

  it('redirectsToLoginWhenTheSessionExpired', async () => {
    stubFetch({ 'GET /api/auth/me': SESSION_OK, [`GET ${RULES_URL}`]: { status: 401, body: { error: 'unauthenticated' } } })
    renderApp('/account/security')

    expect(await screen.findByRole('heading', { name: en.login.title })).toBeInTheDocument()
  })

  it('keepsTheSessionOnDatabaseUnavailable', async () => {
    stubFetch(accessRoutes({ status: 503, body: { error: 'database_unavailable' } }))
    renderApp('/account/security')

    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.database_unavailable)
    expect(screen.queryByRole('heading', { name: en.login.title })).not.toBeInTheDocument()
  })

  it('writesNothingToBrowserStorageNorConsole', async () => {
    const consoleSpies = (['log', 'warn', 'error'] as const).map((method) => vi.spyOn(console, method))
    stubFetch(accessRoutes(LIST_WITH_RULES))
    renderApp('/account/security')
    await screen.findByRole('table')

    expect(JSON.stringify({ ...localStorage })).not.toContain('203.0.113')
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('203.0.113')
    consoleSpies.forEach((spy) => expect(spy).not.toHaveBeenCalled())
  })

  it('linksTheAccountNameToThePage', async () => {
    stubFetch({ 'GET /api/auth/me': { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }, 'GET /api/alerts': { status: 200, body: { items: [], total: 0 } }, [`GET ${RULES_URL}`]: EMPTY_LIST })
    renderApp('/account/security')

    expect(await screen.findByRole('link', { name: 'alice' })).toHaveAttribute('href', '/account/security')
  })

  it('explainsTheGenericConsequenceWhenSeveralRulesExist', async () => {
    stubFetch(accessRoutes(LIST_WITH_RULES))
    const user = userEvent.setup()
    renderApp('/account/security')

    await user.click(await screen.findByRole('button', { name: 'Delete 203.0.113.0/24' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(en.accountSecurity.deleteDescription)).toBeInTheDocument()
    expect(within(dialog).queryByText(en.accountSecurity.deleteLastDescription)).not.toBeInTheDocument()
  })

  it('explainsThatDeletingTheLastRuleTurnsTheAllowlistOff', async () => {
    stubFetch(accessRoutes({ status: 200, body: { rules: [{ id: 1, kind: 'ip', value: '203.0.113.0/24' }], client_ip: '203.0.113.7', client_country: null } }))
    const user = userEvent.setup()
    renderApp('/account/security')

    await user.click(await screen.findByRole('button', { name: 'Delete 203.0.113.0/24' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(en.accountSecurity.deleteLastDescription)).toBeInTheDocument()
    expect(within(dialog).queryByText(en.accountSecurity.deleteDescription)).not.toBeInTheDocument()
  })

  it('explainsTheLastRuleDeletionInFrench', async () => {
    await setLanguage('fr')
    stubFetch(accessRoutes({ status: 200, body: { rules: [{ id: 1, kind: 'ip', value: '203.0.113.0/24' }], client_ip: '203.0.113.7', client_country: null } }))
    const user = userEvent.setup()
    renderApp('/account/security')

    await user.click(await screen.findByRole('button', { name: 'Supprimer 203.0.113.0/24' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(fr.accountSecurity.deleteLastDescription)).toBeInTheDocument()
  })
})
