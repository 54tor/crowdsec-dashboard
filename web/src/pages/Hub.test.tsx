import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import fr from '@/i18n/fr.json'
import { makeHealth, makeHubItem } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { INJECTED_IMAGE_SELECTOR, prepareEnglishApp, requestsTo, SESSION_OK, slowResponse } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

function hubRoutes(extraRoutes = {}) {
  const hubItems = [
    makeHubItem({ type: 'collections', name: 'crowdsecurity/linux' }),
    makeHubItem({ type: 'parsers', name: 'crowdsecurity/sshd-logs', description: 'ssh' }),
  ]
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/hub': { status: 200, body: hubItems },
    'GET /api/health': { status: 200, body: makeHealth() },
    ...extraRoutes,
  }
}

const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }
const HOSTILE_DESCRIPTION = '<img src=x onerror=alert(1)>'

// AppSec items come back from GET /api/hub with the cscli hub type names as `type`.
function appSecRoutes(extraRoutes = {}) {
  const hubItems = [
    makeHubItem({ type: 'collections', name: 'crowdsecurity/linux' }),
    makeHubItem({ type: 'appsec-rules', name: 'crowdsecurity/vpatch-env-access', description: HOSTILE_DESCRIPTION }),
    makeHubItem({ type: 'appsec-configs', name: 'crowdsecurity/appsec-default' }),
  ]
  return hubRoutes({ 'GET /api/hub': { status: 200, body: hubItems }, ...extraRoutes })
}

async function openInstallDialog(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: en.hub.install }))
  return screen.findByRole('dialog', { name: en.hub.installTitle })
}

describe('hub page', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('listsItemsAndFiltersByTypeAndName', async () => {
    stubFetch(hubRoutes())
    const user = userEvent.setup()
    renderApp('/hub')

    expect(await screen.findByText('crowdsecurity/linux', { selector: 'td' })).toBeInTheDocument()
    expect(screen.getByText('crowdsecurity/sshd-logs', { selector: 'td' })).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText(en.hub.filterType), 'parsers')
    expect(screen.queryByText('crowdsecurity/linux', { selector: 'td' })).not.toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText(en.hub.filterType), '')
    await user.type(screen.getByLabelText(en.clientFilter.label), 'LINUX')
    expect(screen.getByText('crowdsecurity/linux', { selector: 'td' })).toBeInTheDocument()
    expect(screen.queryByText('crowdsecurity/sshd-logs', { selector: 'td' })).not.toBeInTheDocument()
  })

  it('filtersHubItemsByNameOrType', async () => {
    stubFetch(hubRoutes())
    const user = userEvent.setup()
    renderApp('/hub')
    await screen.findByText('crowdsecurity/sshd-logs', { selector: 'td' })

    await user.type(screen.getByLabelText(en.clientFilter.label), 'PARSERS')

    expect(screen.queryByText('crowdsecurity/linux', { selector: 'td' })).toBeNull()
    expect(screen.getByText('crowdsecurity/sshd-logs', { selector: 'td' })).toBeInTheDocument()
    expect(await screen.findByText('1 of 2')).toBeInTheDocument()

    await user.clear(screen.getByLabelText(en.clientFilter.label))
    await user.type(screen.getByLabelText(en.clientFilter.label), 'no-such-item')

    expect(screen.getByText(en.clientFilter.noMatch)).toBeInTheDocument()
    expect(screen.queryByText(en.hub.noItems)).toBeNull()
  })

  // The status column printed the raw cscli word: it is now a status badge.
  it.each([
    { hubStatus: 'enabled', expectedVariant: 'nominal' },
    { hubStatus: 'tainted', expectedVariant: 'outline' },
  ])('statusColumnShowsABadge $hubStatus', async ({ hubStatus, expectedVariant }) => {
    stubFetch(hubRoutes({ 'GET /api/hub': { status: 200, body: [makeHubItem({ name: 'crowdsecurity/linux', status: hubStatus })] } }))
    renderApp('/hub')

    const hubRow = (await screen.findByText('crowdsecurity/linux', { selector: 'td' })).closest('tr') as HTMLElement
    const statusBadge = within(hubRow).getByText(hubStatus)

    expect(statusBadge).toHaveAttribute('data-slot', 'badge')
    expect(statusBadge).toHaveAttribute('data-variant', expectedVariant)
  })

  // On a phone the table scrolls in its region: short columns must not be
  // squeezed to two or three characters per line.
  it('shortColumnsDoNotWrap', async () => {
    stubFetch(hubRoutes())
    renderApp('/hub')

    const nameCell = await screen.findByText('crowdsecurity/linux', { selector: 'td' })

    expect(nameCell).toHaveClass('whitespace-nowrap')
  })

  it('reloadBannerAppearsAfterHubUpgrade', async () => {
    const fetchMock = stubFetch(hubRoutes({ 'POST /api/hub/upgrade': { status: 200, body: { status: 'upgraded' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    expect(screen.queryByText(en.hub.reloadRequired)).not.toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: en.hub.upgrade }))

    expect(await screen.findByText(en.hub.reloadRequired)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.hub.reload })).toBeInTheDocument()
    expect(requestsTo(fetchMock, 'POST', '/api/hub/upgrade')).toHaveLength(1)
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/hub').length).toBeGreaterThan(1))
  })

  it('reloadBannerAppearsAfterUpdateAndDisappearsAfterReload', async () => {
    const fetchMock = stubFetch(
      hubRoutes({
        'POST /api/hub/update': { status: 200, body: { status: 'updated' } },
        'POST /api/crowdsec/reload': { status: 200, body: { status: 'reload_requested' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: en.hub.update }))
    await user.click(await screen.findByRole('button', { name: en.hub.reload }))

    await waitFor(() => expect(screen.queryByText(en.hub.reloadRequired)).not.toBeInTheDocument())
    expect(requestsTo(fetchMock, 'POST', '/api/crowdsec/reload')).toHaveLength(1)
  })

  it('reloadFailureKeepsBannerAndShowsTranslatedError', async () => {
    stubFetch(
      hubRoutes({
        'POST /api/hub/update': { status: 200, body: { status: 'updated' } },
        'POST /api/crowdsec/reload': { status: 502, body: { error: 'cscli_failed' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: en.hub.update }))
    await user.click(await screen.findByRole('button', { name: en.hub.reload }))

    expect(await screen.findByRole('alert')).toHaveTextContent(en.errors.cscli_failed)
    expect(screen.getByText(en.hub.reloadRequired)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.hub.reload })).toBeEnabled()
  })

  it('reloadBannerSurvivesNavigationAwayAndBack', async () => {
    stubFetch(hubRoutes({ 'POST /api/hub/update': { status: 200, body: { status: 'updated' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: en.hub.update }))
    await screen.findByText(en.hub.reloadRequired)
    await user.click(screen.getByRole('link', { name: en.nav.health }))
    await user.click(await screen.findByRole('link', { name: en.nav.hub }))

    expect(await screen.findByText(en.hub.reloadRequired)).toBeInTheDocument()
  })

  it('timeoutOnUpgradeShowsTranslatedMessageRefreshButtonAndReloadBanner', async () => {
    const fetchMock = stubFetch(hubRoutes({ 'POST /api/hub/upgrade': { status: 504, body: { error: 'cscli_timeout' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: en.hub.upgrade }))

    expect(await screen.findByText(en.errors.cscli_timeout)).toBeInTheDocument()
    expect(screen.getByText(en.hub.reloadRequired)).toBeInTheDocument()
    const hubFetchesBefore = requestsTo(fetchMock, 'GET', '/api/hub').length
    await user.click(screen.getByRole('button', { name: en.errors.refresh }))
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/hub').length).toBeGreaterThan(hubFetchesBefore))
    expect(screen.getByRole('button', { name: en.hub.upgrade })).toBeEnabled()
  })

  it('reloadBannerSurvivesRefreshAfterTimeoutAndDisappearsOnlyAfterSuccessfulReload', async () => {
    const fetchMock = stubFetch(
      hubRoutes({
        'POST /api/hub/collections': { status: 200, body: { status: 'installed' } },
        'POST /api/hub/upgrade': { status: 504, body: { error: 'cscli_timeout' } },
        'POST /api/crowdsec/reload': { status: 200, body: { status: 'reload_requested' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: en.hub.install }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(en.hub.installName), 'crowdsecurity/nginx')
    await user.click(within(dialog).getByRole('button', { name: en.hub.installSubmit }))
    await screen.findByText(en.hub.reloadRequired)

    await user.click(screen.getByRole('button', { name: en.hub.upgrade }))
    const hubFetchesBefore = requestsTo(fetchMock, 'GET', '/api/hub').length
    await user.click(await screen.findByRole('button', { name: en.errors.refresh }))
    await waitFor(() => expect(requestsTo(fetchMock, 'GET', '/api/hub').length).toBeGreaterThan(hubFetchesBefore))
    expect(screen.getByText(en.hub.reloadRequired)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: en.hub.reload }))
    await waitFor(() => expect(screen.queryByText(en.hub.reloadRequired)).not.toBeInTheDocument())
  })

  it('timeoutOnRemoveRaisesReloadBanner', async () => {
    stubFetch(
      hubRoutes({
        'POST /api/hub/collections': { status: 504, body: { error: 'cscli_timeout' } },
        'DELETE /api/hub/collections/crowdsecurity/linux': { status: 504, body: { error: 'cscli_timeout' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: 'Remove crowdsecurity/linux' }))
    const removeDialog = await screen.findByRole('dialog')
    await user.type(within(removeDialog).getByLabelText('Type crowdsecurity/linux to confirm'), 'crowdsecurity/linux')
    await user.click(within(removeDialog).getByRole('button', { name: en.hub.remove }))
    expect(await within(removeDialog).findByText(en.errors.cscli_timeout)).toBeInTheDocument()
    expect(screen.getAllByText(en.hub.reloadRequired).length).toBeGreaterThan(0)
  })

  it('timeoutOnInstallRaisesReloadBanner', async () => {
    stubFetch(hubRoutes({ 'POST /api/hub/collections': { status: 504, body: { error: 'cscli_timeout' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: en.hub.install }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(en.hub.installName), 'crowdsecurity/nginx')
    await user.click(within(dialog).getByRole('button', { name: en.hub.installSubmit }))

    expect(await within(dialog).findByText(en.errors.cscli_timeout)).toBeInTheDocument()
    expect(screen.getAllByText(en.hub.reloadRequired).length).toBeGreaterThan(0)
  })

  it('showsSpinnerNoteAndBlocksDoubleSubmitWhileUpgrading', async () => {
    const fetchMock = stubFetch(hubRoutes())
    const defaultImplementation = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (input, init) =>
      init?.method === 'POST' ? slowResponse(200, { status: 'upgraded' }, 50) : defaultImplementation(input, init),
    )
    const user = userEvent.setup()
    renderApp('/hub')

    expect(await screen.findByText(en.hub.slowNote)).toBeInTheDocument()
    await user.dblClick(screen.getByRole('button', { name: en.hub.upgrade }))

    expect(await screen.findByRole('button', { name: new RegExp(en.dialog.working) })).toBeDisabled()
    expect(screen.getByRole('button', { name: en.hub.update })).toBeDisabled()
    await screen.findByText(en.hub.reloadRequired)
    expect(requestsTo(fetchMock, 'POST', '/api/hub/upgrade')).toHaveLength(1)
  })

  it('installCollectionPostsNameAndRaisesBanner', async () => {
    const fetchMock = stubFetch(hubRoutes({ 'POST /api/hub/collections': { status: 200, body: { status: 'installed' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: en.hub.install }))
    const dialog = await screen.findByRole('dialog', { name: en.hub.installTitle })
    await user.type(within(dialog).getByLabelText(en.hub.installName), 'crowdsecurity/nginx')
    await user.click(within(dialog).getByRole('button', { name: en.hub.installSubmit }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/hub/collections')[0].body))).toEqual({ name: 'crowdsecurity/nginx' })
    expect(await screen.findByText(en.hub.reloadRequired)).toBeInTheDocument()
  })

  it('installRejectsInvalidNameInlineAndShowsApiErrorTranslated', async () => {
    stubFetch(hubRoutes({ 'POST /api/hub/collections': { status: 502, body: { error: 'cscli_failed' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: en.hub.install }))
    const dialog = await screen.findByRole('dialog')
    const nameInput = within(dialog).getByLabelText(en.hub.installName)
    await user.type(nameInput, '../etc')
    expect(within(dialog).getByRole('button', { name: en.hub.installSubmit })).toBeDisabled()

    await user.clear(nameInput)
    await user.type(nameInput, 'crowdsecurity/nginx')
    await user.click(within(dialog).getByRole('button', { name: en.hub.installSubmit }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(en.errors.cscli_failed)
    expect(within(dialog).getByRole('button', { name: en.hub.installSubmit })).toBeEnabled()
  })

  it('removeCollectionEncodesEachSegmentAndKeepsSlash', async () => {
    const fetchMock = stubFetch(hubRoutes({ 'DELETE /api/hub/collections/crowdsecurity/linux': { status: 200, body: { status: 'removed' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    expect(await screen.findAllByRole('button', { name: /^Remove / })).toHaveLength(1)
    await user.click(screen.getByRole('button', { name: 'Remove crowdsecurity/linux' }))
    const dialog = await screen.findByRole('dialog')
    const submitButton = within(dialog).getByRole('button', { name: en.hub.remove })
    expect(submitButton).toBeDisabled()
    await user.type(within(dialog).getByLabelText('Type crowdsecurity/linux to confirm'), 'crowdsecurity/linux')
    await user.click(submitButton)

    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', '/api/hub/collections/crowdsecurity/linux')).toHaveLength(1))
    expect(requestsTo(fetchMock, 'DELETE', '/api/hub/collections/crowdsecurity/linux')[0].body).toBe('{"confirm":"crowdsecurity/linux"}')
    expect(await screen.findByText(en.hub.reloadRequired)).toBeInTheDocument()
  })
  it('offersRemovalOfAnAppSecRule', async () => {
    const fetchMock = stubFetch(
      appSecRoutes({ 'DELETE /api/hub/appsec-rules/crowdsecurity/vpatch-env-access': { status: 200, body: { status: 'removed' } } }),
    )
    const user = userEvent.setup()
    const { container } = renderApp('/hub')

    // The hostile description must stay a text node, never parsed as markup.
    expect(await screen.findByText(HOSTILE_DESCRIPTION, { selector: 'td' })).toBeInTheDocument()
    expect(container.querySelector(INJECTED_IMAGE_SELECTOR)).toBeNull()
    expect(screen.getByRole('button', { name: 'Remove crowdsecurity/appsec-default' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Remove crowdsecurity/vpatch-env-access' }))
    const removeDialog = await screen.findByRole('dialog')
    await user.type(within(removeDialog).getByLabelText('Type crowdsecurity/vpatch-env-access to confirm'), 'crowdsecurity/vpatch-env-access')
    await user.click(within(removeDialog).getByRole('button', { name: en.hub.remove }))

    const removalPath = '/api/hub/appsec-rules/crowdsecurity/vpatch-env-access'
    await waitFor(() => expect(requestsTo(fetchMock, 'DELETE', removalPath)).toHaveLength(1))
    expect(requestsTo(fetchMock, 'DELETE', removalPath)[0].body).toBe('{"confirm":"crowdsecurity/vpatch-env-access"}')
    expect(await screen.findByText(en.hub.reloadRequired)).toBeInTheDocument()
  })

  // Every removable kind can carry AppSec rules (a collection may bundle
  // them): the dialog warns before the retyped name unlocks the removal.
  it('warnsAboutTheAppSecAcquisitionBeforeEveryRemoval', async () => {
    stubFetch(appSecRoutes())
    const user = userEvent.setup()
    renderApp('/hub')

    for (const itemName of ['crowdsecurity/linux', 'crowdsecurity/vpatch-env-access', 'crowdsecurity/appsec-default']) {
      await user.click(await screen.findByRole('button', { name: `Remove ${itemName}` }))
      const removeDialog = await screen.findByRole('dialog')
      expect(within(removeDialog).getByText(en.hub.removeAppSecWarning, { exact: false })).toBeInTheDocument()
      const submitButton = within(removeDialog).getByRole('button', { name: en.hub.remove })
      expect(submitButton).toBeDisabled()
      await user.type(within(removeDialog).getByLabelText(`Type ${itemName} to confirm`), itemName)
      expect(submitButton).toBeEnabled()
      await user.click(within(removeDialog).getByRole('button', { name: en.dialog.cancel }))
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    }
  })

  it('translatesARemovalThatDidNotTakeEffect', async () => {
    stubFetch(appSecRoutes({ 'DELETE /api/hub/appsec-rules/crowdsecurity/vpatch-env-access': { status: 409, body: { error: 'hub_item_still_installed' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    await user.click(await screen.findByRole('button', { name: 'Remove crowdsecurity/vpatch-env-access' }))
    const removeDialog = await screen.findByRole('dialog')
    await user.type(within(removeDialog).getByLabelText('Type crowdsecurity/vpatch-env-access to confirm'), 'crowdsecurity/vpatch-env-access')
    await user.click(within(removeDialog).getByRole('button', { name: en.hub.remove }))

    expect(await within(removeDialog).findByText(en.errors.hub_item_still_installed)).toBeInTheDocument()
  })

  it('installsAnAppSecConfigurationWithTheRightKind', async () => {
    const fetchMock = stubFetch(appSecRoutes({ 'POST /api/hub/appsec-configs': { status: 200, body: { status: 'installed' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    const dialog = await openInstallDialog(user)
    await user.selectOptions(within(dialog).getByLabelText(en.hub.installKind), 'appsec-configs')
    await user.type(within(dialog).getByLabelText(en.hub.installName), 'crowdsecurity/appsec-default')
    await user.click(within(dialog).getByRole('button', { name: en.hub.installSubmit }))

    await waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/hub/appsec-configs')).toHaveLength(1))
    expect(JSON.parse(String(requestsTo(fetchMock, 'POST', '/api/hub/appsec-configs')[0].body))).toEqual({ name: 'crowdsecurity/appsec-default' })
    expect(requestsTo(fetchMock, 'POST', '/api/hub/collections')).toHaveLength(0)
  })

  it('hidesActionsForReadOnly', async () => {
    stubFetch(appSecRoutes({ 'GET /api/auth/me': READ_ONLY_SESSION }))
    renderApp('/hub')

    expect(await screen.findByText('crowdsecurity/vpatch-env-access', { selector: 'td' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.hub.install })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: en.hub.update })).not.toBeInTheDocument()
    expect(screen.queryAllByRole('button', { name: /^Remove / })).toHaveLength(0)
  })

  it('showsAppSecActivationNote', async () => {
    stubFetch(appSecRoutes())
    const user = userEvent.setup()
    renderApp('/hub')

    const dialog = await openInstallDialog(user)
    expect(within(dialog).getByText(en.hub.appsecSuggestions)).toBeInTheDocument()
    expect(within(dialog).getByText(en.hub.appsecActivationNote)).toBeInTheDocument()
    expect(en.hub.appsecActivationNote).toContain('docs/operations.md')
    expect(en.hub.appsecSuggestions).toContain('crowdsecurity/appsec-virtual-patching')
    expect(en.hub.appsecSuggestions).toContain('crowdsecurity/appsec-generic-rules')
  })

  // The default appsec configuration loads the vpatch rules too: both
  // collections are named, generic rules first, in each language.
  it('activationNoteNamesBothAppSecCollectionsInOrder', () => {
    for (const activationNote of [en.hub.appsecActivationNote, fr.hub.appsecActivationNote]) {
      const genericRulesPosition = activationNote.indexOf('crowdsecurity/appsec-generic-rules')
      const virtualPatchingPosition = activationNote.indexOf('crowdsecurity/appsec-virtual-patching')
      expect(genericRulesPosition).toBeGreaterThanOrEqual(0)
      expect(virtualPatchingPosition).toBeGreaterThan(genericRulesPosition)
    }
  })

  it('marksReloadRequiredAfterInstall', async () => {
    stubFetch(appSecRoutes({ 'POST /api/hub/appsec-rules': { status: 200, body: { status: 'installed' } } }))
    const user = userEvent.setup()
    renderApp('/hub')

    const dialog = await openInstallDialog(user)
    await user.selectOptions(within(dialog).getByLabelText(en.hub.installKind), 'appsec-rules')
    await user.type(within(dialog).getByLabelText(en.hub.installName), 'crowdsecurity/vpatch-env-access')
    await user.click(within(dialog).getByRole('button', { name: en.hub.installSubmit }))

    expect(await screen.findByText(en.hub.reloadRequired)).toBeInTheDocument()
  })
})
