import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { ENGINE_NAMES_WITH_SIDECARS, selectTargetEngine } from '@/test/engineTargetHarness'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp, requestsTo, SESSION_OK } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

const READ_ONLY_SESSION = { status: 200, body: { status: 'ok', account_name: 'bob', account_role: 'read_only' } }
const FILE_NAME = 'acquis.d/nginx.yaml'
const FILE_URL = `/api/config/edit/${FILE_NAME}`
const ORIGINAL_CONTENT = 'source: file\nfilenames:\n  - /var/log/nginx/*.log\n'
const FILE_DIGEST = 'digest-1'

function editableFile(overrides = {}) {
  return {
    status: 200,
    body: { name: FILE_NAME, exists: true, read_only: false, writable: true, digest: FILE_DIGEST, content: ORIGINAL_CONTENT, ...overrides },
  }
}

function advancedRoutes(extraRoutes = {}) {
  return {
    'GET /api/auth/me': SESSION_OK,
    'GET /api/engines/names': ENGINE_NAMES_WITH_SIDECARS,
    'GET /api/config/files': { status: 200, body: { files: ['config.yaml', FILE_NAME] } },
    [`GET ${FILE_URL}`]: editableFile(),
    [`GET /api/config/backups/${FILE_NAME}`]: { status: 200, body: { items: [] } },
    ...extraRoutes,
  }
}

async function openEditor(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('checkbox', { name: en.configEdit.advancedMode }))
  await user.click(await screen.findByRole('button', { name: FILE_NAME }))
  return screen.findByLabelText(`Editor for ${FILE_NAME}`)
}

async function appendToEditor(user: ReturnType<typeof userEvent.setup>, editor: HTMLElement, addedText: string) {
  await user.click(editor)
  await user.type(editor, addedText)
}

describe('config page advanced mode', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  it('hidesAdvancedSwitchForReadOnlyAccount', async () => {
    stubFetch({ ...advancedRoutes(), 'GET /api/auth/me': READ_ONLY_SESSION })
    renderApp('/config')

    // A read-only account is redirected away from /config altogether: the switch cannot be reached.
    expect(await screen.findByRole('heading', { name: en.alerts.title })).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: en.configEdit.advancedMode })).not.toBeInTheDocument()
  })

  it('showsRawEditorWhenAdvancedModeIsOn', async () => {
    stubFetch(advancedRoutes())
    const user = userEvent.setup()
    renderApp('/config')

    const editor = await openEditor(user)

    expect(editor).toHaveValue(ORIGINAL_CONTENT)
    expect(editor).toHaveAttribute('spellcheck', 'false')
    expect(screen.queryByLabelText(`Content of ${FILE_NAME}`)).not.toBeInTheDocument()
  })

  it('keepsTheViewerWhenAdvancedModeIsOff', async () => {
    stubFetch(advancedRoutes({ [`GET /api/config/files/${FILE_NAME}`]: { status: 200, body: { name: FILE_NAME, content: ORIGINAL_CONTENT } } }))
    const user = userEvent.setup()
    renderApp('/config')

    await user.click(await screen.findByRole('button', { name: FILE_NAME }))

    expect((await screen.findByLabelText(`Content of ${FILE_NAME}`)).textContent).toBe(ORIGINAL_CONTENT)
    expect(screen.queryByRole('button', { name: en.configEdit.validate })).not.toBeInTheDocument()
  })

  it('stillRendersWhenLocalStorageIsUnavailable', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError')
    })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError')
    })
    stubFetch(advancedRoutes())
    const user = userEvent.setup()
    renderApp('/config')

    const editor = await openEditor(user)

    expect(editor).toBeInTheDocument()
    vi.restoreAllMocks()
  })

  it('saveStaysDisabledUntilValidationHasNoError', async () => {
    stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': { status: 200, body: { issues: [] } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)
    const saveButton = screen.getByRole('button', { name: en.configEdit.save })

    // Never validated: saving is not allowed even though the text is untouched.
    expect(saveButton).toBeDisabled()

    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))

    expect(await screen.findByText(en.configEdit.issues.none)).toBeInTheDocument()
    expect(saveButton).toBeEnabled()
  })

  it('editingInvalidatesTheValidation', async () => {
    stubFetch(advancedRoutes({ 'POST /api/config/edit/validate': { status: 200, body: { issues: [] } } }))
    const user = userEvent.setup()
    renderApp('/config')
    const editor = await openEditor(user)
    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))
    await screen.findByText(en.configEdit.issues.none)

    await appendToEditor(user, editor, '# edit')

    expect(screen.getByRole('button', { name: en.configEdit.save })).toBeDisabled()
    expect(screen.queryByText(en.configEdit.issues.none)).not.toBeInTheDocument()
  })

  it('listsIssuesWithLineNumbers', async () => {
    stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': {
          status: 200,
          body: { issues: [{ line: 3, path: 'filenames', severity: 'error', code: 'wrong_type' }] },
        },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)

    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))

    const issueItem = (await screen.findByText('Line 3')).closest('li') as HTMLElement
    expect(within(issueItem).getByText(en.configEdit.issues.severity.error)).toBeInTheDocument()
    expect(within(issueItem).getByText('filenames')).toBeInTheDocument()
    expect(within(issueItem).getByText(en.configEdit.issues.codes.wrong_type)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.configEdit.save })).toBeDisabled()
  })

  // A code added to the backend before the web catalogue must still read as a
  // sentence: the generic label in the user's language, the raw code beside it.
  it('labelsAnUnknownIssueCodeGenerically', async () => {
    stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': {
          status: 200,
          body: { issues: [{ line: 4, path: 'source', severity: 'warning', code: 'brand_new_check' }] },
        },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)

    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))

    const issueItem = (await screen.findByText('Line 4')).closest('li') as HTMLElement
    expect(within(issueItem).getByText(en.configEdit.issues.unknownCode)).toBeInTheDocument()
    expect(within(issueItem).getByText('brand_new_check')).toBeInTheDocument()
  })

  it('warningsDoNotBlockSaving', async () => {
    stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': {
          status: 200,
          body: { issues: [{ line: 2, path: 'extra', severity: 'warning', code: 'unknown_key' }] },
        },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)

    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))

    expect(await screen.findByText('Line 2')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: en.configEdit.save })).toBeEnabled()
  })

  it('offersReloadButtonAfterSuccessfulSave', async () => {
    let currentDigest = FILE_DIGEST
    const fetchMock = stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': { status: 200, body: { issues: [] } },
        [`PUT ${FILE_URL}`]: () => {
          currentDigest = 'digest-2'
          return { status: 200, body: { created: false, digest: 'digest-2', rolled_back: false, backup_stored: true } }
        },
        [`GET ${FILE_URL}`]: () => editableFile(currentDigest === FILE_DIGEST ? {} : { digest: currentDigest, content: `${ORIGINAL_CONTENT}# edit` }),
        'POST /api/crowdsec/reload': { status: 200, body: { status: 'ok' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    const editor = await openEditor(user)
    await appendToEditor(user, editor, '# edit')
    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))
    await screen.findByText(en.configEdit.issues.none)

    await user.click(screen.getByRole('button', { name: en.configEdit.save }))

    const reloadButton = await screen.findByRole('button', { name: en.hub.reload })
    const [saveRequest] = requestsTo(fetchMock, 'PUT', FILE_URL)
    expect(JSON.parse(saveRequest.body as string)).toEqual({ content: `${ORIGINAL_CONTENT}# edit`, expected_digest: FILE_DIGEST })
    // The refreshed file replaces the buffer and carries the new digest.
    expect(await screen.findByLabelText(`Editor for ${FILE_NAME}`)).toHaveValue(`${ORIGINAL_CONTENT}# edit`)
    await user.click(reloadButton)
    expect(requestsTo(fetchMock, 'POST', '/api/crowdsec/reload')).toHaveLength(1)
  })

  it('showsDigestConflictAndOffersReload', async () => {
    const fetchMock = stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': { status: 200, body: { issues: [] } },
        [`PUT ${FILE_URL}`]: { status: 409, body: { error: 'digest_mismatch' } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    const editor = await openEditor(user)
    await appendToEditor(user, editor, '# mine')
    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))
    await screen.findByText(en.configEdit.issues.none)

    await user.click(screen.getByRole('button', { name: en.configEdit.save }))

    expect(await screen.findByText(en.configEdit.conflict.title)).toBeInTheDocument()
    // Nothing is overwritten and the edit is kept until the user confirms discarding it.
    expect(screen.getByLabelText(`Editor for ${FILE_NAME}`)).toHaveValue(`${ORIGINAL_CONTENT}# mine`)
    const getCountBeforeReload = requestsTo(fetchMock, 'GET', FILE_URL).length

    await user.click(screen.getByRole('button', { name: en.configEdit.conflict.reload }))
    await user.click(await screen.findByRole('button', { name: en.configEdit.discard.confirm }))

    expect(await screen.findByLabelText(`Editor for ${FILE_NAME}`)).toHaveValue(ORIGINAL_CONTENT)
    expect(requestsTo(fetchMock, 'GET', FILE_URL).length).toBe(getCountBeforeReload + 1)
  })

  it('showsRolledBackNoticeWhenCrowdsecRejectsTheChange', async () => {
    stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': { status: 200, body: { issues: [] } },
        [`PUT ${FILE_URL}`]: { status: 422, body: { error: 'config_test_failed', rolled_back: true } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)
    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))
    await screen.findByText(en.configEdit.issues.none)

    await user.click(screen.getByRole('button', { name: en.configEdit.save }))

    expect(await screen.findByText(en.configEdit.rejectedRolledBack)).toBeInTheDocument()
  })

  it('listsAffectedFilesWhenTheConfigIsInconsistent', async () => {
    stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': { status: 200, body: { issues: [] } },
        [`PUT ${FILE_URL}`]: { status: 500, body: { error: 'config_inconsistent', affected_files: ['acquis.d/a.yaml'] } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)
    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))
    await screen.findByText(en.configEdit.issues.none)

    await user.click(screen.getByRole('button', { name: en.configEdit.save }))

    expect(await screen.findByText(en.errors.config_inconsistent)).toBeInTheDocument()
    expect(screen.getByText('acquis.d/a.yaml')).toBeInTheDocument()
  })

  it('showsLineAndExplanationOnSecretMergeError', async () => {
    stubFetch(
      advancedRoutes({
        'POST /api/config/edit/validate': { status: 200, body: { issues: [] } },
        [`PUT ${FILE_URL}`]: { status: 400, body: { error: 'secret_context_changed', line: 7 } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)
    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))
    await screen.findByText(en.configEdit.issues.none)

    await user.click(screen.getByRole('button', { name: en.configEdit.save }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Line 7')
    expect(alert).toHaveTextContent(en.errors.secret_context_changed)
    expect(alert).toHaveTextContent(en.configEdit.secretExplanation)
  })

  it('deleteAsksToTypeTheFileName', async () => {
    const fetchMock = stubFetch(advancedRoutes({ [`DELETE ${FILE_URL}`]: { status: 200, body: { status: 'ok' } } }))
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)

    await user.click(screen.getByRole('button', { name: en.configEdit.delete.open }))
    const dialog = await screen.findByRole('dialog')
    const confirmButton = within(dialog).getByRole('button', { name: en.configEdit.delete.submit })
    expect(confirmButton).toBeDisabled()

    await user.type(within(dialog).getByRole('textbox'), FILE_NAME)
    await user.click(confirmButton)

    const [deleteRequest] = await vi.waitFor(() => {
      const issuedRequests = requestsTo(fetchMock, 'DELETE', FILE_URL)
      expect(issuedRequests).toHaveLength(1)
      return issuedRequests
    })
    expect(JSON.parse(deleteRequest.body as string)).toEqual({ expected_digest: FILE_DIGEST, confirm: FILE_NAME })
    expect(await screen.findByText(en.config.select)).toBeInTheDocument()
  })

  it('showsConfigYamlReadOnlyAndEditsLocalOverride', async () => {
    stubFetch(
      advancedRoutes({
        'GET /api/config/edit/config.yaml': {
          status: 200,
          body: { name: 'config.yaml', exists: true, read_only: true, writable: false, digest: 'd', content: 'api: {}\n' },
        },
        'GET /api/config/edit/config.yaml.local': {
          status: 200,
          body: { name: 'config.yaml.local', exists: false, read_only: false, writable: true, digest: 'absent-digest', content: '' },
        },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await user.click(await screen.findByRole('checkbox', { name: en.configEdit.advancedMode }))

    await user.click(await screen.findByRole('button', { name: 'config.yaml' }))

    expect((await screen.findByLabelText('Content of config.yaml')).textContent).toBe('api: {}\n')
    expect(screen.queryByRole('textbox', { name: /Editor for/ })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: en.configEdit.editOverrides }))

    // The absent override file starts empty; saving will create it.
    expect(await screen.findByLabelText('Editor for config.yaml.local')).toHaveValue('')
  })

  it('createsANewFileFromAnEmptyEditorUsingTheAbsentFileDigest', async () => {
    const newName = 'acquis.d/new.yaml'
    const fetchMock = stubFetch(
      advancedRoutes({
        [`GET /api/config/edit/${newName}`]: {
          status: 200,
          body: { name: newName, exists: false, read_only: false, writable: true, digest: 'absent-digest', content: '' },
        },
        'POST /api/config/edit/validate': { status: 200, body: { issues: [] } },
        [`PUT /api/config/edit/${newName}`]: { status: 200, body: { created: true, digest: 'd2', rolled_back: false, backup_stored: false } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await user.click(await screen.findByRole('checkbox', { name: en.configEdit.advancedMode }))

    await user.type(await screen.findByLabelText(en.configEdit.newFile.label), 'nope.txt')
    await user.click(screen.getByRole('button', { name: en.configEdit.newFile.create }))
    expect(await screen.findByText(en.configEdit.newFile.invalid)).toBeInTheDocument()

    await user.clear(screen.getByLabelText(en.configEdit.newFile.label))
    await user.type(screen.getByLabelText(en.configEdit.newFile.label), newName)
    await user.click(screen.getByRole('button', { name: en.configEdit.newFile.create }))
    const editor = await screen.findByLabelText(`Editor for ${newName}`)
    await user.type(editor, 'source: file')
    await user.click(screen.getByRole('button', { name: en.configEdit.validate }))
    await screen.findByText(en.configEdit.issues.none)
    await user.click(screen.getByRole('button', { name: en.configEdit.save }))

    await vi.waitFor(() => expect(requestsTo(fetchMock, 'PUT', `/api/config/edit/${newName}`)).toHaveLength(1))
    const [createRequest] = requestsTo(fetchMock, 'PUT', `/api/config/edit/${newName}`)
    expect(JSON.parse(createRequest.body as string)).toEqual({ content: 'source: file', expected_digest: 'absent-digest' })
  })

  it('restoreListShowsTenNewestBackups', async () => {
    const backups = Array.from({ length: 12 }, (_unused, backupIndex) => ({
      id: backupIndex + 1,
      created_at: `2026-11-${String(20 - backupIndex).padStart(2, '0')}T10:00:00Z`,
      account_name: `account-${backupIndex + 1}`,
      size: 100 + backupIndex,
    }))
    const fetchMock = stubFetch(
      advancedRoutes({
        [`GET /api/config/backups/${FILE_NAME}`]: { status: 200, body: { items: backups } },
        '/api/config/backups/1/restore': { status: 200 },
        'POST /api/config/backups/1/restore': { status: 200, body: { created: false, digest: 'd3', rolled_back: false, backup_stored: true } },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    await openEditor(user)

    const restoreButtons = await screen.findAllByRole('button', { name: /^Restore backup of/ })
    expect(restoreButtons).toHaveLength(10)
    expect(screen.getByText('account-1')).toBeInTheDocument()
    expect(screen.queryByText('account-11')).not.toBeInTheDocument()

    await user.click(restoreButtons[0])
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: en.configEdit.backups.restore }))

    await vi.waitFor(() => expect(requestsTo(fetchMock, 'POST', '/api/config/backups/1/restore')).toHaveLength(1))
    const [restoreRequest] = requestsTo(fetchMock, 'POST', '/api/config/backups/1/restore')
    expect(JSON.parse(restoreRequest.body as string)).toEqual({ expected_digest: FILE_DIGEST })
  })

  it('asksConfirmationBeforeSwitchingFileWithUnsavedEdits', async () => {
    stubFetch(
      advancedRoutes({
        'GET /api/config/edit/config.yaml': {
          status: 200,
          body: { name: 'config.yaml', exists: true, read_only: true, writable: false, digest: 'd', content: 'api: {}\n' },
        },
      }),
    )
    const user = userEvent.setup()
    renderApp('/config')
    const editor = await openEditor(user)
    await appendToEditor(user, editor, '# unsaved')

    await user.click(screen.getByRole('button', { name: 'config.yaml' }))
    await user.click(await screen.findByRole('button', { name: en.dialog.cancel }))

    // Cancelling keeps the buffer and the file.
    expect(screen.getByLabelText(`Editor for ${FILE_NAME}`)).toHaveValue(`${ORIGINAL_CONTENT}# unsaved`)

    await user.click(screen.getByRole('button', { name: 'config.yaml' }))
    await user.click(await screen.findByRole('button', { name: en.configEdit.discard.confirm }))

    expect(await screen.findByLabelText('Content of config.yaml')).toBeInTheDocument()
  })

  it('asksConfirmationBeforeSwitchingEngineWithUnsavedEdits', async () => {
    stubFetch(advancedRoutes({ 'GET /api/config/files?engine=peer': { status: 200, body: { files: ['acquis.yaml'] } } }))
    const user = userEvent.setup()
    renderApp('/config')
    const editor = await openEditor(user)
    await appendToEditor(user, editor, '# unsaved')

    await selectTargetEngine(user, 'peer')
    expect(await screen.findByText(en.configEdit.discard.title)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: en.configEdit.discard.confirm }))

    expect(await screen.findByRole('button', { name: 'acquis.yaml' })).toBeInTheDocument()
    expect(screen.queryByLabelText(`Editor for ${FILE_NAME}`)).not.toBeInTheDocument()
  })
})
