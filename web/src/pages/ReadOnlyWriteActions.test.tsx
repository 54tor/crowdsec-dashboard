import { screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import en from '@/i18n/en.json'
import { makeAlert, makeBouncer, makeDecision, makeHealth, makeHubItem, makeMachine, makePage } from '@/test/fixtures'
import { stubFetch } from '@/test/fetchStub'
import { prepareEnglishApp } from '@/test/pageHarness'
import { renderApp } from '@/test/renderApp'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: () => <div data-testid="timeline-canvas" />,
}))

const ADMIN_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'alice', account_role: 'admin' } }
const READ_ONLY_SESSION = { status: 200, body: { status: 'authenticated', account_name: 'bob', account_role: 'read_only' } }

const HEALTH = makeHealth({
  bouncers: [makeBouncer({ name: 'firewall-one' })],
  machines: [makeMachine({ machine_id: 'machine-one', self: false, is_validated: false })],
})

function readRoutes(session: typeof ADMIN_SESSION) {
  return {
    'GET /api/auth/me': session,
    'GET /api/decisions?page=1&per_page=20': { status: 200, body: makePage([makeDecision({ id: 10, alert_id: 1 })]) },
    'GET /api/alerts?page=1&per_page=20': { status: 200, body: makePage([makeAlert({ id: 42, uuid: 'UUID-42' })]) },
    'GET /api/alerts?page=1&per_page=100': { status: 200, body: makePage([makeAlert({ id: 42, uuid: 'UUID-42' })], { per_page: 100 }) },
    'GET /api/health': { status: 200, body: HEALTH },
    'GET /api/hub': { status: 200, body: [makeHubItem({ type: 'collections', name: 'crowdsecurity/linux' })] },
  }
}

interface WritePageCase {
  path: string
  waitForReadContent: () => Promise<unknown>
  writeControls: () => (HTMLElement | null)[]
}

const WRITE_PAGES: Record<string, WritePageCase> = {
  decisions: {
    path: '/decisions',
    waitForReadContent: () => screen.findByText('203.0.113.7'),
    writeControls: () => [screen.queryByRole('button', { name: en.ban.open }), screen.queryByRole('button', { name: 'Unban 203.0.113.7' })],
  },
  alerts: {
    path: '/alerts',
    waitForReadContent: () => screen.findAllByRole('table'),
    writeControls: () => [screen.queryByRole('button', { name: 'Delete alert 42' })],
  },
  bouncers: {
    path: '/bouncers',
    waitForReadContent: () => screen.findByText('firewall-one', { selector: 'td' }),
    writeControls: () => [screen.queryByRole('button', { name: en.bouncers.add }), screen.queryByRole('button', { name: 'Delete firewall-one' })],
  },
  machines: {
    path: '/machines',
    waitForReadContent: () => screen.findByText('203.0.113.20'),
    writeControls: () => [
      screen.queryByRole('button', { name: en.machines.add }),
      screen.queryByRole('button', { name: 'Delete machine-one' }),
      screen.queryByRole('button', { name: 'Validate machine-one' }),
    ],
  },
  hub: {
    path: '/hub',
    waitForReadContent: () => screen.findByText('crowdsecurity/linux', { selector: 'td' }),
    writeControls: () => [
      screen.queryByRole('button', { name: en.hub.update }),
      screen.queryByRole('button', { name: en.hub.upgrade }),
      screen.queryByRole('button', { name: 'Remove crowdsecurity/linux' }),
    ],
  },
}

describe('write actions per account role', () => {
  beforeEach(prepareEnglishApp)
  afterEach(() => vi.unstubAllGlobals())

  for (const [pageName, pageCase] of Object.entries(WRITE_PAGES)) {
    it(`${pageName}PageDoesNotRenderWriteActionsForAReadOnlyAccount`, async () => {
      stubFetch(readRoutes(READ_ONLY_SESSION))
      renderApp(pageCase.path)

      await pageCase.waitForReadContent()

      expect(pageCase.writeControls().filter((control) => control !== null)).toEqual([])
    })

    it(`${pageName}PageRendersWriteActionsForAnAdminAccount`, async () => {
      stubFetch(readRoutes(ADMIN_SESSION))
      renderApp(pageCase.path)

      await pageCase.waitForReadContent()

      expect(pageCase.writeControls().filter((control) => control !== null).length).toBeGreaterThan(0)
    })
  }
})
