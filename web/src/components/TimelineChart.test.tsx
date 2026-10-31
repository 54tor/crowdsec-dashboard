import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { TimelineChart } from '@/components/TimelineChart'
import en from '@/i18n/en.json'
import { makeAlert } from '@/test/fixtures'
import { prepareEnglishApp } from '@/test/pageHarness'

vi.mock('@/components/TimelineChartCanvas', () => ({
  default: ({ buckets }: { buckets: unknown[] }) => <div data-testid="timeline-canvas">{buckets.length}</div>,
}))

describe('timeline chart', () => {
  beforeEach(prepareEnglishApp)

  it('timelineChartRendersEmptyStateForNoAlerts', () => {
    render(<TimelineChart alerts={[]} />)

    expect(screen.getByText(en.chart.empty)).toBeInTheDocument()
    expect(screen.queryByTestId('timeline-canvas')).not.toBeInTheDocument()
  })

  it('bucketsAlertsPerHourAndExposesTextAlternative', async () => {
    const alertsInTwoHours = [
      makeAlert({ id: 1, created_at: '2026-10-31T10:05:00Z' }),
      makeAlert({ id: 2, created_at: '2026-10-31T10:10:00Z' }),
      makeAlert({ id: 3, created_at: '2026-10-31T12:10:00Z' }),
    ]
    render(<TimelineChart alerts={alertsInTwoHours} />)

    expect(await screen.findByTestId('timeline-canvas')).toHaveTextContent('2')
    expect(screen.getByRole('img', { name: /3 alerts, 2 active hours/ })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: en.chart.label })).toBeInTheDocument()
  })

  it('ignoresAlertsWithUnparsableDates', () => {
    render(<TimelineChart alerts={[makeAlert({ created_at: 'not a date' })]} />)

    expect(screen.getByText(en.chart.empty)).toBeInTheDocument()
  })
})
