import type { UseQueryResult } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Decision, Page } from '@/api/types'
import { PagedTableSection } from '@/components/PagedTableSection'
import { makeDecision, makePage } from '@/test/fixtures'
import { prepareEnglishApp } from '@/test/pageHarness'

// Only the fields the section reads are filled: a settled query holding one page.
function settledQuery(pageData: Page<Decision>): UseQueryResult<Page<Decision>> {
  return { data: pageData, error: null, isPending: false } as UseQueryResult<Page<Decision>>
}

const VALUE_COLUMN = [{ key: 'value', header: 'Value', cell: (decision: Decision) => decision.value }]

describe('paged table section', () => {
  beforeEach(prepareEnglishApp)

  // Deleting the last row of the last page shrinks the total: the section must
  // move back to the new last page instead of showing "Page 3 of 2" over an empty list.
  it('movesBackToTheLastPageWhenTheCurrentPageNoLongerExists', () => {
    const shrunkPage = makePage<Decision>([], { page: 3, per_page: 20, total: 40, window_size: 40 })
    const pageChangeSpy = vi.fn()

    render(
      <PagedTableSection
        query={settledQuery(shrunkPage)}
        page={3}
        onPageChange={pageChangeSpy}
        caption="Decisions"
        columns={VALUE_COLUMN}
        rowKey={(decision) => decision.id}
      />,
    )

    expect(pageChangeSpy).toHaveBeenCalledWith(2)
  })

  it('keepsTheCurrentPageWhenItStillExists', () => {
    const middlePage = makePage<Decision>([makeDecision()], { page: 2, per_page: 20, total: 41, window_size: 41 })
    const pageChangeSpy = vi.fn()

    render(
      <PagedTableSection
        query={settledQuery(middlePage)}
        page={2}
        onPageChange={pageChangeSpy}
        caption="Decisions"
        columns={VALUE_COLUMN}
        rowKey={(decision) => decision.id}
      />,
    )

    expect(pageChangeSpy).not.toHaveBeenCalled()
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument()
  })
})
