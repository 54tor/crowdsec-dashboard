import { afterEach, describe, expect, it, vi } from 'vitest'
import { downloadBlob } from './downloadBlob'

describe('downloadBlob', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('clicksAnAttachedLinkThenRemovesItAndRevokesTheUrlOnTheNextTick', () => {
    vi.useFakeTimers()
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:fake')
    const revokeObjectUrl = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined)
    // Firefox ignores clicks on detached links, so the link must be in the document when it is clicked.
    let wasAttachedWhenClicked = false
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function recordAttachment(this: HTMLAnchorElement) {
      wasAttachedWhenClicked = document.body.contains(this)
    })

    downloadBlob(new Blob(['{}']), 'bundle.json')

    expect(wasAttachedWhenClicked).toBe(true)
    expect(document.querySelector('a[download="bundle.json"]')).toBeNull()
    // Revoking synchronously can cancel the download before the browser starts it.
    expect(revokeObjectUrl).not.toHaveBeenCalled()
    vi.runAllTimers()
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:fake')
  })
})
