// jsdom ships without window.matchMedia. This stub answers the queries the app
// uses (viewport width bounds and the dark colour-scheme preference) from two
// values that tests drive with setViewportWidth and setSystemPrefersDark.
// Every list ever created is kept so a change can notify its listeners.

type MediaQueryChangeListener = (event: MediaQueryListEvent) => void

const DEFAULT_VIEWPORT_WIDTH_IN_PIXELS = 1920
const WIDTH_CONDITION_PATTERN = /\((min|max)-width:\s*(\d+(?:\.\d+)?)px\)/
const DARK_SCHEME_CONDITION = '(prefers-color-scheme: dark)'
const LIGHT_SCHEME_CONDITION = '(prefers-color-scheme: light)'

let currentViewportWidthInPixels = DEFAULT_VIEWPORT_WIDTH_IN_PIXELS
let currentSystemPrefersDark = false
const createdQueryLists: StubMediaQueryList[] = []

function evaluateCondition(condition: string): boolean {
  const widthConditionMatch = WIDTH_CONDITION_PATTERN.exec(condition)
  if (widthConditionMatch) {
    const [, boundKind, boundValue] = widthConditionMatch
    const boundInPixels = Number(boundValue)
    if (boundKind === 'min') {
      return currentViewportWidthInPixels >= boundInPixels
    }
    return currentViewportWidthInPixels <= boundInPixels
  }
  if (condition.includes(DARK_SCHEME_CONDITION)) {
    return currentSystemPrefersDark
  }
  if (condition.includes(LIGHT_SCHEME_CONDITION)) {
    return !currentSystemPrefersDark
  }
  return false
}

// Only conjunctions ("a and b") are supported; that covers every query in the app.
function evaluateMediaQuery(mediaQuery: string): boolean {
  return mediaQuery.split(/\s+and\s+/).every((condition) => evaluateCondition(condition.trim()))
}

class StubMediaQueryList extends EventTarget {
  readonly media: string
  onchange: MediaQueryChangeListener | null = null
  private lastKnownMatches: boolean

  constructor(mediaQuery: string) {
    super()
    this.media = mediaQuery
    this.lastKnownMatches = evaluateMediaQuery(mediaQuery)
  }

  get matches(): boolean {
    return evaluateMediaQuery(this.media)
  }

  addListener(legacyListener: MediaQueryChangeListener): void {
    this.addEventListener('change', legacyListener as EventListener)
  }

  removeListener(legacyListener: MediaQueryChangeListener): void {
    this.removeEventListener('change', legacyListener as EventListener)
  }

  notifyIfChanged(): void {
    const currentMatches = this.matches
    if (currentMatches === this.lastKnownMatches) {
      return
    }
    this.lastKnownMatches = currentMatches
    const changeEvent = Object.assign(new Event('change'), { matches: currentMatches, media: this.media })
    this.dispatchEvent(changeEvent)
    this.onchange?.(changeEvent as MediaQueryListEvent)
  }
}

function notifyEveryQueryList(): void {
  for (const queryList of createdQueryLists) {
    queryList.notifyIfChanged()
  }
}

export function setViewportWidth(widthInPixels: number): void {
  currentViewportWidthInPixels = widthInPixels
  notifyEveryQueryList()
}

export function setSystemPrefersDark(prefersDark: boolean): void {
  currentSystemPrefersDark = prefersDark
  notifyEveryQueryList()
}

export function installMatchMediaStub(): void {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (mediaQuery: string) => {
      const queryList = new StubMediaQueryList(mediaQuery)
      createdQueryLists.push(queryList)
      return queryList
    },
  })
}

// Restores the defaults silently: listeners from the previous test are dropped
// rather than notified, because their components are already unmounted.
export function resetMatchMediaStub(): void {
  createdQueryLists.length = 0
  currentViewportWidthInPixels = DEFAULT_VIEWPORT_WIDTH_IN_PIXELS
  currentSystemPrefersDark = false
}
