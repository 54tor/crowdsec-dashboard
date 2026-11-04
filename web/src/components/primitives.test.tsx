import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import type { ReactElement } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ConfirmDeleteDialog } from '@/components/ConfirmDeleteDialog'
import { EmptyState } from '@/components/EmptyState'
import { ErrorNotice, WarningNotice } from '@/components/Notice'
import { PageHeader } from '@/components/PageHeader'
import { RowDeleteAction } from '@/components/RowDeleteAction'
import { SelectField } from '@/components/SelectField'
import { Alert } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { CheckboxField } from '@/components/CheckboxField'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { setLanguage } from '@/i18n'
import { prepareEnglishApp } from '@/test/pageHarness'

// Dialogs and notices read the query client (mutations, timeout refresh), so each
// render gets a fresh one to keep the cases independent.
function renderWithQueryClient(element: ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}>{element}</QueryClientProvider>)
}

const ENGINE_OPTIONS = [
  { value: 'local', label: 'local' },
  { value: 'edge', label: 'edge' },
] as const

describe('shared primitives', () => {
  beforeEach(prepareEnglishApp)

  // The solid red fill is reserved for the final, irreversible confirmation.
  it('confirmDialogButtonIsSolidDestructive', () => {
    renderWithQueryClient(
      <ConfirmDeleteDialog
        open
        trigger={<button type="button">Open</button>}
        title="Delete engine"
        description="This removes the engine."
        target="edge"
        submitLabel="Delete for good"
        request={vi.fn().mockResolvedValue(undefined)}
        onDeleted={vi.fn()}
        onOpen={vi.fn()}
        onClose={vi.fn()}
      />,
    )

    const confirmButton = screen.getByRole('button', { name: 'Delete for good' })

    expect(confirmButton).toHaveAttribute('data-variant', 'destructive')
  })

  // A row trigger only opens the dialog: it stays outlined so tables are not a wall of red.
  it('rowDeleteTriggerIsNotSolid', () => {
    renderWithQueryClient(
      <RowDeleteAction
        buttonLabel="Delete"
        ariaLabel="Delete edge"
        title="Delete engine"
        description="This removes the engine."
        target="edge"
        request={vi.fn().mockResolvedValue(undefined)}
        invalidates={[]}
      />,
    )

    const rowTrigger = screen.getByRole('button', { name: 'Delete edge' })

    expect(rowTrigger).toHaveAttribute('data-variant', 'destructiveOutline')
  })

  it.each(['default', 'sm', 'icon'] as const)('buttonsMeetTouchTargets (%s)', (buttonSize) => {
    render(<Button size={buttonSize}>Act</Button>)

    const buttonClasses = screen.getByRole('button', { name: 'Act' }).className.split(' ')
    const meetsDesktopTarget = buttonClasses.includes('h-10') || buttonClasses.includes('size-10')
    const meetsMobileTarget = buttonClasses.includes('max-md:h-11') || buttonClasses.includes('max-md:size-11')

    expect(meetsDesktopTarget).toBe(true)
    expect(meetsMobileTarget).toBe(true)
  })

  // A pressed toggle used to differ only by a faint background (about 1.1:1):
  // it must also gain the inset border and the strong text of a checked segment.
  it('pressedOutlineToggleIsMarkedBeyondColour', () => {
    render(
      <>
        <Button variant="outline" aria-pressed>
          Pressed
        </Button>
        <Button variant="outline" aria-pressed={false}>
          Released
        </Button>
      </>,
    )

    const pressedToggleClasses = ['aria-pressed:shadow-[inset_0_0_0_1px_var(--input)]', 'aria-pressed:text-foreground', 'aria-pressed:font-medium']
    expect(screen.getByRole('button', { name: 'Pressed' })).toHaveClass(...pressedToggleClasses)
    expect(screen.getByRole('button', { name: 'Released' })).toHaveClass('aria-[pressed=false]:text-muted-foreground', 'aria-[pressed=false]:font-normal')
  })

  // The whole row, label text included, is the hit area of a checkbox.
  it('checkboxLabelWrapsTheBoxAndMeetsTouchTargets', () => {
    render(<CheckboxField id="include-expired" label="Include expired" checked={false} onChange={vi.fn()} />)

    const checkbox = screen.getByRole('checkbox', { name: 'Include expired' })
    const checkboxLabel = checkbox.closest('label')

    expect(checkboxLabel).not.toBeNull()
    expect(checkboxLabel).toHaveClass('flex', 'min-h-10', 'max-md:min-h-11', 'cursor-pointer')
  })

  // Menu items were 28 px high and only tinted on focus: they need the touch
  // target height and the double focus ring for keyboard users.
  it('menuItemsMeetTouchTargetsAndShowKeyboardFocus', () => {
    render(
      <DropdownMenu open>
        <DropdownMenuTrigger>Menu</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem>Plain item</DropdownMenuItem>
          <DropdownMenuRadioGroup value="first">
            <DropdownMenuRadioItem value="first">Radio item</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>,
    )

    const menuItems = [screen.getByRole('menuitem', { name: 'Plain item' }), screen.getByRole('menuitemradio', { name: 'Radio item' })]
    for (const menuItem of menuItems) {
      expect(menuItem).toHaveClass('min-h-10', 'max-md:min-h-11', 'focus-ring')
    }
  })

  it('controlsUseTheDoubleFocusRing', () => {
    const { container } = render(
      <>
        <Button>Act</Button>
        <Input aria-label="Name" />
        <SelectField id="engine" label="Engine" value="local" options={ENGINE_OPTIONS} onChange={vi.fn()} />
      </>,
    )

    expect(screen.getByRole('button', { name: 'Act' })).toHaveClass('focus-ring')
    expect(screen.getByRole('textbox', { name: 'Name' })).toHaveClass('focus-ring')
    expect(screen.getByLabelText('Engine')).toHaveClass('focus-ring')
    // The old translucent ring fails the 3:1 non-text contrast: none may remain.
    expect(container.querySelectorAll('[class*="ring-ring/50"]')).toHaveLength(0)
  })

  it.each(['critical', 'warning', 'info', 'nominal'] as const)('badgeStateVariants (%s)', (stateVariant) => {
    render(<Badge variant={stateVariant}>State</Badge>)

    expect(screen.getByText('State')).toHaveAttribute('data-variant', stateVariant)
  })

  // Only errors interrupt assistive technology; warnings are announced politely.
  it('noticesAreTinted', () => {
    renderWithQueryClient(
      <>
        <WarningNotice>Collection is late</WarningNotice>
        <ErrorNotice error={{ code: 'unknown' }} />
      </>,
    )

    expect(screen.getByRole('status')).toHaveAttribute('data-variant', 'warning')
    expect(screen.getByRole('alert')).toHaveAttribute('data-variant', 'critical')
  })

  // A bare Alert must not interrupt screen readers unless it reports a failure.
  it.each([
    ['info', 'status'],
    ['warning', 'status'],
    ['critical', 'alert'],
  ] as const)('alertRoleFollowsVariant (%s)', (alertVariant, expectedRole) => {
    render(<Alert variant={alertVariant}>Message</Alert>)

    expect(screen.getByRole(expectedRole)).toHaveAttribute('data-variant', alertVariant)
  })

  it('selectFieldIsLabelledAndDescribed', () => {
    render(<SelectField id="engine" label="Engine" value="local" options={ENGINE_OPTIONS} onChange={vi.fn()} hint="Pick one" error="Required" />)

    const engineSelect = screen.getByLabelText('Engine')

    expect(engineSelect.tagName).toBe('SELECT')
    expect(engineSelect).toHaveAttribute('aria-describedby', 'engine-hint engine-error')
    expect(engineSelect).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByText('Pick one')).toHaveAttribute('id', 'engine-hint')
    expect(screen.getByText('Required')).toHaveAttribute('id', 'engine-error')
  })

  it('pageHeaderRendersOneHeading', () => {
    render(<PageHeader title="Alerts" description="Recent alerts" actions={<button type="button">Ban</button>} />)

    const headings = screen.getAllByRole('heading')

    expect(headings).toHaveLength(1)
    expect(screen.getByRole('heading', { level: 1, name: 'Alerts' }).closest('header')).toContainElement(screen.getByRole('button', { name: 'Ban' }))
    expect(screen.getByText('Recent alerts')).toBeInTheDocument()
  })

  // With a long description the actions wrapped under it at the left edge:
  // they stay at the right like on every other page.
  it('pageHeaderActionsStayAtTheRight', () => {
    render(<PageHeader title="Allowlists" description="A long description" actions={<button type="button">Compact</button>} />)

    expect(screen.getByRole('button', { name: 'Compact' }).parentElement).toHaveClass('ml-auto')
  })

  it('emptyStateShowsMessage', () => {
    const { container } = render(<EmptyState message="Nothing to show" action={<button type="button">Reset</button>} />)

    expect(screen.getByText('Nothing to show')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Reset' })).toBeInTheDocument()
    expect(container.querySelector('[data-icon="inbox"]')).not.toBeNull()
  })

  it('dialogCloseButtonIsTranslated', async () => {
    await setLanguage('fr')

    render(
      <Dialog open>
        <DialogContent>
          <DialogTitle>Titre</DialogTitle>
          <DialogDescription>Description</DialogDescription>
        </DialogContent>
      </Dialog>,
    )

    expect(screen.getByRole('button', { name: 'Fermer' })).toBeInTheDocument()
  })
})
