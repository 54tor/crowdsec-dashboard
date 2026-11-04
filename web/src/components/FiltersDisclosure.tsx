import { useId, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import { Button } from '@/components/ui/button'
import { useIsMobileViewport } from '@/hooks/useMediaQuery'

interface FiltersDisclosureProps {
  children: ReactNode
  activeFilterCount: number
  hasInvalidFilter: boolean
}

export function FiltersDisclosure({ children, activeFilterCount, hasInvalidFilter }: FiltersDisclosureProps) {
  const { t } = useTranslation()
  const isMobileViewport = useIsMobileViewport()
  const [isExpandedByVisitor, setIsExpandedByVisitor] = useState(false)
  const filtersPanelId = useId()
  if (!isMobileViewport) {
    return <>{children}</>
  }
  const isPanelOpen = isExpandedByVisitor || hasInvalidFilter
  const toggleLabel = activeFilterCount > 0 ? t('filters.toggleWithCount', { count: activeFilterCount }) : t('filters.toggle')
  return (
    <div className="space-y-3">
      <Button type="button" variant="outline" aria-expanded={isPanelOpen} aria-controls={filtersPanelId} onClick={() => setIsExpandedByVisitor((wasExpanded) => !wasExpanded)}>
        <Icon name="filter_list" />
        {toggleLabel}
      </Button>
      <div id={filtersPanelId}>{isPanelOpen && children}</div>
    </div>
  )
}
