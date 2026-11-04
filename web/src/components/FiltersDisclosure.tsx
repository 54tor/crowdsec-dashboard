import { useId, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon } from '@/components/Icon'
import { Button } from '@/components/ui/button'
import { useIsMobileViewport } from '@/hooks/useMediaQuery'

export function FiltersDisclosure({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const isMobileViewport = useIsMobileViewport()
  const [isExpanded, setIsExpanded] = useState(false)
  const filtersPanelId = useId()
  if (!isMobileViewport) {
    return <>{children}</>
  }
  return (
    <div className="space-y-3">
      <Button type="button" variant="outline" aria-expanded={isExpanded} aria-controls={filtersPanelId} onClick={() => setIsExpanded((wasExpanded) => !wasExpanded)}>
        <Icon name="filter_list" />
        {t('filters.toggle')}
      </Button>
      <div id={filtersPanelId}>{isExpanded && children}</div>
    </div>
  )
}
