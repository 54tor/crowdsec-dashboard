import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { useTableDensity, type TableDensity } from '@/hooks/useTableDensity'

const DENSITY_CHOICES: readonly TableDensity[] = ['comfortable', 'compact']

export function DensityToggle() {
  const { t } = useTranslation()
  const { density, changeDensity } = useTableDensity()
  return (
    <div role="group" aria-label={t('list.density.label')} className="inline-flex gap-1">
      {DENSITY_CHOICES.map((densityChoice) => (
        <Button
          key={densityChoice}
          type="button"
          variant="outline"
          size="sm"
          aria-pressed={density === densityChoice}
          onClick={() => changeDensity(densityChoice)}
        >
          {t(`list.density.${densityChoice}`)}
        </Button>
      ))}
    </div>
  )
}
