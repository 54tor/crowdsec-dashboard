import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Pagination, PaginationContent, PaginationItem } from '@/components/ui/pagination'

interface PaginationBarProps {
  page: number
  totalPages: number
  onPageChange: (page: number) => void
}

export function PaginationBar({ page, totalPages, onPageChange }: PaginationBarProps) {
  const { t } = useTranslation()
  return (
    <Pagination aria-label={t('list.pagination')}>
      <PaginationContent className="gap-3">
        <PaginationItem>
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
            {t('list.previous')}
          </Button>
        </PaginationItem>
        <PaginationItem>
          <span aria-live="polite" className="text-sm">
            {t('list.pageOf', { page, total: totalPages })}
          </span>
        </PaginationItem>
        <PaginationItem>
          <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>
            {t('list.next')}
          </Button>
        </PaginationItem>
      </PaginationContent>
    </Pagination>
  )
}
