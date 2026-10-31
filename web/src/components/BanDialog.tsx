import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { BanForm } from '@/components/BanForm'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogTrigger } from '@/components/ui/dialog'

export function BanDialog() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [isOpen, setIsOpen] = useState(false)
  const [lastBannedTarget, setLastBannedTarget] = useState<string | null>(null)

  function finishBan(bannedTarget: string) {
    setLastBannedTarget(bannedTarget)
    setIsOpen(false)
    void queryClient.invalidateQueries({ queryKey: ['decisions'] })
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <p role="status" className="text-sm text-muted-foreground">
        {lastBannedTarget && t('ban.success', { target: lastBannedTarget })}
      </p>
      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogTrigger asChild>
          <Button type="button">{t('ban.open')}</Button>
        </DialogTrigger>
        <DialogContent showCloseButton={false}>
          <BanForm onBanned={finishBan} onClose={() => setIsOpen(false)} />
        </DialogContent>
      </Dialog>
    </div>
  )
}
