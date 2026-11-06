import { useLayoutEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'

const BOTTOM_TOLERANCE_PIXELS = 24

interface LogLinesProps {
  lines: string[]
}

export function LogLines({ lines }: LogLinesProps) {
  const { t } = useTranslation()
  const blockRef = useRef<HTMLPreElement>(null)
  const isFollowingEndRef = useRef(true)
  useLayoutEffect(() => {
    const block = blockRef.current
    if (block && isFollowingEndRef.current) {
      block.scrollTop = block.scrollHeight
    }
  }, [lines])
  function rememberScrollPosition() {
    const block = blockRef.current
    if (block) {
      isFollowingEndRef.current = block.scrollHeight - block.scrollTop - block.clientHeight <= BOTTOM_TOLERANCE_PIXELS
    }
  }
  return (
    <pre
      ref={blockRef}
      role="log"
      aria-label={t('engineLogs.linesLabel')}
      tabIndex={0}
      onScroll={rememberScrollPosition}
      className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs"
    >
      {lines.length === 0 ? t('engineLogs.empty') : lines.map((line, lineIndex) => <div key={lineIndex} className="whitespace-pre-wrap [overflow-wrap:anywhere]">{line}</div>)}
    </pre>
  )
}
