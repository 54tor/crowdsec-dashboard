import { BarChart } from 'echarts/charts'
import { GridComponent } from 'echarts/components'
import { init, use as registerEchartsModules } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useIsDark } from '@/hooks/useIsDark'
import type { HourBucket } from '@/lib/hourlyBuckets'

registerEchartsModules([BarChart, GridComponent, CanvasRenderer])

const PALETTES = {
  light: { text: '#3f3f46', grid: '#d4d4d8', bar: '#1d4ed8' },
  dark: { text: '#d4d4d8', grid: '#3f3f46', bar: '#60a5fa' },
}

export default function TimelineChartCanvas({ buckets }: { buckets: HourBucket[] }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const isDark = useIsDark()
  const { t, i18n } = useTranslation()

  useEffect(() => {
    const container = containerRef.current
    if (!container) {
      return
    }
    const palette = isDark ? PALETTES.dark : PALETTES.light
    const hourFormatter = new Intl.DateTimeFormat(i18n.language, { day: 'numeric', month: 'short', hour: 'numeric' })
    const chart = init(container, undefined, { renderer: 'canvas' })
    chart.setOption({
      backgroundColor: 'transparent',
      textStyle: { color: palette.text },
      grid: { left: 40, right: 16, top: 16, bottom: 40 },
      xAxis: {
        type: 'category',
        data: buckets.map((bucket) => hourFormatter.format(bucket.hourStart)),
        axisLine: { lineStyle: { color: palette.grid } },
        axisLabel: { color: palette.text },
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        splitLine: { lineStyle: { color: palette.grid } },
        axisLabel: { color: palette.text },
      },
      series: [
        {
          type: 'bar',
          name: t('chart.seriesName'),
          data: buckets.map((bucket) => bucket.count),
          itemStyle: { color: palette.bar },
        },
      ],
    })
    const resizeObserver = new ResizeObserver(() => chart.resize())
    resizeObserver.observe(container)
    return () => {
      resizeObserver.disconnect()
      chart.dispose()
    }
  }, [buckets, isDark, i18n.language, t])

  return <div ref={containerRef} aria-hidden="true" className="h-64 w-full" />
}
