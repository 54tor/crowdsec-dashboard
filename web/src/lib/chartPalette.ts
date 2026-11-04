export interface ChartPalette {
  text: string
  grid: string
  bar: string
}

export function readChartPalette(rootElement: HTMLElement = document.documentElement): ChartPalette {
  const computedStyle = getComputedStyle(rootElement)
  const readVariable = (variableName: string) => computedStyle.getPropertyValue(variableName).trim()
  return {
    text: readVariable('--muted-foreground'),
    grid: readVariable('--border'),
    bar: readVariable('--info'),
  }
}
