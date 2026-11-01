export interface EngineRow {
  engine?: string
  live?: boolean
}

export function isLiveLocalRow(row: EngineRow): boolean {
  const engineName = row.engine ?? 'local'
  const isLive = row.live ?? true
  return engineName === 'local' && isLive
}
