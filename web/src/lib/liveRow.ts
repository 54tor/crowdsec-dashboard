import { isLocalEngine, LOCAL_ENGINE_NAME } from '@/api/engineQuery'

export interface EngineRow {
  engine?: string
  live?: boolean
}

export function engineOfRow(row: EngineRow): string {
  return row.engine ?? LOCAL_ENGINE_NAME
}

export function isRowWritableOnItsEngine(row: EngineRow, isWritableEngine: (engineName: string) => boolean): boolean {
  const engineName = engineOfRow(row)
  if (isLocalEngine(engineName)) {
    return row.live ?? true
  }
  return isWritableEngine(engineName)
}
