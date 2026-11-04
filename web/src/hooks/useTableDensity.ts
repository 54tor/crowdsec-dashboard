import { useSyncExternalStore } from 'react'

export type TableDensity = 'comfortable' | 'compact'

export const TABLE_DENSITY_STORAGE_KEY = 'table-density'

const DEFAULT_TABLE_DENSITY: TableDensity = 'comfortable'

const densityListeners = new Set<() => void>()
let lastChosenDensity: TableDensity | null = null

function readStoredDensity(): TableDensity {
  try {
    const storedValue = localStorage.getItem(TABLE_DENSITY_STORAGE_KEY)
    return storedValue === 'compact' ? 'compact' : DEFAULT_TABLE_DENSITY
  } catch {
    return DEFAULT_TABLE_DENSITY
  }
}

function persistDensity(density: TableDensity): void {
  try {
    localStorage.setItem(TABLE_DENSITY_STORAGE_KEY, density)
  } catch {
    return
  }
}

function subscribeToDensity(onDensityChange: () => void): () => void {
  densityListeners.add(onDensityChange)
  return () => densityListeners.delete(onDensityChange)
}

function readCurrentDensity(): TableDensity {
  return lastChosenDensity ?? readStoredDensity()
}

function changeDensity(density: TableDensity): void {
  lastChosenDensity = density
  persistDensity(density)
  densityListeners.forEach((notifyListener) => notifyListener())
}

export function resetTableDensityStore(): void {
  lastChosenDensity = null
}

export function useTableDensity(): { density: TableDensity; changeDensity: (density: TableDensity) => void } {
  const density = useSyncExternalStore(subscribeToDensity, readCurrentDensity)
  return { density, changeDensity }
}
