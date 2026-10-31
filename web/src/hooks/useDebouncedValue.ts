import { useEffect, useState } from 'react'

export function useDebouncedValue<Value>(value: Value, delayMilliseconds: number): Value {
  const [debouncedValue, setDebouncedValue] = useState(value)
  useEffect(() => {
    const timerHandle = setTimeout(() => setDebouncedValue(value), delayMilliseconds)
    return () => clearTimeout(timerHandle)
  }, [value, delayMilliseconds])
  return debouncedValue
}
