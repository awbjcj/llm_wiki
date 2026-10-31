import { useCallback, useEffect, useRef, useState } from "react"

/**
 * State that shows a value briefly, then falls back to `idle`.
 *
 * Used for "Copied" / "Saved" confirmations. Each `flash` restarts the timer,
 * so repeated clicks keep the confirmation visible for the full duration, and
 * a pending timer is cleared on unmount. Pass a primitive `idle` so `flash`
 * stays referentially stable.
 */
export function useTransientValue<T>(idle: T, durationMs: number) {
  const [value, setValue] = useState<T>(idle)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => {
    if (timerRef.current !== null) clearTimeout(timerRef.current)
  }, [])

  const flash = useCallback((next: T) => {
    if (timerRef.current !== null) clearTimeout(timerRef.current)
    setValue(next)
    timerRef.current = setTimeout(() => {
      timerRef.current = null
      setValue(idle)
    }, durationMs)
  }, [idle, durationMs])

  return [value, flash] as const
}
