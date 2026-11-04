(function () {
  let storedPreference = null
  try {
    storedPreference = window.localStorage.getItem('theme-preference')
  } catch {
    storedPreference = null
  }
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const followsSystem = storedPreference !== 'light' && storedPreference !== 'dark'
  const isDark = storedPreference === 'dark' || (followsSystem && systemPrefersDark)
  const rootElement = document.documentElement
  rootElement.classList.toggle('dark', isDark)
  rootElement.style.colorScheme = isDark ? 'dark' : 'light'
})()
