import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authAPI } from '../api/auth'

export const useAuthStore = defineStore('auth', () => {
  const token = ref('')
  const refreshToken = ref('')
  const user = ref(null)

  const isAuthenticated = computed(() => !!token.value)

  function loadFromStorage() {
    const saved = localStorage.getItem('rayscan_auth')
    if (saved) {
      try {
        const data = JSON.parse(saved)
        token.value = data.token || ''
        refreshToken.value = data.refreshToken || ''
        user.value = data.user || null
      } catch { /* ignore */ }
    }
  }

  function saveToStorage() {
    localStorage.setItem('rayscan_auth', JSON.stringify({
      token: token.value,
      refreshToken: refreshToken.value,
      user: user.value,
    }))
  }

  async function login(username, password) {
    const res = await authAPI.login(username, password)
    if (res.ok) {
      token.value = res.access_token
      refreshToken.value = res.refresh_token
      user.value = res.user
      saveToStorage()
    }
    return res
  }

  async function initAdmin(username, password) {
    return await authAPI.init(username, password)
  }

  function logout() {
    token.value = ''
    refreshToken.value = ''
    user.value = null
    localStorage.removeItem('rayscan_auth')
  }

  return { token, refreshToken, user, isAuthenticated, loadFromStorage, login, initAdmin, logout }
})
