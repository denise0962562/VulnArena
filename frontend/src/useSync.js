import { computed, onUnmounted, ref } from 'vue'
import { api } from './api'

const STORAGE_KEY = 'vulnarena.tasks.v1'
const running = (task) => task && ['PENDING', 'RUNNING'].includes(task.status) && !task.unavailable

function readHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]')
    return Array.isArray(value)
      ? value
          .filter(
            (t) =>
              typeof t?.id === 'string' &&
              ['PENDING', 'RUNNING', 'SUCCESS', 'FAILED'].includes(t.status),
          )
          .slice(0, 8)
      : []
  } catch {
    return []
  }
}

export function useSync(onSuccess) {
  const history = ref(readHistory())
  const active = computed(() => history.value.find(running))
  const submitting = ref(false)
  const pollError = ref('')
  let timer
  let disposed = false
  let generation = 0

  function save(task) {
    history.value = [task, ...history.value.filter((entry) => entry.id !== task.id)].slice(0, 8)
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history.value))
    } catch {
      /* Private mode. */
    }
  }

  async function poll(id, token) {
    try {
      const task = await api.task(id)
      if (disposed || token !== generation) return
      const previous = history.value.find((entry) => entry.id === id)
      save({ ...task, label: previous?.label, unavailable: false })
      pollError.value = ''
      if (running(task)) timer = setTimeout(() => poll(id, token), 1500)
      else if (task.status === 'SUCCESS') await onSuccess()
    } catch (error) {
      if (disposed || token !== generation) return
      pollError.value = error.message
      if (error.status === 404) {
        const previous = history.value.find((entry) => entry.id === id)
        if (previous) save({ ...previous, unavailable: true })
      }
    }
  }

  function resume(task = active.value) {
    if (!task) return
    clearTimeout(timer)
    const token = ++generation
    pollError.value = ''
    void poll(task.id, token)
  }

  async function submit(query) {
    if (submitting.value || active.value) throw new Error('已有同步任务正在运行。')
    submitting.value = true
    try {
      const task = await api.sync(query)
      if (disposed) return
      save({ ...task, label: query.cve_id || query.keyword })
      resume(task)
      return task
    } finally {
      submitting.value = false
    }
  }

  onUnmounted(() => {
    disposed = true
    generation++
    clearTimeout(timer)
  })
  return { history, active, submitting, pollError, submit, resume }
}
