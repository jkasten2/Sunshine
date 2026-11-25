import { mount, flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import ReconnectBanner from '../../src_assets/common/assets/web/ReconnectBanner.vue'
import { state as notificationState } from '../../src_assets/common/assets/web/Notification.vue'

beforeEach(() => {
  vi.useFakeTimers()
  notificationState.notifications.splice(0, notificationState.notifications.length)
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function mountBanner() {
  return mount(ReconnectBanner, {
    global: {
      mocks: {
        $t: (key, params) => (params ? `${key}:${JSON.stringify(params)}` : key),
      },
    },
  })
}

describe('ReconnectBanner', () => {
  it('polls pending reconnects and renders launch and resume prompts', async () => {
    let payload = {
      status: true,
      reconnects: [
        { id: '0123456789abcdef0123456789abcdef', uuid: 'u1', name: 'Laptop', address: '192.168.1.20', action: 'launch' },
        { id: 'fedcba9876543210fedcba9876543210', uuid: 'u2', name: '', address: '', action: 'resume' },
      ],
    }
    let ok = true
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (url === './api/clients/reconnect') {
        return { ok, status: ok ? 200 : 401, json: async () => payload }
      }
      throw new Error(`Unexpected URL: ${url}`)
    }))

    const wrapper = mountBanner()
    await flushPromises()

    const alerts = wrapper.findAll('[role="region"] .alert')
    expect(alerts).toHaveLength(2)
    expect(alerts[0].text()).toContain('reconnect.launch_prompt:{"name":"Laptop","address":"192.168.1.20"}')
    expect(alerts[1].text()).toContain('reconnect.resume_prompt:{"name":"troubleshooting.unpair_single_unknown","address":"pin.unknown_address"}')

    ok = false
    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(wrapper.findAll('[role="region"] .alert')).toHaveLength(2)

    ok = true
    payload = { status: true }
    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(wrapper.find('[role="region"]').exists()).toBe(false)

    wrapper.unmount()
  })

  it('submits accept, deny, failure, and network-error outcomes', async () => {
    let reconnects = [
      { id: '0123456789abcdef0123456789abcdef', uuid: 'u1', name: 'TV', address: '10.0.0.5', action: 'launch' },
    ]
    let postBehavior = 'approve_ok'

    vi.stubGlobal('fetch', vi.fn(async (url, options = {}) => {
      if (url === './api/clients/reconnect' && options.method === 'POST') {
        if (postBehavior === 'throw') {
          throw new Error('network error')
        }
        reconnects = []
        return {
          ok: true,
          status: 200,
          json: async () => ({ status: postBehavior !== 'status_false' }),
        }
      }
      if (url === './api/clients/reconnect') {
        return { ok: true, status: 200, json: async () => ({ status: true, reconnects }) }
      }
      throw new Error(`Unexpected URL: ${url}`)
    }))

    const wrapper = mountBanner()
    await flushPromises()

    await wrapper.findAll('[role="region"] button')[0].trigger('click')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('./api/clients/reconnect', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ request_id: '0123456789abcdef0123456789abcdef', approve: true }),
    }))
    expect(notificationState.notifications.at(-1)?.messageKey).toBe('reconnect.approve_success')

    reconnects = [{ id: '11111111111111111111111111111111', uuid: 'u2', name: 'Phone', address: '10.0.0.6', action: 'launch' }]
    postBehavior = 'deny_ok'
    vi.advanceTimersByTime(2000)
    await flushPromises()
    await wrapper.findAll('[role="region"] button')[1].trigger('click')
    await flushPromises()
    expect(notificationState.notifications.at(-1)?.messageKey).toBe('reconnect.deny_success')

    reconnects = [{ id: '22222222222222222222222222222222', uuid: 'u3', name: 'Tablet', address: '10.0.0.7', action: 'launch' }]
    postBehavior = 'status_false'
    vi.advanceTimersByTime(2000)
    await flushPromises()
    await wrapper.findAll('[role="region"] button')[0].trigger('click')
    await flushPromises()
    expect(notificationState.notifications.at(-1)?.messageKey).toBe('reconnect.resolve_failure')

    reconnects = [{ id: '33333333333333333333333333333333', uuid: 'u4', name: 'Deck', address: '10.0.0.8', action: 'launch' }]
    postBehavior = 'throw'
    vi.advanceTimersByTime(2000)
    await flushPromises()
    await wrapper.findAll('[role="region"] button')[0].trigger('click')
    await flushPromises()
    expect(notificationState.notifications.at(-1)?.messageKey).toBe('reconnect.resolve_failure')

    wrapper.unmount()
  })

  it('ignores background poll errors and stops polling cleanly even if called twice', async () => {
    const fetchSpy = vi.fn(async () => {
      throw new Error('offline')
    })
    vi.stubGlobal('fetch', fetchSpy)

    const wrapper = mountBanner()
    await flushPromises()
    expect(wrapper.find('[role="region"]').exists()).toBe(false)

    wrapper.vm.stopReconnectPolling()
    wrapper.vm.stopReconnectPolling()
    const callsBeforeUnmount = fetchSpy.mock.calls.length
    wrapper.unmount()
    vi.advanceTimersByTime(6000)
    await flushPromises()
    expect(fetchSpy.mock.calls.length).toBe(callsBeforeUnmount)
  })
})
