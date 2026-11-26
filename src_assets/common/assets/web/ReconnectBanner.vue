<template>
  <div v-if="pendingReconnects.length > 0" class="container mt-3" role="region" :aria-label="$t('reconnect.banner_label')">
    <div
      v-for="req in pendingReconnects"
      :key="req.id"
      class="alert alert-warning d-flex flex-wrap justify-content-between align-items-center gap-3 mb-2"
      role="alert"
    >
      <div class="d-flex align-items-center gap-2">
        <AlertTriangle :size="20" class="icon flex-shrink-0"></AlertTriangle>
        <div>
          <strong>{{ $t('reconnect.title') }}</strong>
          <div>
            {{
              $t(
                req.action === 'resume' ? 'reconnect.resume_prompt' : 'reconnect.launch_prompt',
                {
                  name: req.name || $t('troubleshooting.unpair_single_unknown'),
                  address: req.address || $t('pin.unknown_address'),
                }
              )
            }}
          </div>
        </div>
      </div>
      <div class="d-flex gap-2 ms-auto">
        <button
          type="button"
          class="btn btn-success btn-sm"
          :disabled="Boolean(submittingReconnectIds[req.id])"
          @click="resolveReconnect(req.id, true)"
        >
          <Check :size="16" class="icon"></Check>
          {{ $t('reconnect.accept') }}
        </button>
        <button
          type="button"
          class="btn btn-danger btn-sm"
          :disabled="Boolean(submittingReconnectIds[req.id])"
          @click="resolveReconnect(req.id, false)"
        >
          <X :size="16" class="icon"></X>
          {{ $t('reconnect.deny') }}
        </button>
      </div>
    </div>
  </div>
</template>

<script>
import { AlertTriangle, Check, X } from '@lucide/vue'
import { apiFetch } from './fetch_utils'
import { notifyKey } from './Notification.vue'

export default {
  components: {
    AlertTriangle,
    Check,
    X,
  },
  data() {
    return {
      pendingReconnects: [],
      reconnectTimer: null,
      submittingReconnectIds: {},
    }
  },
  mounted() {
    this.loadPendingReconnects()
    this.reconnectTimer = globalThis.setInterval(() => this.loadPendingReconnects(), 2000)
  },
  beforeUnmount() {
    this.stopReconnectPolling()
  },
  methods: {
    stopReconnectPolling() {
      if (this.reconnectTimer !== null) {
        globalThis.clearInterval(this.reconnectTimer)
        this.reconnectTimer = null
      }
    },
    async loadPendingReconnects() {
      try {
        const response = await fetch('./api/clients/reconnect', { method: 'GET' })
        if (!response.ok) {
          return
        }
        const body = await response.json()
        this.pendingReconnects = Array.isArray(body.reconnects) ? body.reconnects : []
      } catch {
        // Ignore transient network errors while polling in the background.
      }
    },
    async resolveReconnect(requestId, approve) {
      this.submittingReconnectIds = { ...this.submittingReconnectIds, [requestId]: true }
      try {
        const response = await apiFetch('./api/clients/reconnect', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ request_id: requestId, approve }),
        })
        const result = await response.json()
        if (result.status === true) {
          notifyKey.success(approve ? 'reconnect.approve_success' : 'reconnect.deny_success')
        } else {
          notifyKey.error('reconnect.resolve_failure')
        }
      } catch {
        notifyKey.error('reconnect.resolve_failure')
      } finally {
        const updated = { ...this.submittingReconnectIds }
        delete updated[requestId]
        this.submittingReconnectIds = updated
        await this.loadPendingReconnects()
      }
    },
  },
}
</script>
