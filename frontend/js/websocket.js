/**
 * WebAudit 360 — Real-Time WebSocket Client
 * Creator: Harsh Patel
 * 
 * Features:
 * - Automatic reconnection with exponential backoff
 * - Event-based subscription pattern
 * - HTTP polling fallback when WebSockets are unavailable
 */

import { CONFIG } from "./config.js";

export class AuditWebSocket {
  constructor(auditId, options = {}) {
    this.auditId = auditId;
    this.options = options;
    this.ws = null;
    this.subscribers = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelayMs = 1500;
    this.isClosedManually = false;
    this.pollingInterval = null;
  }

  connect() {
    this.isClosedManually = false;
    const wsUrl = `${CONFIG.WS_BASE_URL}/audits/${this.auditId}`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.emit("open", { auditId: this.auditId });
      };

      this.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          this.emit("message", payload);
          if (payload.event) {
            this.emit(payload.event, payload);
          }
        } catch (e) {
          console.error("[WebSocket] Failed to parse message:", event.data);
        }
      };

      this.ws.onerror = (err) => {
        this.emit("error", err);
      };

      this.ws.onclose = (event) => {
        if (!this.isClosedManually) {
          this.handleDisconnect();
        }
      };
    } catch (err) {
      console.warn("[WebSocket] Native connection failed, starting polling fallback:", err);
      this.startPollingFallback();
    }
  }

  handleDisconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelayMs * Math.pow(1.5, this.reconnectAttempts);
      setTimeout(() => {
        if (!this.isClosedManually) {
          this.connect();
        }
      }, delay);
    } else {
      console.warn("[WebSocket] Max reconnect attempts exceeded, engaging polling fallback.");
      this.startPollingFallback();
    }
  }

  startPollingFallback() {
    if (this.pollingInterval) return;
    this.pollingInterval = setInterval(async () => {
      try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/audits/${this.auditId}`);
        if (response.ok) {
          const audit = await response.json();
          this.emit("poll_update", audit);
          if (["COMPLETED", "FAILED", "CANCELLED"].includes(audit.status)) {
            this.close();
            this.emit("audit_completed", { auditId: this.auditId, status: audit.status, audit });
          }
        }
      } catch (err) {
        console.warn("[WebSocket Fallback] Polling request failed:", err);
      }
    }, 2500);
  }

  on(event, callback) {
    if (!this.subscribers.has(event)) {
      this.subscribers.set(event, []);
    }
    this.subscribers.get(event).push(callback);
    return this;
  }

  emit(event, data) {
    const callbacks = this.subscribers.get(event) || [];
    callbacks.forEach((cb) => {
      try {
        cb(data);
      } catch (e) {
        console.error(`[WebSocket] Callback error for event "${event}":`, e);
      }
    });
  }

  close() {
    this.isClosedManually = true;
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
      this.pollingInterval = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}
