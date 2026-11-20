// JSDOM has no layout observer. Shared V1 Radix controls use it to size their
// hidden form inputs; actual sizing is checked by the browser parity gate.
class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Object.defineProperty(globalThis, 'ResizeObserver', { configurable: true, writable: true, value: ResizeObserverMock })
