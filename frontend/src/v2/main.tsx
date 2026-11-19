import { flushSync } from 'react-dom'
import { Controller } from './web/controller'

// The document owns authentication. Scrub an Azure callback synchronously
// before importing the router, UI providers or stylesheet dependency graph.
const controller = new Controller(undefined, clear => flushSync(clear))
const callback = location.pathname === '/auth/azure/callback' ? controller.callback() : undefined

void import('./web/AdminApp').then(({ mount }) => {
  mount(controller)
  void controller.start(callback)
}).catch(() => {
  const message = document.createElement('p')
  message.textContent = 'OPS could not load. Reload this page to try again.'
  document.getElementById('root')?.replaceChildren(message)
})
