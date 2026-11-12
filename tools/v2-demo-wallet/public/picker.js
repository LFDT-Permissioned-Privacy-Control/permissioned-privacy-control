const form = document.querySelector('#proof'), submit = document.querySelector('#submit'), status = document.querySelector('#status')
let active = false
const sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))
async function json(path, options) {
  const response = await fetch(path, { ...options, credentials: 'omit', mode: 'same-origin', redirect: 'error', cache: 'no-store' })
  if (!response.ok) throw Error(response.status === 409 ? 'The wallet is busy. Wait for the current proof and try again.' : 'The demo wallet rejected the request. Check its URI and selected profile.')
  return response.json()
}
form.addEventListener('submit', async event => {
  event.preventDefault()
  if (active) return
  active = true; submit.disabled = true
  try {
    status.textContent = 'Generating a fresh cryptographic proof…'
    const job = await json('/prove', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ persona: document.querySelector('#persona').value, requestUri: document.querySelector('#request').value }) })
    const deadline = Date.now() + 150_000
    for (;;) {
      await sleep(750)
      const result = await json('/jobs/' + job.id)
      if (result.status === 'submitted') { status.textContent = 'Proof submitted. Return to the original OPS tab and confirm this identity. To switch identities, sign out in OPS and start a new login.'; break }
      if (result.status === 'failed' || Date.now() >= deadline) throw Error('Proof could not be submitted. Check that the selected persona matches the OPS profile, then start a fresh login request.')
    }
  } catch (error) { status.textContent = error.message }
  finally { active = false; submit.disabled = false }
})
