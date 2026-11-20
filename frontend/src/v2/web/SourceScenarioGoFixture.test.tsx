import '@testing-library/jest-dom/vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { webcrypto } from 'node:crypto'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceScenario } from './SourceScenario'
import { loadSavedSourcePackage } from './sourceProject'
const mocks = vi.hoisted(() => ({ download: vi.fn() }))
vi.mock('./SourceReview', () => ({ download: mocks.download }))
afterEach(() => { cleanup(); vi.unstubAllGlobals(); mocks.download.mockReset() })
// Explicit offline acceptance gate: first run SourceAuthoringExport with its
// fixture directory, then native unpack/prepare/check/simulate in that directory.
for (const [scenarioFile, reportFile] of [['authoring-scenario.json', 'authoring-simulation-report.json'], ['authoring-scenario-unknown-signer.json', 'authoring-unknown-signer-report.json'], ['authoring-signer-present-scenario.json', 'authoring-signer-present-report.json']]) it.runIf(!!process.env.OPS_AUTHORING_GO_REPORT_DIR)(`imports the actual Go simulation of ${scenarioFile} with exact byte binding`, async () => {
  vi.stubGlobal('crypto', webcrypto)
  const directory = resolve(process.env.OPS_AUTHORING_GO_REPORT_DIR!), source = readFileSync(resolve(directory, 'authoring-source-package.json'), 'utf8'), scenario = readFileSync(resolve(directory, scenarioFile), 'utf8'), report = readFileSync(resolve(directory, reportFile), 'utf8'), expected = JSON.parse(report)
  const project = await loadSavedSourcePackage(source), org = project.roots[0].draft.organizations[0].id
  render(<SourceScenario project={project} root={project.roots[0].id} organization={org} check={() => {}} />)
  function file(raw: string) { const file = new File([raw], 'offline.json'); Object.defineProperty(file, 'text', { value: async () => raw }); return file }
  fireEvent.change(screen.getByLabelText('Import hypothetical scenario'), { target: { files: [file(scenario)] } }); await waitFor(() => expect(screen.getByLabelText('Hypothetical signer')).toHaveValue(JSON.parse(scenario).context.Signer ?? ''))
  await userEvent.click(screen.getByRole('button', { name: 'Export policy scenario' })); await waitFor(() => expect(mocks.download).toHaveBeenCalledTimes(1)); expect(mocks.download.mock.calls[0][1]).toBe(scenario)
  fireEvent.change(screen.getByLabelText('Selected prepared manifest digest'), { target: { value: expected.manifestDigest } }); fireEvent.change(screen.getByLabelText('Go scenario result'), { target: { files: [file(report)] } })
  expect(await screen.findByText(`Conditional ${expected.decision.Allowed ? 'allow' : 'deny'}${expected.decision.Code ? ': ' + expected.decision.Code : ''}`)).toBeInTheDocument()
  expect(screen.getByText('Imported local result')).toBeInTheDocument()
})
