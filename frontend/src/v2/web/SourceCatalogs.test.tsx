import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceCatalogs } from './SourceCatalogs'
import { fixtureProject, org } from './configurationFixtures.test-support'
afterEach(()=>{cleanup();vi.unstubAllGlobals()})
it('inspects supported public identity fields and named verified-claim mappings without provider or mutation calls',async()=>{
 const fetch=vi.fn();vi.stubGlobal('fetch',fetch); const project=await fixtureProject(), pane=render(<SourceCatalogs project={project} root="source" organization={org} page="identity-profiles" />)
 await userEvent.click(screen.getByRole('button',{name:'bank-staff'})); expect(within(screen.getByRole('dialog')).getByText('Azure tenant ID')).toBeInTheDocument(); expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
 pane.rerender(<SourceCatalogs project={project} root="source" organization={org} page="claim-mappings" />)
 expect(screen.getByText('staff-reader')).toBeInTheDocument(); expect(screen.getByText('payments')).toBeInTheDocument(); expect(screen.getByText(/Reader/)).toBeInTheDocument(); expect(fetch).not.toHaveBeenCalled()
 expect(screen.queryByRole('button',{name:/Add claim|Edit mapping|Remove mapping/})).not.toBeInTheDocument()
})
it('keeps unresolved mapping references visible without silently granting or changing memberships',async()=>{
 const {fixtureDocuments}=await import('./configurationFixtures.test-support'),docs=fixtureDocuments()
 const project=await fixtureProject({'identity.json':{...docs['identity.json'],mappings:[{...docs['identity.json'].mappings[0],profileId:'unknown-profile',groupIds:['unknown-group']}]}})
 render(<SourceCatalogs project={project} root="source" organization={org} page="claim-mappings" />)
 expect(screen.getByText('Unresolved imported profile')).toBeInTheDocument();expect(screen.getByText('unknown-profile')).toBeInTheDocument();expect(screen.getByText(/Unresolved imported group/)).toBeInTheDocument();expect(screen.queryByRole('button',{name:/Remove|Edit/})).not.toBeInTheDocument()
})
it('retains readable compliance prices, threshold overrides and TTLs as configuration content',async()=>{
 const {fixtureDocuments}=await import('./configurationFixtures.test-support'),docs=fixtureDocuments()
 const policy={organizationId:org,recordMaxSeconds:3600,priceMaxAgeSeconds:300,spec:{settings:{enabled:true,thresholdFiat:1000.5,currency:'usd',unknownPricePolicy:'forbidden',enforcementMode:'enforce'},tokenPrices:[{id:'price',tokenAddress:'native',symbol:'ETH',decimals:18,pricesByCurrency:{usd:2450.5},coingeckoId:'ethereum'}],addressThresholds:[{id:'threshold',address:'0x'+'2'.repeat(40),thresholdFiat:0,note:'Corporate override'}]}}
 const project=await fixtureProject({'draft.json':{...docs['draft.json'],complianceCatalog:{path:'compliance.json'}},'compliance.json':{apiVersion:'ops.compliance-policy/v1alpha1',kind:'CompliancePolicy',organizations:[policy],sanctions:[]}})
 render(<SourceCatalogs project={project} root="source" organization={org} page="compliance-source" />)
 expect(screen.getByText('1000.5 USD')).toBeInTheDocument();expect(screen.getByText('USD: 2450.5 (configured)')).toBeInTheDocument();expect(screen.getByText('Override: 0 USD')).toBeInTheDocument();expect(screen.getByText('Corporate override')).toBeInTheDocument();expect(screen.getByText('3600 seconds')).toBeInTheDocument();expect(screen.queryByRole('button',{name:/Add token|Edit compliance/})).not.toBeInTheDocument()
})
