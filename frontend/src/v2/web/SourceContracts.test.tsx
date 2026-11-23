import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceContracts } from './SourceContracts'
import { fixtureDocuments, fixtureProject, org, contractID, address } from './configurationFixtures.test-support'
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
it('retains dedicated readonly columns, address copy, ABI signatures and collapsed raw source', async () => {
 const project=await fixtureProject(); render(<SourceContracts project={project} root="source" organization={org} />)
 for(const name of ['Address','Name','ABI','Read groups','Execution rules']) expect(screen.getByRole('columnheader',{name})).toBeInTheDocument()
 expect(screen.getByRole('button',{name:'Copy address '+address})).toBeInTheDocument()
 await userEvent.click(screen.getByRole('button',{name:/^ABI ·/})); const dialog=screen.getByRole('dialog')
 expect(within(dialog).getByText('transfer(address,uint256)')).toBeInTheDocument(); expect(within(dialog).getByText('0xa9059cbb')).toBeInTheDocument()
 const details=within(dialog).getByText('Advanced public ABI JSON').closest('details')!; expect(details).not.toHaveAttribute('open')
 expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument(); expect(screen.queryByRole('button',{name:/Register contract|Edit contract|Save/})).not.toBeInTheDocument()
})
it('filters contracts by name/address and retains named linkage and read group metadata', async () => {
 const project=await fixtureProject(); render(<SourceContracts project={project} root="source" organization={org} />)
 expect(screen.getByRole('link',{name:'1 source rules'})).toHaveAttribute('href','/admin/rbac/execution-policy?org='+org)
 fireEvent.change(screen.getByLabelText('Search contracts'),{target:{value:'missing'}}); expect(screen.getByText('No matching contracts')).toBeInTheDocument()
 await userEvent.click(screen.getByRole('button',{name:'Clear search'})); await userEvent.click(screen.getByRole('button',{name:'Read grants'}))
 expect(screen.getByRole('dialog')).toHaveTextContent('Reader'); expect(screen.getByRole('dialog')).toHaveTextContent('Read grants control history eligibility')
})
it('rederives an open inspector by stable contract ID, and never reopens a removed inspector', async () => {
 const first=await fixtureProject(), docs=fixtureDocuments(), registry=docs['registry.json']
 const pane=render(<SourceContracts project={first} root="source" organization={org} />)
 await userEvent.click(screen.getByRole('button',{name:'Vault'}))
 const updated=await fixtureProject({'registry.json':{...registry,spec:{contracts:registry.spec.contracts.map(c=>({...c,name:'Vault refreshed'}))}}})
 pane.rerender(<SourceContracts project={updated} root="source" organization={org} />); expect(screen.getByRole('dialog')).toHaveTextContent('Vault refreshed')
 const removed=await fixtureProject({'registry.json':{...registry,spec:{contracts:[]}}}); pane.rerender(<SourceContracts project={removed} root="source" organization={org} />)
 expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); pane.rerender(<SourceContracts project={first} root="source" organization={org} />); expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
 expect(first.roots[0].files.find(f=>f.path==='registry.json')?.originalText).toContain(contractID)
})
it('retains contract keyset-free local paging and resets filtered pages without revealing unrelated fields',async()=>{
 const docs=fixtureDocuments(),registry=docs['registry.json'],contracts=Array.from({length:28},(_,i)=>({...registry.spec.contracts[0],id:i.toString(16).padStart(8,'0')+'-aaaa-4aaa-8aaa-aaaaaaaaaaaa',name:'Vault '+String(i).padStart(2,'0'),address:'0x'+i.toString(16).padStart(40,'0'),privateNote:'do not search note'}))
 const project=await fixtureProject({'registry.json':{...registry,spec:{contracts}}});render(<SourceContracts project={project} root="source" organization={org} />)
 expect(screen.getByText('Showing 1–25 of 28')).toBeInTheDocument();await userEvent.click(screen.getByRole('button',{name:'Next'}));expect(screen.getByText('Showing 26–28 of 28')).toBeInTheDocument();expect(screen.getByRole('button',{name:'Vault 27'})).toBeInTheDocument()
 fireEvent.change(screen.getByLabelText('Search contracts'),{target:{value:'do not search note'}});expect(screen.getByText('No matching contracts')).toBeInTheDocument();await userEvent.click(screen.getByRole('button',{name:'Clear search'}));expect(screen.getByText('Showing 1–25 of 28')).toBeInTheDocument();expect(screen.getByRole('button',{name:'Vault 00'})).toBeInTheDocument()
})
