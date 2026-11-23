import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceRecords } from './SourceRecords'
afterEach(cleanup)
it('displays configured nested fact and event permissions in details without editing controls', async () => {
 render(<SourceRecords title="Permissions" records={[{id:'mapping',fact:{kind:'azure.role',value:'payments'},eventRules:{mode:'allowlist',rules:[{topic0:'topic',name:'Paid'}]}}]} fields={[{key:'fact.kind',label:'Fact kind'},{key:'fact.value',label:'Fact value'},{key:'eventRules.mode',label:'Event mode'},{key:'eventRules.rules',label:'Event rules',kind:'json'}]} />)
 expect(screen.getByText('Fact kind: azure.role')).toBeInTheDocument(); await userEvent.click(screen.getByRole('button',{name:'mapping'}))
 const dialog=screen.getByRole('dialog'); expect(within(dialog).getByText('azure.role')).toBeInTheDocument(); expect(within(dialog).getByText('allowlist')).toBeInTheDocument()
 const details=within(dialog).getByText('Show event rules').closest('details')!; expect(details).not.toHaveAttribute('open'); await userEvent.click(within(details).getByText('Show event rules')); expect(within(details).getByText(/"name": "Paid"/)).toBeVisible()
 expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument(); expect(within(dialog).queryByRole('button',{name:/Save|Edit|Remove/})).not.toBeInTheDocument()
})
it('closes an inspector when its formerly unique stable ID becomes ambiguous or disappears',async()=>{
 const fields=[{key:'name',label:'Name'}],row={id:'stable',name:'Original'}
 const pane=render(<SourceRecords title="Profiles" records={[row]} fields={fields} />);await userEvent.click(screen.getByRole('button',{name:'Original'}))
 pane.rerender(<SourceRecords title="Profiles" records={[{...row,name:'Changed'}]} fields={fields} />);expect(screen.getByRole('dialog')).toHaveTextContent('Changed')
 const spy=vi.spyOn(console,'error').mockImplementation(()=>{});pane.rerender(<SourceRecords title="Profiles" records={[row,{...row,name:'Duplicate'}]} fields={fields} />);expect(screen.queryByRole('dialog')).not.toBeInTheDocument();pane.rerender(<SourceRecords title="Profiles" records={[row]} fields={fields} />);expect(screen.queryByRole('dialog')).not.toBeInTheDocument();spy.mockRestore()
})
it('closes an idless catalog inspector on a new observation instead of rebinding an array position',async()=>{
 const {SourceViewProvider}=await import('./sourceViewState'),viewer={setViewState:vi.fn()} as unknown as import('./configurationViewer').ConfigurationViewer
 const view={sources:[],selected:'current',project:null,busy:false,error:null,observation:1,viewState:{}}
 const row={url:'https://context.example',path:'context.json'},fields=[{key:'url',label:'Context URL'}]
 const pane=render(<SourceViewProvider viewer={viewer} view={view}><SourceRecords title="Pins" records={[row]} fields={fields}/></SourceViewProvider>);await userEvent.click(screen.getByRole('button',{name:row.url}));expect(screen.getByRole('dialog')).toBeInTheDocument()
 pane.rerender(<SourceViewProvider viewer={viewer} view={{...view,observation:2}}><SourceRecords title="Pins" records={[{...row,url:'https://other.example'}]} fields={fields}/></SourceViewProvider>);expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
 pane.rerender(<SourceViewProvider viewer={viewer} view={{...view,observation:3}}><SourceRecords title="Pins" records={[row]} fields={fields}/></SourceViewProvider>);expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})
