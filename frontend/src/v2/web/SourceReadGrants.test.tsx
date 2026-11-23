import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it } from 'vitest'
import { SourceReadGrants } from './SourceReadGrants'
import type { JSONObject } from './sourceProject'
const reader='22222222-2222-4222-8222-222222222222', topic='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
const abi=[{type:'event',name:'Transfer',anonymous:false,inputs:[{name:'from',type:'address',indexed:true},{name:'to',type:'address',indexed:true},{name:'value',type:'uint256',indexed:false}]}]
const group={id:reader,slug:'readers',name:'Bank Readers',isOrgAdmin:false,isOrgReadonlyAdmin:true,allowedMethods:['eth_call'],claims:[]}
const grant={id:'grant',groupId:reader,eventRules:{mode:'allowlist',rules:[{topic0:topic,name:'Transfer',paramRules:[{index:0,must_be:'self'},{index:2,must_be:'0x'+'f'.repeat(64)}]}]}}
const contract=(patch:JSONObject={})=>({id:'contract',name:'Bank token',abi,readGrants:[grant],...patch})
afterEach(cleanup)
it('preserves readonly selected event colors, OR/self, exact large scalar and source group metadata',async()=>{
 render(<SourceReadGrants contract={contract()} groups={[group]} />)
 expect(screen.getByText(/Organization readonly admin role/)).toBeInTheDocument(); await userEvent.click(screen.getByRole('button',{name:'Bank Readers'}))
 const dialog=screen.getByRole('dialog'); expect(within(dialog).getByRole('group',{name:'Event visibility'})).toHaveTextContent('Specific events only')
 expect(within(dialog).getByText('Specific events only').parentElement).toHaveClass('bg-primary-50','text-primary')
 expect(within(dialog).getByText(/any one of its parameter constraints matches \(OR\)/)).toBeInTheDocument(); expect(within(dialog).getByText('Viewer’s linked address (self)')).toBeInTheDocument(); expect(within(dialog).getByText('0x'+'f'.repeat(64))).toBeInTheDocument()
 expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument(); expect(within(dialog).queryByRole('button',{name:/Save|Add|Remove/})).not.toBeInTheDocument()
 expect(within(dialog).getByText('Advanced native read grant JSON').closest('details')).not.toHaveAttribute('open')
})
it('retains unresolved event declarations visibly instead of inventing an ABI match',async()=>{
 const value=contract({readGrants:[{...grant,eventRules:{mode:'allowlist',rules:[{topic0:'0x'+'1'.repeat(64),name:'ExternalEvent',paramRules:[]}]}}]})
 render(<SourceReadGrants contract={value} groups={[group]} />); await userEvent.click(screen.getByRole('button',{name:'Bank Readers'}))
 expect(screen.getByRole('dialog')).toHaveTextContent('This rule does not match an event in the current ABI'); expect(screen.getByRole('dialog')).toHaveTextContent('No constraints · every event with this signature')
})
it('rederives grants by stable ID after updates and closes removed grant inspection',async()=>{
 const pane=render(<SourceReadGrants contract={contract()} groups={[group]} />); await userEvent.click(screen.getByRole('button',{name:'Bank Readers'}))
 pane.rerender(<SourceReadGrants contract={contract({readGrants:[{...grant,eventRules:{mode:'none',rules:[]}}]})} groups={[group]} />); expect(screen.getByRole('dialog')).toHaveTextContent('No events visible')
 pane.rerender(<SourceReadGrants contract={contract({readGrants:[]})} groups={[group]} />); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); pane.rerender(<SourceReadGrants contract={contract()} groups={[group]} />); expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
})
