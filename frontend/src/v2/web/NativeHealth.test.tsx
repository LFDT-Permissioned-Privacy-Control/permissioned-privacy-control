import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { NativeHealth, parseHealth } from './NativeHealth'
import type { OperationScope } from './controller'

const org='11111111-1111-4111-8111-111111111111',other='22222222-2222-4222-8222-222222222222',member='33333333-3333-4333-8333-333333333333'
function response(organizationId=org,version='v2.0.0') {
  const at=new Date().toISOString()
  return {organizationId,build:{version,commit:'abcdef012345',builtAt:'2026-11-20T12:00:00Z'},process:'running',observedAt:at,readiness:{state:'unavailable',sampledAt:at},node:{state:'connected',sampledAt:at,latencyMs:12}}
}
function scope() {
  const request=vi.fn(async(_path:string,_options?:RequestInit):Promise<unknown>=>response())
  return {identity:{actor:'ops:p1:'+'A'.repeat(43),expires:Date.now()/1000+300},signal:new AbortController().signal,request,check:vi.fn(),self:{organizations:[{id:org,name:'Bank A',isOrgAdmin:true,isOrgReadonlyAdmin:false},{id:other,name:'Bank B',isOrgAdmin:false,isOrgReadonlyAdmin:true},{id:member,name:'Member bank',isOrgAdmin:false,isOrgReadonlyAdmin:false}]}} as unknown as OperationScope & {request:typeof request}
}
afterEach(()=>{cleanup();vi.restoreAllMocks();vi.useRealTimers()})
it.each(['1','123456','123456789'])('accepts actual Go RFC3339Nano timestamp precision %s without requiring JavaScript milliseconds',fraction=>{
  const value=response(),at=`2027-01-15T08:00:00.${fraction}Z`
  value.observedAt=at;value.readiness.sampledAt=at;value.node.sampledAt=at
  expect(parseHealth(value,org).node.sampledAt).toBe(at)
})
it('keeps failed operational readiness distinct from a measured connected own node and shows safe build identity',async()=>{
  const s=scope();render(<MemoryRouter initialEntries={['/?org='+org]}><NativeHealth scope={s}/></MemoryRouter>)
  await screen.findByText('v2.0.0')
  expect(within(screen.getByText('Operational readiness (sampled)').closest('.group')!).getByText('Unavailable')).toBeInTheDocument()
  expect(within(screen.getByText('Blockchain node (sampled)').closest('.group')!).getByText('Connected')).toBeInTheDocument()
  expect(screen.getByText('abcdef012345')).toBeInTheDocument();expect(screen.getByText('12ms')).toBeInTheDocument()
  expect(screen.getByLabelText('Health organization')).not.toHaveTextContent('Member bank')
  expect(s.request).toHaveBeenCalledWith(`/api/v2/orgs/${org}/diagnostics`,expect.objectContaining({signal:expect.any(AbortSignal)}))
})
it('does not infer a connected node from healthy operational readiness',async()=>{
  const s=scope(),value=response();value.readiness.state='ready';value.node={state:'unknown'} as typeof value.node;s.request.mockResolvedValue(value)
  render(<MemoryRouter initialEntries={['/?org='+org]}><NativeHealth scope={s}/></MemoryRouter>)
  await screen.findByText('v2.0.0')
  expect(screen.getByText('Operational readiness (sampled)').closest('.group')!.querySelector('.status-dot-success')).not.toBeNull()
  expect(within(screen.getByText('Blockchain node (sampled)').closest('.group')!).getByText('Unknown')).toBeInTheDocument()
  expect(screen.queryByText('Connected')).not.toBeInTheDocument();expect(screen.queryByText('12ms')).not.toBeInTheDocument()
})
it('aborts and fences a delayed prior-organization health sample',async()=>{
  const s=scope();let finish!:(value:unknown)=>void,oldSignal:AbortSignal|undefined
  const pending=new Promise<unknown>(resolve=>{finish=resolve})
  s.request.mockImplementation(async(path,options)=>{if(path.includes(org)){oldSignal=options?.signal??undefined;return pending};return response(other,'v2.0.1')})
  render(<MemoryRouter initialEntries={['/?org='+org]}><NativeHealth scope={s}/></MemoryRouter>)
  await waitFor(()=>expect(oldSignal).toBeDefined())
  fireEvent.change(screen.getByLabelText('Health organization'),{target:{value:other}})
  await screen.findByText('v2.0.1');expect(oldSignal!.aborted).toBe(true)
  await act(async()=>{finish(response(org,'STALE-BUILD'));await pending})
  expect(screen.queryByText('STALE-BUILD')).not.toBeInTheDocument()
})
it('fences a pending health response after the original role scope is replaced',async()=>{
  const s=scope();let finish!:(value:unknown)=>void;const pending=new Promise<unknown>(resolve=>{finish=resolve});s.request.mockReturnValue(pending)
  const view=render(<MemoryRouter initialEntries={['/?org='+org]}><NativeHealth scope={s}/></MemoryRouter>)
  await waitFor(()=>expect(s.request).toHaveBeenCalled())
  const replaced=scope();replaced.self.organizations=[]
  view.rerender(<MemoryRouter initialEntries={['/?org='+org]}><NativeHealth scope={replaced}/></MemoryRouter>)
  await act(async()=>{finish(response(org,'OLD-PRIVATE-BUILD'));await pending})
  expect(screen.queryByText('OLD-PRIVATE-BUILD')).not.toBeInTheDocument()
  expect(replaced.request).not.toHaveBeenCalled()
})
it('rejects unknown/raw fields and malformed or foreign diagnostics instead of displaying them',()=>{
  for(const value of [{...response(),rpcUrl:'https://secret.node'}, {...response(),organizationId:other}, {...response(),node:{state:'connected',sampledAt:'2099-01-01T00:00:00Z'}}, {...response(),node:{state:'credential failure'}}, {...response(),build:{...response().build,commit:'Bearer SECRET'}}]) expect(()=>parseHealth(value,org)).toThrow()
})
it('polls visible pages every five seconds without overlap, pauses hidden, resumes visible and stops at original expiry',async()=>{
  vi.useFakeTimers();vi.setSystemTime(new Date('2026-11-20T12:00:00Z'))
  let hidden=false;vi.spyOn(document,'hidden','get').mockImplementation(()=>hidden)
  const s=scope();s.identity.expires=Date.now()/1000+16
  let finishSecond!:(value:unknown)=>void,finishThird!:(value:unknown)=>void
  const second=new Promise<unknown>(resolve=>{finishSecond=resolve}),third=new Promise<unknown>(resolve=>{finishThird=resolve})
  s.request.mockResolvedValueOnce(response()).mockReturnValueOnce(second).mockReturnValueOnce(third)
  render(<MemoryRouter initialEntries={['/?org='+org]}><NativeHealth scope={s}/></MemoryRouter>)
  const flush=async()=>{for(let i=0;i<12;i++)await Promise.resolve()}
  await act(flush);expect(s.request).toHaveBeenCalledTimes(1)
  await act(async()=>{vi.advanceTimersByTime(5000);await flush()});expect(s.request).toHaveBeenCalledTimes(2)
  await act(async()=>{vi.advanceTimersByTime(5000);await flush()});expect(s.request).toHaveBeenCalledTimes(2)
  hidden=true;fireEvent(document,new Event('visibilitychange'))
  await act(async()=>{finishSecond(response());await flush();vi.advanceTimersByTime(5000);await flush()});expect(s.request).toHaveBeenCalledTimes(2)
  hidden=false;fireEvent(document,new Event('visibilitychange'));await act(flush);expect(s.request).toHaveBeenCalledTimes(3)
  await act(async()=>{vi.advanceTimersByTime(1000);finishThird(response(org,'EXPIRED-BUILD'));await flush();vi.advanceTimersByTime(10000);await flush()})
  expect(s.request).toHaveBeenCalledTimes(3);expect(screen.queryByText('EXPIRED-BUILD')).not.toBeInTheDocument()
  expect(s.request.mock.calls[2][1]!.signal!.aborted).toBe(true)
  expect(screen.getByRole('button',{name:'Refresh health'})).toBeDisabled();expect(screen.getByText(/original session ended/)).toBeInTheDocument()
})
it('stops polling and clears retained health when the original scope aborts',async()=>{
  vi.useFakeTimers();vi.setSystemTime(new Date('2026-11-20T12:00:00Z'))
  const s=scope(),parent=new AbortController();Object.assign(s,{signal:parent.signal})
  render(<MemoryRouter initialEntries={['/?org='+org]}><NativeHealth scope={s}/></MemoryRouter>)
  await act(async()=>{for(let i=0;i<12;i++)await Promise.resolve()});expect(s.request).toHaveBeenCalledTimes(1)
  await act(async()=>{parent.abort();vi.advanceTimersByTime(15000);for(let i=0;i<12;i++)await Promise.resolve()})
  expect(s.request).toHaveBeenCalledTimes(1);expect(screen.queryByText('v2.0.0')).not.toBeInTheDocument()
})
