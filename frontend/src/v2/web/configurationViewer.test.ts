import { afterEach, describe, expect, it, vi } from 'vitest'
import { ConfigurationViewer } from './configurationViewer'
import { OperationHTTPError } from './operationsTransport'
import type { Controller, State } from './controller'
import { fixtureEnvelope, org } from './configurationFixtures.test-support'
const tag='"'+'a'.repeat(64)+'"', nextTag='"'+'b'.repeat(64)+'"'
const initial=():State=>({phase:'selected',busy:false,flow:null,pending:null,candidate:null,error:null,profiles:[],self:{actorId:'ops:p1:'+'A'.repeat(43),principalKind:'human',sourceProfile:'staff',sourceProfileDigest:'sha256:'+'a'.repeat(64),expiresAt:Math.floor(Date.now()/1000)+300,organizations:[{id:org,name:'Serving Bank',slug:'bank',isOrgAdmin:true,isOrgReadonlyAdmin:false}]}})
async function harness() {
 let state=initial(), revision=0, owns=true
 const envelope=await fixtureEnvelope(), list={sources:[{id:'current',label:'Current'}]}
 const request=vi.fn(async(endpoint:string,_options?:RequestInit):Promise<unknown>=>endpoint.endsWith('/sources')?list:{notModified:false,etag:tag,value:envelope})
 const controller={snapshot:()=>state,get scopeRevision(){return revision},ownsScope:()=>owns&&state.phase==='selected'&&!!state.self&&state.self.expiresAt*1000>Date.now(),captureOperations:vi.fn(async(signal:AbortSignal)=>{
  const original=state.self,rev=revision
  const check=()=>{if(signal.aborted||rev!==revision||state.self!==original||!owns||!state.self||state.self.expiresAt*1000<=Date.now())throw Error('retired ownership')}
  return {self:original!,identity:{actor:original!.actorId,expires:original!.expiresAt},signal,check,request:async<T,>(endpoint:string,options?:RequestInit)=>{check();const result=await request(endpoint,options);check();return result as T},dispose:vi.fn()}
 })}
 const viewer=new ConfigurationViewer(controller as unknown as Controller);viewer.setActive(true)
 return {viewer,request,controller,envelope,list,state:()=>state,replace:(next:State,bump=false)=>{state=next;if(bump)revision++;viewer.observe()},lose:()=>{owns=false;viewer.observe()}}
}
afterEach(()=>{vi.useRealTimers()})
describe('authenticated current configuration view',()=>{
 it('opens a single source, retains observation/root state on304 and preserves it across valid updates',async()=>{
  const h=await harness();await h.viewer.refresh();const before=h.viewer.snapshot();expect(before.selected).toBe('current');expect(before.project).not.toBeNull()
  h.viewer.setViewState('/root','broker',before.observation)
  h.request.mockImplementation(async(endpoint)=>endpoint.endsWith('/sources')?h.list:{notModified:true,etag:tag})
  await h.viewer.refresh();expect(h.viewer.snapshot().project).toBe(before.project);expect(h.viewer.snapshot().viewState['/root']).toBe('broker');expect(h.request.mock.lastCall?.[1]?.headers).toEqual({'If-None-Match':tag})
  h.request.mockImplementation(async(endpoint)=>endpoint.endsWith('/sources')?h.list:{notModified:false,etag:nextTag,value:h.envelope})
  await h.viewer.refresh(true);expect(h.viewer.snapshot().project).not.toBe(before.project);expect(h.viewer.snapshot().viewState['/root']).toBe('broker');expect(h.request.mock.lastCall?.[1]?.headers).toEqual({'If-None-Match':tag,'Cache-Control':'no-cache'})
 })
 it('requires an explicit choice among folders and does not silently choose after deletion or reappearance',async()=>{
  const h=await harness();h.list.sources.push({id:'other',label:'Other'});await h.viewer.refresh();expect(h.viewer.snapshot().selected).toBeNull()
  h.viewer.select('current');await vi.waitFor(()=>expect(h.viewer.snapshot().busy).toBe(false));expect(h.viewer.snapshot().project).not.toBeNull()
  h.list.sources.shift();await h.viewer.refresh();expect(h.viewer.snapshot().selected).toBeNull();expect(h.viewer.snapshot().project).toBeNull()
  h.list.sources.push({id:'current',label:'Current'});await h.viewer.refresh();expect(h.viewer.snapshot().selected).toBeNull()
 })
 it.each([400,403,404,503])('clears current source and inspection state on point failure%s',async status=>{
  const h=await harness();await h.viewer.refresh();h.viewer.setViewState('inspection','private-value',h.viewer.snapshot().observation)
  h.request.mockImplementation(async(endpoint)=>{if(endpoint.endsWith('/sources'))return h.list;throw new OperationHTTPError(status,false)})
  await h.viewer.refresh();expect(h.viewer.snapshot().project).toBeNull();expect(h.viewer.snapshot().viewState).toEqual({});expect(h.viewer.snapshot().error).not.toBeNull()
  if(status===403){expect(h.viewer.snapshot().sources).toEqual([]);expect(h.viewer.snapshot().selected).toBeNull()}
  if(status===404){expect(h.viewer.snapshot().sources).toEqual([]);expect(h.viewer.snapshot().selected).toBeNull()}
 })
 it('clears previously authorized folder names and selection when the catalog fails',async()=>{
  const h=await harness();await h.viewer.refresh();h.request.mockRejectedValue(new OperationHTTPError(403,false));await h.viewer.refresh()
  expect(h.viewer.snapshot()).toMatchObject({sources:[],selected:null,project:null,viewState:{}})
 })
 it('clears malformed selected data and rejects an invalid unchanged response',async()=>{
  const h=await harness();await h.viewer.refresh();h.request.mockImplementation(async endpoint=>endpoint.endsWith('/sources')?h.list:{notModified:false,etag:nextTag,value:{roots:[]}})
  await h.viewer.refresh();expect(h.viewer.snapshot().project).toBeNull();expect(h.viewer.snapshot().error).toContain('invalid')
  h.request.mockImplementation(async endpoint=>endpoint.endsWith('/sources')?h.list:{notModified:true,etag:tag});await h.viewer.refresh();expect(h.viewer.snapshot().project).toBeNull();expect(h.viewer.snapshot().error).toContain('invalid')
 })
 it.each(['actor','profile','digest','kind','role','scope','expired','proof','busy','cross-tab'])('clears confidential view on %s ownership loss',async kind=>{
  const h=await harness();await h.viewer.refresh();const state=h.state(),self={...state.self!,organizations:state.self!.organizations.map(o=>({...o}))}
  if(kind==='actor')self.actorId='ops:p1:'+'B'.repeat(43)
  if(kind==='profile')self.sourceProfile='other'
  if(kind==='digest')self.sourceProfileDigest='sha256:'+'b'.repeat(64)
  if(kind==='kind')self.principalKind='service'
  if(kind==='role')self.organizations[0].isOrgAdmin=false
  if(kind==='expired')self.expiresAt=Math.floor(Date.now()/1000)-1
  if(kind==='cross-tab')h.lose();else h.replace({...state,self,...(kind==='proof'?{phase:'proof-pending' as const,self:null}:{}),...(kind==='busy'?{busy:true}:{})},kind==='scope')
  expect(h.viewer.snapshot().project).toBeNull();expect(h.viewer.snapshot().sources).toEqual([]);expect(h.viewer.snapshot().selected).toBeNull()
 })
 it('does not let a delayed old source replace a newer folder, and bounds refresh to one in-flight cycle',async()=>{
  const h=await harness();h.list.sources.push({id:'other',label:'Other'});await h.viewer.refresh()
  let finish!:(value:unknown)=>void
  h.request.mockImplementation(async endpoint=>endpoint.endsWith('/sources')?h.list:endpoint.endsWith('/current')?new Promise(resolve=>{finish=resolve}):{notModified:false,etag:nextTag,value:h.envelope})
  h.viewer.select('current');await vi.waitFor(()=>expect(finish).toBeTypeOf('function'))
  const count=h.controller.captureOperations.mock.calls.length;await h.viewer.refresh();expect(h.controller.captureOperations).toHaveBeenCalledTimes(count)
  h.viewer.select('other');await vi.waitFor(()=>expect(h.viewer.snapshot().project).not.toBeNull());const latest=h.viewer.snapshot().project
  finish({notModified:false,etag:tag,value:h.envelope});await new Promise(resolve=>setTimeout(resolve,0));expect(h.viewer.snapshot().selected).toBe('other');expect(h.viewer.snapshot().project).toBe(latest)
 })
 it('does not publish delayed catalog/source reads after account replacement or suspension',async()=>{
  const h=await harness();let finish!:(value:unknown)=>void;h.request.mockImplementation(()=>new Promise(resolve=>{finish=resolve}))
  const pending=h.viewer.refresh();await vi.waitFor(()=>expect(finish).toBeTypeOf('function'));h.replace({...h.state(),phase:'anonymous',self:null},true);finish(h.list);await pending
  expect(h.viewer.snapshot().sources).toEqual([]);expect(h.viewer.snapshot().project).toBeNull();expect(h.viewer.snapshot().busy).toBe(false)
 })
})
