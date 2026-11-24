import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, useNavigate } from 'react-router-dom'
import { NativeAdminApp } from './AdminApp'
import { Controller, State } from './controller'
import { WalletController } from './wallet'
import { CONTEXT_KEY } from '../auth/context'
import { activeMulti, deniedMulti, readMultiMarker, writeMultiMarker } from '../auth/multiContext'
import { fixtureDocuments, fixtureEnvelope, org } from './configurationFixtures.test-support'
const protectedRenders=vi.hoisted(()=>[] as boolean[])
vi.mock('./NativeOperationsPages',()=>({NativeOperationsPage:({state}:{state:State})=>{protectedRenders.push(state.self!.organizations.some(o=>o.isOrgAdmin||o.isOrgReadonlyAdmin));return <p>Operational page fixture</p>}}))
const family='33333333-3333-4333-8333-333333333333'
const initial=():State=>({phase:'selected',busy:false,flow:null,pending:null,candidate:null,error:null,profiles:[{id:'bank',provider:'privado',principalKind:'human'}],self:{actorId:'ops:p1:'+'A'.repeat(43),principalKind:'human',sourceProfile:'bank',sourceProfileDigest:'sha256:'+'a'.repeat(64),expiresAt:Math.floor(Date.now()/1000)+300,organizations:[{id:org,name:'Serving Bank',slug:'live-bank',isOrgAdmin:true,isOrgReadonlyAdmin:false}]}})
async function harness(path='/admin/rbac/organizations',override?:State) {
 let state=override??initial(),revision=0,tag='"'+'a'.repeat(64)+'"',value=await fixtureEnvelope()
 let navigate:ReturnType<typeof useNavigate>
 function Probe(){navigate=useNavigate();return null}
 const subscribers=new Set<()=>void>(),notify=()=>subscribers.forEach(f=>f())
 localStorage.clear();sessionStorage.clear();writeMultiMarker(state.self?activeMulti({actorId:state.self.actorId,sourceProfile:state.self.sourceProfile,browserSessionId:family,provider:'privado'}):deniedMulti())
 const list={sources:[{id:'current',label:'Current'}]}
 const request=vi.fn(async(endpoint:string,_options?:RequestInit):Promise<unknown>=>endpoint.endsWith('/sources')?list:{notModified:false,etag:tag,value})
 const mock={snapshot:()=>state,subscribe:(fn:()=>void)=>{subscribers.add(fn);return()=>{subscribers.delete(fn)}},get scopeRevision(){return revision},
  ownsScope:vi.fn((scope:number,actor:string)=>{const marker=readMultiMarker();return scope===revision&&state.phase==='selected'&&!state.flow&&!state.pending&&state.self?.actorId===actor&&state.self.expiresAt*1000>Date.now()&&marker?.phase==='active'&&marker.browserSessionId===family&&marker.actorId===actor&&marker.sourceProfile===state.self.sourceProfile}),
  logout:vi.fn(async()=>{revision++;state={...state,phase:'anonymous',self:null};writeMultiMarker(deniedMulti());notify()}),refresh:vi.fn(),downloadOwnWalletToken:vi.fn(),copyOwnRPCCredential:vi.fn(async()=>true),
  wallet:new WalletController(async()=>{throw Error('no wallet operation requested')}),captureOperations:vi.fn(async(signal:AbortSignal)=>{
   const rev=revision,self=state.self!;const check=()=>{if(signal.aborted||state.self!==self||!mock.ownsScope(rev,self.actorId))throw Error('retired ownership')}
   return {self,identity:{actor:self.actorId,expires:self.expiresAt},signal,check,request:async<T,>(endpoint:string,options?:RequestInit)=>{check();const result=await request(endpoint,options);check();return result as T},dispose:vi.fn()}
  })}
 const pane=render(<MemoryRouter initialEntries={[path]}><Probe/><NativeAdminApp controller={mock as unknown as Controller}/></MemoryRouter>)
 return {...pane,mock,request,list,navigate:(path:string)=>act(()=>navigate(path)),state:()=>state,
  replace:(next:State)=>act(()=>{revision++;state=next;writeMultiMarker(next.self?activeMulti({actorId:next.self.actorId,sourceProfile:next.self.sourceProfile,browserSessionId:family,provider:'privado'}):deniedMulti());notify()}),
  source:(next:typeof value)=>{value=next;tag='"'+'b'.repeat(64)+'"'},refresh:async()=>{await userEvent.click(screen.getByRole('button',{name:'Refresh',exact:true}));await waitFor(()=>expect(screen.getByRole('button',{name:'Refresh',exact:true})).toBeEnabled())}}
}
afterEach(()=>{cleanup();protectedRenders.length=0;vi.unstubAllGlobals();vi.useRealTimers();Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'})})
describe('file-backed read-only Admin',()=>{
 it('uses real source organization/group views with preserved permission colors and no authoring controls',async()=>{
  const h=await harness();await screen.findByText('Bank',{exact:true});expect(screen.getByTestId('admin-nav')).toBeInTheDocument()
  await userEvent.click(screen.getByText('Bank',{exact:true}));await userEvent.click(screen.getAllByTitle('View declared permissions')[0])
  expect(screen.getByRole('dialog')).toHaveTextContent('Deployer');expect(within(screen.getByRole('dialog')).getByRole('checkbox',{name:'Deploy contracts'})).toBeChecked()
  expect(screen.queryByRole('button',{name:/Edit local|Save draft|New organization|Review & export|Open saved/})).not.toBeInTheDocument();expect(document.querySelector('input[type=file]')).toBeNull()
  expect(h.request.mock.calls.every(([,options])=>options?.method===undefined||options.method==='GET')).toBe(true)
 })
 it('groups configuration tabs under RBAC and preserves the selected folder across identity and settings navigation',async()=>{
  const h=await harness();await screen.findByText('Bank',{exact:true})
  expect(within(screen.getByTestId('rbac-tabs')).getAllByRole('tab').map(t=>t.textContent)).toEqual(['Organizations','Groups','Contracts','Execution Policy','Source files'])
  await userEvent.click(screen.getByRole('tab',{name:'Identity'}));expect(screen.getByTestId('identity-tabs')).toHaveTextContent('Profiles');await screen.findByRole('button',{name:'bank-staff'})
  expect(screen.getByTestId('configuration-source-current')).toHaveAttribute('aria-selected','true');await userEvent.click(screen.getByRole('tab',{name:'Claim mappings'}));expect(screen.getByText('staff-reader')).toBeInTheDocument()
  await userEvent.click(screen.getByRole('link',{name:'Settings'}));expect(screen.getByTestId('configuration-source-current')).toHaveAttribute('aria-selected','true');expect(screen.queryByText('Review & export')).not.toBeInTheDocument();h.unmount()
 })
 it('retains the broker root and reopens current raw bytes when external source updates',async()=>{
  const envelope=await fixtureEnvelope(),h=await harness('/admin/configuration');await screen.findByTestId('workspace-source')
  expect(screen.getByText('Raw configuration behind the Organizations, Groups, Contracts and Policies views.')).toBeInTheDocument()
  const multi={...envelope,roots:[{...envelope.roots[0],id:'core'},{...structuredClone(envelope.roots[0]),id:'broker'}]};h.source(multi);await h.refresh()
  fireEvent.change(screen.getByLabelText('Source root'),{target:{value:'broker'}});await userEvent.click(screen.getByRole('button',{name:'groups.json'}));expect(screen.getByLabelText('Source groups.json')).toHaveTextContent('Deployer')
  const next=structuredClone(multi);next.roots[1].files.find(f=>f.path==='groups.json')!.dataBase64=btoa(atob(next.roots[1].files.find(f=>f.path==='groups.json')!.dataBase64).replace('Deployer','Updated broker group'))
  h.source(next);await h.refresh();expect(screen.getByLabelText('Source root')).toHaveValue('broker');expect(screen.getByLabelText('Source groups.json')).toHaveTextContent('Updated broker group')
  expect(screen.getByText(/Core contains access rules and policies/)).toBeInTheDocument()
  h.navigate('/admin/rbac/organizations');await screen.findByText('Bank',{exact:true});expect(screen.queryByLabelText('Source root')).not.toBeInTheDocument()
  h.navigate('/admin/rbac/contracts');expect(screen.queryByLabelText('Source root')).not.toBeInTheDocument()
  h.navigate('/admin/configuration');expect(screen.getByLabelText('Source root')).toHaveValue('broker')
 })
 it('does not show a root selector for a single source',async()=>{
  const h=await harness('/admin/configuration');await screen.findByTestId('workspace-source');expect(screen.queryByLabelText('Source root')).not.toBeInTheDocument();h.unmount()
 })
 it('shows runtime and broker settings from their respective roots',async()=>{
  const docs=fixtureDocuments(), core=await fixtureEnvelope({'draft.json':{...docs['draft.json'],runtimeCatalog:{path:'runtime.json'}},'runtime.json':{apiVersion:'ops.runtime-policy/v1alpha1',kind:'RuntimePolicy',readProfile:'demo-read'}})
  const broker=await fixtureEnvelope({'draft.json':{...docs['draft.json'],authCatalog:{path:'auth.json'}},'auth.json':{apiVersion:'ops.auth-broker/v1alpha1',kind:'AuthBroker',issuerId:'demo-issuer'}})
  const h=await harness('/admin/settings');h.source({...core,roots:[{...core.roots[0],id:'core'},{...broker.roots[0],id:'broker'}]});await h.refresh()
  expect(screen.getByText('demo-read')).toBeInTheDocument();fireEvent.change(screen.getByLabelText('Source root'),{target:{value:'broker'}})
  expect(screen.getByText('demo-issuer')).toBeInTheDocument();expect(screen.getByText('Authentication broker')).toBeInTheDocument();expect(screen.queryByText(/no runtime policy document/i)).not.toBeInTheDocument()
 })
 it('offers distinct identity catalogs even when one is named broker',async()=>{
  const docs=fixtureDocuments(), core=await fixtureEnvelope(), broker=await fixtureEnvelope({'identity.json':{...docs['identity.json'],profiles:[{...docs['identity.json'].profiles[0],id:'broker-staff'}]}})
  const h=await harness('/admin/identity/profiles');h.source({...core,roots:[{...core.roots[0],id:'core'},{...broker.roots[0],id:'broker'}]});await h.refresh()
  expect(screen.getByRole('button',{name:'bank-staff'})).toBeInTheDocument();fireEvent.change(screen.getByLabelText('Source root'),{target:{value:'broker'}});expect(screen.getByRole('button',{name:'broker-staff'})).toBeInTheDocument()
 })
 it('offers roots with organizations even when they have no documents',async()=>{
  const docs=fixtureDocuments(), core=await fixtureEnvelope(), other=await fixtureEnvelope({'draft.json':{...docs['draft.json'],organizations:[{id:org,slug:'other',name:'Other Bank'}],documents:[]}})
  const h=await harness('/admin/rbac/organizations');await screen.findByText('Bank',{exact:true});h.source({...core,roots:[{...core.roots[0],id:'core'},{...other.roots[0],id:'other',files:other.roots[0].files.filter(f=>['draft.json','identity.json'].includes(f.path))}]});await h.refresh()
  fireEvent.change(screen.getByLabelText('Source root'),{target:{value:'other'}});expect(screen.getByText('Other Bank',{exact:true})).toBeInTheDocument()
 })
 it('clears a removed selected folder and does not auto-select the remaining folder or its later reappearance',async()=>{
  const h=await harness();await screen.findByText('Bank',{exact:true});h.list.sources.push({id:'other',label:'Other'});await h.refresh();h.list.sources.shift();await h.refresh()
  expect(screen.queryByText('Bank',{exact:true})).not.toBeInTheDocument();expect(screen.getByTestId('configuration-source-other')).toHaveAttribute('aria-selected','false')
  h.list.sources.push({id:'current',label:'Current'});await h.refresh();expect(screen.getByTestId('configuration-source-current')).toHaveAttribute('aria-selected','false')
 })
 it.each(['groups','contract','execution','compliance','nestedCalls'])('keeps unsupported %s source readable while refusing misleading structured permissions',async kind=>{
  const docs=fixtureDocuments();let route='/admin/rbac/groups?org='+org,overrides:Record<string,unknown>={}
  if(kind==='groups')overrides['groups.json']={...docs['groups.json'],spec:{groups:docs['groups.json'].spec.groups.map(g=>({...g,isOrgAdmin:'true'}))}}
  if(kind==='contract'){route='/admin/rbac/contracts?org='+org;overrides['registry.json']={...docs['registry.json'],spec:{contracts:docs['registry.json'].spec.contracts.map(c=>({...c,allowVisibleToUnlock:'true'}))}}}
  if(kind==='execution'){route='/admin/rbac/execution-policy?org='+org;overrides['execution.json']={...docs['execution.json'],spec:{policy:{...docs['execution.json'].spec.policy,bindings:[{group:'g',allow:{}}]}}}}
  if(kind==='nestedCalls'){route='/admin/rbac/execution-policy?org='+org;overrides['execution.json']={...docs['execution.json'],spec:{policy:{...docs['execution.json'].spec.policy,nestedCalls:'inherit'}}}}
  if(kind==='compliance'){route='/admin/compliance/policy?org='+org;overrides={'draft.json':{...docs['draft.json'],complianceCatalog:{path:'compliance.json'}},'compliance.json':{apiVersion:'ops.compliance-policy/v1alpha1',kind:'CompliancePolicy',organizations:[{organizationId:org,spec:{settings:{enabled:'true'},tokenPrices:[],addressThresholds:[]}}],sanctions:[]}}}
  const h=await harness(route);h.source(await fixtureEnvelope(overrides));const spy=vi.spyOn(console,'error').mockImplementation(()=>{})
  await h.refresh();if(kind==='nestedCalls')await screen.findByRole('status');else await screen.findByRole('alert');expect(screen.getByRole('button',{name:'View source files'})).toBeInTheDocument();await userEvent.click(screen.getByRole('button',{name:'View source files'}))
  const file=kind==='groups'?'groups.json':kind==='contract'?'registry.json':kind==='execution'||kind==='nestedCalls'?'execution.json':'compliance.json';await userEvent.click(screen.getByRole('button',{name:file}));expect(screen.getByLabelText('Source '+file)).toHaveTextContent(kind==='execution'?'"allow":{}':kind==='nestedCalls'?'"nestedCalls":"inherit"':'"true"');spy.mockRestore()
 })
 it('keeps unsafe numbers as exact raw text without rendering a rounded permission value',async()=>{
  const h=await harness('/admin/rbac/execution-policy?org='+org),envelope=await fixtureEnvelope(),f=envelope.roots[0].files.find(f=>f.path==='execution.json')!;f.dataBase64=btoa(atob(f.dataBase64).replace('"maxDepth":1','"maxDepth":9007199254740993'));h.source(envelope);await h.refresh()
  expect(screen.getByRole('status')).toHaveTextContent('cannot be displayed exactly');await userEvent.click(screen.getByRole('button',{name:'View source files'}));await userEvent.click(screen.getByRole('button',{name:'execution.json'}));expect(screen.getByLabelText('Source execution.json')).toHaveTextContent('9007199254740993')
 })
 it('clears confidential source and open dialogs on an account replacement, renewal boundary or page departure',async()=>{
  const h=await harness();await screen.findByText('Bank',{exact:true});await userEvent.click(screen.getByText('Bank',{exact:true}));await userEvent.click(screen.getAllByTitle('View declared permissions')[0]);h.replace({...h.state(),phase:'proof-pending',self:null})
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument();h.replace(initial());await screen.findByText('Bank',{exact:true});act(()=>window.dispatchEvent(new Event('pagehide')));expect(screen.queryByText('Bank',{exact:true})).not.toBeInTheDocument()
 })
 it('does not retain folder data after another tab changes the verified session marker',async()=>{
  await harness();await screen.findByText('Bank',{exact:true});act(()=>{writeMultiMarker(deniedMulti());window.dispatchEvent(new StorageEvent('storage',{key:CONTEXT_KEY}))})
  expect(screen.queryByText('Bank',{exact:true})).not.toBeInTheDocument();expect(screen.queryByTestId('workspace-source')).not.toBeInTheDocument()
 })
 it('keeps the own-account/wallet page available without organization admin roles',async()=>{
  const state=initial();state.self={...state.self!,organizations:[]};await harness('/admin/account',state)
  expect(screen.getByTestId('account-identity')).toHaveTextContent(state.self.actorId);expect(screen.getByRole('button',{name:'Refresh session'})).toBeEnabled();expect(screen.getByRole('heading',{name:'Linked Addresses'})).toBeInTheDocument();expect(screen.getByTestId('account-organizations')).toHaveTextContent('No organizations');expect(screen.queryByTestId('admin-nav')).not.toBeInTheDocument()
 })
 it.each(['/admin','/admin/rbac','/admin/rbac/organizations','/admin/rbac/configuration','/admin/configuration','/admin/identity/profiles','/admin/identity/claim-mappings','/admin/settings','/admin/disclosure/rules','/admin/compliance/policy','/admin/compliance','/admin/disclosure','/disclosures','/admin/logs','/admin/diagnostics'])('denies member console entry at%s without mounting or fetching protected content',async path=>{
  const state=initial();state.self!.organizations[0].isOrgAdmin=false;const h=await harness(path,state)
  expect(screen.getByRole('heading',{name:'Access Denied'})).toBeInTheDocument();expect(screen.queryByTestId('admin-nav')).not.toBeInTheDocument();expect(screen.queryByText('Operational page fixture')).not.toBeInTheDocument();expect(h.mock.captureOperations).not.toHaveBeenCalled()
  await userEvent.click(screen.getByRole('button',{name:'Go to your account'}));expect(screen.getByTestId('account-identity')).toBeInTheDocument();expect(h.request).not.toHaveBeenCalled()
 })
 it('allows verified readonly admins to inspect external configuration without editing controls',async()=>{
  const state=initial();state.self!.organizations[0].isOrgAdmin=false;state.self!.organizations[0].isOrgReadonlyAdmin=true;await harness('/admin/rbac/organizations',state);await screen.findByText('Bank',{exact:true});expect(screen.queryByRole('button',{name:/Edit|Save|New organization|Export/})).not.toBeInTheDocument()
 })
 it('never renders a protected operational subtree after the same identity loses admin roles',async()=>{
  const h=await harness('/admin/compliance');expect(screen.getByText('Operational page fixture')).toBeInTheDocument();const state=initial();state.self!.organizations[0].isOrgAdmin=false;h.replace(state);expect(screen.getByRole('heading',{name:'Access Denied'})).toBeInTheDocument();expect(protectedRenders.every(Boolean)).toBe(true)
 })
 it.each([['Copy access token','token'],['Copy Authorization header','header'],['Copy for Foundry','foundry']] as const)('keeps explicit Account credential action%s',async(label,format)=>{
  const h=await harness('/admin/account');await userEvent.click(screen.getByRole('button',{name:label}));expect(h.mock.copyOwnRPCCredential).toHaveBeenCalledWith(format);expect(screen.getByRole('button',{name:'Copied'})).toBeInTheDocument()
 })
})
it('polls visible configurations, pauses while hidden or on operational pages, and refreshes on focus',async()=>{
 vi.useFakeTimers();const h=await harness();await act(async()=>{await vi.advanceTimersByTimeAsync(0)});expect(screen.getByText('Bank',{exact:true})).toBeInTheDocument()
 const before=h.mock.captureOperations.mock.calls.length
 await act(async()=>{await vi.advanceTimersByTimeAsync(2000)});expect(h.mock.captureOperations.mock.calls.length).toBe(before+1)
 Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'})
 await act(async()=>{await vi.advanceTimersByTimeAsync(4000)});expect(h.mock.captureOperations.mock.calls.length).toBe(before+1)
 Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'})
 await act(async()=>{window.dispatchEvent(new Event('focus'));await Promise.resolve()});expect(h.mock.captureOperations.mock.calls.length).toBe(before+2)
 h.navigate('/admin/compliance');await act(async()=>{await vi.advanceTimersByTimeAsync(4000)});expect(h.mock.captureOperations.mock.calls.length).toBe(before+2)
 vi.useRealTimers()
})
