import '@testing-library/jest-dom/vitest'
import {cleanup, render, screen, within} from '@testing-library/react'
import {MemoryRouter} from 'react-router-dom'
import {afterEach, describe, expect, it, vi} from 'vitest'
import {NativeAccountPage} from './AccountPage'
import type {Controller,State} from './controller'
vi.mock('./WalletPanel',()=>({WalletPanel:()=>null}))
afterEach(cleanup)
const org='11111111-1111-1111-1111-111111111111'
const groups=[{id:'22222222-2222-2222-2222-222222222222',name:'Payments team',slug:'payments'}]
function state():State{return {phase:'selected',profiles:[],self:{actorId:'ops:p1:'+'A'.repeat(43),principalKind:'human',sourceProfile:'bank',sourceProfileDigest:'sha256:'+'a'.repeat(64),expiresAt:Math.floor(Date.now()/1000)+300,organizations:[{id:org,name:'Serving Bank',slug:'bank',isOrgAdmin:false,isOrgReadonlyAdmin:false,groups,groupCount:1,groupsTruncated:false}]},flow:null,pending:null,candidate:null,busy:false,error:null}}
const controller={refresh:vi.fn(),logout:vi.fn(),downloadOwnWalletToken:vi.fn()} as unknown as Controller
describe('Account own mapped group display',()=>{
 it('uses the verified own names and existing badge palette without group permission or directory controls',()=>{
  const request=vi.fn();vi.stubGlobal('fetch',request)
  render(<MemoryRouter><NativeAccountPage controller={controller} state={state()}/></MemoryRouter>)
  const own=screen.getByTestId('account-own-groups'),badge=within(own).getByText('Payments team')
  expect(badge.className).toContain('bg-primary-50');expect(badge).toHaveAttribute('title','payments · '+groups[0].id)
  expect(own.querySelector('a,button')).toBeNull();expect(screen.queryByText('admin')).toBeNull();expect(screen.queryByText('KYC Status')).toBeNull();expect(request).not.toHaveBeenCalled();vi.unstubAllGlobals()
 })
 it('replaces badges on current Self renewal and role loss without deriving roles from group names',()=>{
  const original=state(),view=render(<MemoryRouter><NativeAccountPage controller={controller} state={original}/></MemoryRouter>)
  const renewed=state();renewed.self!.organizations[0]={...renewed.self!.organizations[0],groups:[{id:'33333333-3333-3333-3333-333333333333',name:'Admin named group',slug:'admin-name'}],groupCount:1}
  view.rerender(<MemoryRouter><NativeAccountPage controller={controller} state={renewed}/></MemoryRouter>)
  expect(screen.queryByText('Payments team')).toBeNull();expect(screen.getByText('Admin named group')).toBeInTheDocument();expect(screen.queryByText('admin')).toBeNull()
  const lost=state();lost.self!.organizations=[];view.rerender(<MemoryRouter><NativeAccountPage controller={controller} state={lost}/></MemoryRouter>)
  expect(screen.queryByText('Admin named group')).toBeNull();expect(screen.getByTestId('account-organizations')).toHaveTextContent('No organizations')
 })
 it('explains truncated membership explicitly and keeps legacy absence compatible',()=>{
  const truncated=state();truncated.self!.organizations[0]={...truncated.self!.organizations[0],groups:[],groupCount:9000,groupsTruncated:true}
  const view=render(<MemoryRouter><NativeAccountPage controller={controller} state={truncated}/></MemoryRouter>)
  expect(screen.getByText('Showing 0 of 9000 mapped groups. Additional memberships are not listed here.')).toBeInTheDocument();expect(screen.queryByText('No mapped groups')).toBeNull()
  const legacy=state();delete legacy.self!.organizations[0].groups;delete legacy.self!.organizations[0].groupCount;delete legacy.self!.organizations[0].groupsTruncated
  view.rerender(<MemoryRouter><NativeAccountPage controller={controller} state={legacy}/></MemoryRouter>);expect(screen.queryByTestId('account-own-groups')).toBeNull()
 })
})
