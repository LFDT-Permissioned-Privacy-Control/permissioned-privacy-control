import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { SourceExecution } from './SourceExecution'
import { fixtureProject, org } from './configurationFixtures.test-support'
afterEach(cleanup)
it('retains structured readonly execution details, exact limits and group/contract linkage',async()=>{
 const project=await fixtureProject(),open=vi.fn();render(<SourceExecution project={project} root="source" organization={org} onOpenSource={open} />)
 expect(screen.getByText('Deployer')).toBeInTheDocument(); expect(screen.getByText('Vault')).toBeInTheDocument(); expect(screen.getByText('transfer(address,uint256)')).toBeInTheDocument()
 await userEvent.click(screen.getByRole('button',{name:'Inspect rule'})); expect(screen.getByRole('dialog')).toHaveTextContent('10000000000000000000000000000000000'); expect(screen.getByRole('dialog')).toHaveTextContent('Maximum depth')
 expect(screen.queryByRole('button',{name:/Add frame|Edit rule|Remove rule|Policy scenario/})).not.toBeInTheDocument(); await userEvent.click(within(screen.getByRole('dialog')).getByRole('button',{name:'Close'})); await userEvent.click(screen.getByRole('button',{name:'View execution source'}));expect(open).toHaveBeenCalledWith('execution.json')
})
