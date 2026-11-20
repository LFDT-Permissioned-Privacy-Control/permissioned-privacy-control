import { useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'

// Options come from the verified live session, never imported configuration.
// Keep business-page navigation and its visible organization selector aligned.
export function useLiveOrganizationScope(organizations: readonly { id: string }[]): [string, (id: string) => void] {
  const location = useLocation(), navigate = useNavigate()
  const requested = new URLSearchParams(location.search).get('org') ?? ''
  const org = requested ? organizations.some(value => value.id === requested) ? requested : '' : organizations.length === 1 ? organizations[0].id : ''
  useEffect(() => {
    if (!requested && org) navigate({ pathname: location.pathname, search: '?org=' + org }, { replace: true })
  }, [org, requested, location.pathname, navigate])
  return [org, id => {
    if (id && !organizations.some(value => value.id === id)) return
    navigate({ pathname: location.pathname, search: id ? '?org=' + id : '' }, { replace: true })
  }]
}
