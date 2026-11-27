import { useEffect, useState } from 'react'
import { hasApiStatus, request } from './api'
import type { ComposeAdoptionPreview, Observation, Resource } from './api'
import type { Copy } from './copy'

export interface AdoptionContext {
  resource: Resource
  sample: NonNullable<Observation['last_success']>
  expired: () => void
}

export function AdoptionPreview({ project, resource, sample, expired, t }: AdoptionContext & { project: string; t: Copy }) {
  const { id, revision, policy_revision } = resource
  const { observed_at, boot_id } = sample
  const [result, setResult] = useState<ComposeAdoptionPreview | 'denied' | 'stale' | 'rateLimited' | 'error' | null>(null)

  useEffect(() => {
    const abort = new AbortController()
    const path = `/resources/${encodeURIComponent(id)}/compose/projects/${encodeURIComponent(project)}/adoption-preview`
    request<ComposeAdoptionPreview>(path, { signal: abort.signal }).then(preview => {
      if (abort.signal.aborted) return
      const matches = preview.version === 1 && preview.action === 'compose.adopt' && preview.status === 'PREVIEW_ONLY' &&
        preview.target.resource_id === id && preview.target.project === project &&
        preview.resource_revision === revision && preview.policy_revision === policy_revision &&
        preview.observed_at === observed_at && preview.boot_id === boot_id
      setResult(matches ? preview : 'stale')
    }).catch(error => {
      if (abort.signal.aborted) return
      if (hasApiStatus(error, 401)) return expired()
      if (hasApiStatus(error, 403)) return setResult('denied')
      if (hasApiStatus(error, 404, 409)) return setResult('stale')
      setResult(hasApiStatus(error, 429) ? 'rateLimited' : 'error')
    })
    return () => abort.abort()
  }, [id, revision, policy_revision, observed_at, boot_id, project, expired])

  return <section id="compose-adoption-preview" aria-labelledby="compose-adoption-heading" className="compose-adoption">
    <h4 id="compose-adoption-heading">{t.adoptionPreview} · <code>{project}</code></h4>
    {result === null ? <p role="status">{t.loading}</p> : typeof result === 'string' ? <p role="alert" className="error">
      {{ denied: t.restartPreviewDenied, stale: t.restartPreviewStale, rateLimited: t.rateLimited, error: t.requestError }[result]}
    </p> : <>
      <p>{t.adoptionScope}</p>
      <ul>{result.containers.map(container => <li key={container.id}>
        <strong>{container.service}</strong> · {t.containerState[container.state]}
        <div>{t.adoptionImage} <code>{container.image_id}</code></div>
        <div>{t.adoptionContainer} <code>{container.id}</code></div>
      </li>)}</ul>
      <h5>{t.composeShared}</h5>
      {(['networks', 'volumes'] as const).map(kind => {
        const { coverage, shared } = result.attachments[kind]
        return <section key={kind}>
          <h6>{kind === 'networks' ? t.composeNetworks : t.composeVolumes}</h6>
          {shared.length > 0 && <ul>{shared.map(({ name, other_projects }) =>
            <li key={name}><code>{name}</code> · <code>{other_projects.join(', ')}</code></li>,
          )}</ul>}
          {coverage === 'PARTIAL' && <p>{t.composeAttachmentsIncomplete}</p>}
          {coverage === 'OBSERVED_COMPOSE_ONLY' && !shared.length && <p>{t.adoptionNoSharedObserved}</p>}
        </section>
      })}
    </>}
  </section>
}
