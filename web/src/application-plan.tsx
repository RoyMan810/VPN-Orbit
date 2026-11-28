import { useEffect, useRef, useState } from 'react'
import { apiErrorDetails, hasApiStatus, isUlid, request } from './api'
import type { Session } from './api'
import type { AdoptionReview } from './adoption-preview'

type Action = 'install' | 'start' | 'remove' | 'detach' | 'start-adopted' | 'stop-adopted'
type Draft = { id: string; plan_hash: string; diff: Record<string, unknown>; risk: string; data_policy: string }
type Saved = { draft: Draft | null; tag: string | null; approval: string | null; job: string | null }
type Registration = { installation_id: string; project: string; spec_digest: string; job_id: string }
type Entry = { seq: number; event: string; outcome: string; attempt: number; code?: string }
const active = new Set(['QUEUED', 'INTENT_PREPARED', 'DISPATCHING', 'EXECUTING', 'VERIFYING'])

export function ApplicationPlan({ resourceId, session, expired, russian, review, clearReview }: {
  resourceId: string; session: Session; expired: () => void; russian: boolean
  review?: AdoptionReview; clearReview: () => void
}) {
  const key = `vpn-orbit.application.${session.user.id}.${resourceId}`
  const load = (): Saved => {
    try {
      const value = JSON.parse(localStorage.getItem(key) ?? 'null') as Saved | null
      if (value?.draft && isUlid(value.draft.id) && /^[0-9a-f]{64}$/.test(value.draft.plan_hash) &&
          typeof value.tag === 'string' && (!value.approval || isUlid(value.approval)) &&
          (!value.job || isUlid(value.job))) return value
    } catch { /* Invalid recovery state is ignored. */ }
    return { draft: null, tag: null, approval: null, job: null }
  }
  const [saved, update] = useState<Saved>(load)
  const [installation, setInstallation] = useState('')
  const [binding, setBinding] = useState('')
  const [action, setAction] = useState<Action>('install')
  const [password, setPassword] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [jobState, setJobState] = useState<{ status: string; reason: string | null } | null>(null)
  const [entries, setEntries] = useState<Entry[]>([])
  const [refresh, setRefresh] = useState(0)
  const [registrations, setRegistrations] = useState<Registration[] | null>(null)
  const flight = useRef(false)
  const words = russian ? {
    title: 'Приложения', id: 'ID подготовленной установки', digest: 'Digest конфигурации',
    install: 'Установить', start: 'Запустить', remove: 'Удалить контейнеры', detach: 'Отменить регистрацию',
    'start-adopted': 'Запустить принятый Node', 'stop-adopted': 'Остановить принятый Node',
    adopt: 'Принятие проекта', cancelAdopt: 'Закрыть план принятия',
    registrations: 'Принятые проекты', noRegistrations: 'Подтверждённых регистраций пока нет.',
    registrationConfirm: 'Подтверждаю изменение регистрации проекта',
    stopConfirm: 'Подтверждаю остановку Node и прерывание его VPN-соединений',
    hint: 'Настройте приложения и секреты на сервере. Удаление сохраняет данные и сети.',
    draft: 'Проверить операцию', confirm: 'Подтверждаю операцию и риск изменения сети хоста',
    password: 'Пароль Owner', approve: 'Подтвердить ревизию', enqueue: 'Выполнить',
    reconcile: 'Сверить результат', reset: 'Новая операция', retry: 'Обновить статус',
    failed: 'Запрос не выполнен. Сохранённый запрос можно повторить.',
  } : {
    title: 'Applications', id: 'Prepared installation ID', digest: 'Configuration digest',
    install: 'Install', start: 'Start', remove: 'Remove containers', detach: 'Detach registration',
    'start-adopted': 'Start adopted Node', 'stop-adopted': 'Stop adopted Node',
    adopt: 'Adopt project', cancelAdopt: 'Close adoption plan',
    registrations: 'Adopted projects', noRegistrations: 'No confirmed registrations yet.',
    registrationConfirm: 'I confirm the change to the project registration',
    stopConfirm: 'I confirm stopping this Node and interrupting its VPN connections',
    hint: 'Prepare application configuration and secrets on the server. Removal preserves data and networks.',
    draft: 'Review operation', confirm: 'I confirm this operation and its host network risk',
    password: 'Owner password', approve: 'Approve revision', enqueue: 'Execute',
    reconcile: 'Reconcile outcome', reset: 'New operation', retry: 'Refresh status',
    failed: 'Request failed. You can retry the saved request.',
  }
  function persist(value: Saved) {
    // Persist the retry binding before effects can be requested; never persist passwords.
    localStorage.setItem(key, JSON.stringify(value))
    update(value)
  }
  async function run(callback: () => Promise<void>) {
    if (flight.current) return
    flight.current = true; setBusy(true); setError('')
    try { await callback() } catch (cause) {
      if (hasApiStatus(cause, 401)) expired()
      else setError(apiErrorDetails(cause) ?? words.failed)
    } finally { flight.current = false; setBusy(false) }
  }
  useEffect(() => {
    if (!saved.job) return
    const stop = new AbortController()
    let timer: number | undefined
    async function poll() {
      try {
        const job = await request<{ status: string; reason: string | null }>(`/jobs/${saved.job}`, { signal: stop.signal })
        const timeline = await request<{ items: Entry[] }>(`/jobs/${saved.job}/application-timeline`, { signal: stop.signal })
        if (stop.signal.aborted) return
        setJobState(job)
        setEntries(timeline.items)
        if (active.has(job.status) || timeline.items.at(-1)?.event === 'application.reconciliation_requested')
          timer = window.setTimeout(poll, 2000)
      } catch (cause) {
        if (!stop.signal.aborted) {
          if (hasApiStatus(cause, 401)) expired()
          else setError(apiErrorDetails(cause) ?? words.failed)
        }
      }
    }
    void poll()
    return () => { stop.abort(); window.clearTimeout(timer) }
  }, [saved.job, refresh, expired, words.failed])
  const last = entries.at(-1)
  const attempt = (last?.attempt ?? 0) + 1
  const status = jobState?.status ?? ''
  const unresolved = status === 'UNKNOWN_OUTCOME' && last?.outcome !== 'RECONCILED_SUCCEEDED'

  return <section id="application-plan" tabIndex={-1} aria-label={words.title}>
    <h3>{words.title}</h3><p>{words.hint}</p>
    <button type="button" disabled={busy} onClick={() => void run(async () => {
      const result = await request<{ items: Registration[] }>(`/resources/${resourceId}/adopted-applications`)
      setRegistrations(result.items)
    })}>{words.registrations}</button>
    {registrations && (registrations.length > 0 ? <ul aria-label={words.registrations}>
      {registrations.map(item => <li key={item.installation_id}>
        <strong>{item.project}</strong> · <code>{item.installation_id}</code>{' '}
        {!saved.draft && (['start-adopted', 'stop-adopted', 'detach'] as const).map(operation =>
          <button key={operation} type="button" onClick={() => {
            clearReview()
            setInstallation(item.installation_id)
            setBinding(item.spec_digest)
            setAction(operation)
          }}>{words[operation]}</button>)}
      </li>)}
    </ul> : <p>{words.noRegistrations}</p>)}
    {!saved.draft && review && <p>{words.adopt} <code>{review.project}</code> <button type="button" onClick={clearReview}>
      {words.cancelAdopt}
    </button></p>}
    {!saved.draft && <form onSubmit={event => {
      event.preventDefault()
      void run(async () => {
        let tag: string | null = null
        const draft = await request<Draft>(`/resources/${resourceId}/application-drafts`, {
          body: { installation_id: installation, spec_digest: binding,
            ...(review ? { action: 'adopt', project: review.project } : { action }) },
          csrf: session.csrf_token, ifMatch: review?.tag,
          onHeaders: headers => { tag = headers.get('ETag') },
        })
        if (!tag) throw new Error('ETAG_MISSING')
        persist({ draft, tag, approval: null, job: null })
      })
    }}>
      <label>{words.id}<input value={installation} maxLength={26} pattern="[0-7][0-9A-HJKMNP-TV-Z]{25}"
        required onChange={event => setInstallation(event.target.value)}/></label>
      <label>{words.digest}<input value={binding} maxLength={64} pattern="[0-9a-f]{64}"
        required onChange={event => setBinding(event.target.value)}/></label>
      {!review && <select aria-label={words.title} value={action} onChange={event => setAction(event.target.value as Action)}>
        <option value="install">{words.install}</option><option value="start">{words.start}</option><option value="remove">{words.remove}</option>
        <option value="detach">{words.detach}</option>
        <option value="start-adopted">{words['start-adopted']}</option>
        <option value="stop-adopted">{words['stop-adopted']}</option>
      </select>}
      <button disabled={busy}>{words.draft}</button>
    </form>}
    {saved.draft && <><pre>{JSON.stringify(saved.draft.diff, null, 2)}</pre>
      <p>{saved.draft.risk} · {saved.draft.data_policy}</p></>}
    {saved.draft && !saved.approval && <form onSubmit={event => {
      event.preventDefault()
      const secret = password; setPassword('')
      if (!confirmed || !secret || !saved.draft) return
      void run(async () => {
        const grant = await request<{ id: string }>('/auth/reauth', {
          csrf: session.csrf_token, body: { password: secret, plan_hash: saved.draft!.plan_hash },
        })
        const value = await request<{ approval_id: string }>(`/change-plans/${saved.draft!.id}/application-approval`, {
          csrf: session.csrf_token, ifMatch: saved.tag ?? undefined, body: { reauth_id: grant.id },
        })
        persist({ ...saved, approval: value.approval_id })
      })
    }}>
      <label><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)}/>{saved.draft.diff.operation === 'stop-adopted' ? words.stopConfirm :
        saved.draft.risk === 'MANAGEMENT_REGISTRATION_ONLY' ? words.registrationConfirm : words.confirm}</label>
      <label>{words.password}<input type="password" autoComplete="current-password" value={password}
        onChange={event => setPassword(event.target.value)}/></label>
      <button disabled={busy || !confirmed || !password}>{words.approve}</button>
    </form>}
    {saved.approval && !saved.job && <button disabled={busy} onClick={() => void run(async () => {
      // The persisted approval identifies the same durable request after a lost reply/reload.
      const result = await request<{ id: string }>(`/change-plans/${saved.draft!.id}/application-execution-requests`, {
        csrf: session.csrf_token, ifMatch: saved.tag ?? undefined, body: { approval_id: saved.approval },
      })
      persist({ ...saved, job: result.id })
    })}>{words.enqueue}</button>}
    {saved.job && <div role="status"><code>{saved.job}</code><p>{status}</p>
      {jobState?.reason && <p>{jobState.reason}</p>}
      {last && <p>{last.outcome} {last.code}</p>}
      <button onClick={() => setRefresh(value => value + 1)}>{words.retry}</button>
      {unresolved && attempt <= 3 && last?.event !== 'application.reconciliation_requested' &&
        <button disabled={busy} onClick={() => void run(async () => {
          await request(`/jobs/${saved.job}/application-reconciliations/${attempt}`, { body: {}, csrf: session.csrf_token })
          setRefresh(value => value + 1)
        })}>{words.reconcile}</button>}
    </div>}
    {saved.draft && (!saved.job || (status && !active.has(status) && !unresolved)) &&
      <button disabled={busy} onClick={() => { localStorage.removeItem(key); update({ draft: null, tag: null, approval: null, job: null }); setConfirmed(false); setEntries([]); setJobState(null) }}>{words.reset}</button>}
    {error && <p role="alert">{error}</p>}
  </section>
}
