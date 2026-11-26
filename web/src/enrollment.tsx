import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, hasApiStatus, isUlid, request, type Session } from './api'
import type { Copy, Language } from './copy'
import { JobTimeline } from './job-timeline'

type Readiness = { platform: keyof Copy['enrollmentPlatforms']; ssh: keyof Copy['enrollmentSshChecks'] }
type PreparationJob = { id: string; resource_id: string; action: 'host.prepare'; status: keyof Copy['probeStatus'];
  revision: number; reason: string | null }
type PreparationInfo = { available: boolean; job: PreparationJob | null }
const preparationDone = (job: PreparationJob) => ['SUCCEEDED', 'FAILED', 'UNKNOWN_OUTCOME', 'CANCELLED_SAFE'].includes(job.status)

function checkedPreparation(job: PreparationJob, t: Copy) {
  if (!isUlid(job.id) || !isUlid(job.resource_id) || job.action !== 'host.prepare' || !Object.hasOwn(t.probeStatus, job.status)
      || !Number.isSafeInteger(job.revision) || job.revision < 1
      || (job.reason !== null && !/^[A-Z][A-Z0-9_]{1,63}$/.test(job.reason))) throw new Error('Invalid preparation job')
  return job
}

export function Enrollment({ t, lang, session, expired, onEnroll, firstVps }: {
  t: Copy; lang: Language; session: Session; firstVps: boolean; expired: () => void; onEnroll: (id: string) => void
}) {
  const [busy, setBusy] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const [byId, setById] = useState(false)
  const [authentication, setAuthentication] = useState<'password' | 'private_key'>('password')
  const [candidates, setCandidates] = useState<string[] | null>(null)
  const [canPrepare, setCanPrepare] = useState(false)
  const [preparation, setPreparation] = useState<PreparationJob | null>(null)
  const [pollFailed, setPollFailed] = useState(false)
  const preparationKey = useRef<{ intent: string; key: string } | null>(null)

  const loadPreparation = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await request<PreparationInfo>('/enrollment/preparation', { signal })
      if (signal?.aborted) return
      setCanPrepare(result.available)
      if (result.job) {
        const job = checkedPreparation(result.job, t)
        setPreparation(previous => previous && previous.id === job.id && previous.revision > job.revision ? previous : job)
      }
    } catch (error) {
      if (!signal?.aborted && hasApiStatus(error, 401)) expired()
    }
  }, [expired, t])

  useEffect(() => {
    if (!expanded && !firstVps) return
    const abort = new AbortController()
    void loadPreparation(abort.signal)
    return () => abort.abort()
  }, [expanded, firstVps, loadPreparation])

  useEffect(() => {
    if (!preparation || preparationDone(preparation) || pollFailed) return
    const abort = new AbortController()
    const timer = window.setTimeout(async () => {
      try {
        const result = await request<PreparationJob>('/jobs/' + encodeURIComponent(preparation.id), {
          signal: AbortSignal.any([abort.signal, AbortSignal.timeout(10_000)]),
        })
        if (abort.signal.aborted) return
        const job = checkedPreparation(result, t)
        if (job.id !== preparation.id || job.resource_id !== preparation.resource_id
            || job.revision < preparation.revision) throw new Error('Invalid preparation job')
        setPreparation(job)
        if (job.status === 'SUCCEEDED') onEnroll(job.resource_id)
      } catch (error) {
        if (abort.signal.aborted) return
        if (hasApiStatus(error, 401)) expired()
        else setPollFailed(true)
      }
    }, 2500)
    return () => { abort.abort(); window.clearTimeout(timer) }
  }, [preparation, pollFailed, t, onEnroll, expired])

  useEffect(() => {
    if (!byId || (!expanded && !firstVps)) return
    const abort = new AbortController()
    request<{ items: string[] }>('/enrollment/candidates', { signal: abort.signal })
      .then(({ items }) => { if (!abort.signal.aborted) setCandidates(items) })
      .catch(error => { if (!abort.signal.aborted && hasApiStatus(error, 401)) expired() })
    return () => abort.abort()
  }, [byId, expanded, expired, firstVps])
  const [status, setStatus] = useState<'enrollmentSuccess' | 'enrollmentMismatch' | 'enrollmentMissing' | 'enrollmentConflict'
    | 'enrollmentAuthenticationFailed' | 'enrollmentConnectionFailed' | 'enrollmentInvalid' | 'enrollmentPreflightUnavailable'
    | 'probeUncertain' | 'requestError' | null>(null)
  const [readiness, setReadiness] = useState<Readiness | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const submitter = (event.nativeEvent as SubmitEvent).submitter
    const preflight = !byId && submitter instanceof HTMLButtonElement && submitter.value === 'preflight'
    const prepare = !byId && submitter instanceof HTMLButtonElement && submitter.value === 'prepare'
    const data = new FormData(form)
    const fingerprint = String(data.get('fingerprint')).trim()
    const resourceId = byId ? String(data.get('id')).trim() : null
    const credential = form.elements.namedItem(authentication)
    const body = byId ? { resource_id: resourceId, fingerprint } : {
      ip: String(data.get('ip')).trim(), port: Number(data.get('port')), username: String(data.get('username')).trim(),
      fingerprint, [authentication]: data.get(authentication),
    }
    if (credential instanceof HTMLInputElement || credential instanceof HTMLTextAreaElement) credential.value = ''
    data.delete(authentication)
    setBusy(true)
    setStatus(null)
    setReadiness(null)
    try {
      if (preflight) {
        setReadiness(await request<Readiness>('/enrollment/ssh/preflight', { body, csrf: session.csrf_token }))
        return
      }
      if (prepare) {
        const intent = JSON.stringify([body.ip, body.port, body.username, fingerprint, authentication])
        if (preparationKey.current?.intent !== intent) preparationKey.current = { intent, key: crypto.randomUUID() }
        const result = await request<PreparationJob>('/enrollment/preparation', {
          body, csrf: session.csrf_token, idempotencyKey: preparationKey.current.key, signal: AbortSignal.timeout(15_000),
        })
        const job = checkedPreparation(result, t)
        preparationKey.current = null
        setPollFailed(false)
        setPreparation(job)
        if (job.status === 'SUCCEEDED') onEnroll(job.resource_id)
        return
      }
      const result = await request<{ id: string }>(byId ? '/resources' : '/enrollment/ssh', {
        body, csrf: session.csrf_token,
      })
      if (byId && result.id !== resourceId) throw new Error('Unexpected resource')
      form.reset()
      setStatus('enrollmentSuccess')
      setCandidates(previous => previous?.filter(id => id !== result.id) ?? null)
      onEnroll(result.id)
    } catch (error) {
      if (prepare && (!hasApiStatus(error, 401, 403, 404, 412, 422))) void loadPreparation()
      if (hasApiStatus(error, 401)) expired()
      else if (hasApiStatus(error, 412)) setStatus('enrollmentMismatch')
      else if (hasApiStatus(error, 404)) setStatus('enrollmentMissing')
      else if (hasApiStatus(error, 409)) setStatus('enrollmentConflict')
      else if (hasApiStatus(error, 422)) setStatus('enrollmentInvalid')
      else if (hasApiStatus(error, 424)) setStatus('enrollmentAuthenticationFailed')
      else if (error instanceof ApiError && error.code === 'SSH_PREFLIGHT_UNAVAILABLE') setStatus('enrollmentPreflightUnavailable')
      else if (hasApiStatus(error, 502)) setStatus('enrollmentConnectionFailed')
      else if (prepare && (!(error instanceof ApiError) || error.status >= 500)) setStatus('probeUncertain')
      else setStatus('requestError')
    } finally {
      setBusy(false)
    }
  }

  return <details className="panel enrollment" open={firstVps || undefined}
    onToggle={event => setExpanded(event.currentTarget.open)}>
    <summary>{t.enroll}</summary>
    <form onSubmit={submit} onInput={() => setReadiness(null)} aria-busy={busy}>
      <p>{t.enrollmentHelp} <a href="https://github.com/RoyMan810/VPN-Orbit/blob/main/docs/vps.md#подготовка-vps">{t.enrollmentGuide}</a></p>
      {byId ? (candidates?.length ? <label>{t.enrollmentId}
        <select name="id" required disabled={busy} defaultValue={candidates.length === 1 ? candidates[0] : ''}>
          {candidates.length > 1 && <option value="">{t.enrollmentChoose}</option>}
          {candidates.map(id => <option key={id} value={id}>{id}</option>)}
        </select>
      </label> : <label>{t.enrollmentId}<input name="id" required disabled={busy} maxLength={26} pattern="[0-7][0-9A-HJKMNP-TV-Z]{25}"/></label>) : <>
        <label>{t.enrollmentIp}<input name="ip" required disabled={busy} maxLength={45} autoComplete="off" spellCheck={false}/></label>
        <label>{t.enrollmentPort}<input name="port" type="number" min={1} max={65535} required disabled={busy} defaultValue={22}/></label>
        <label>{t.enrollmentUsername}<input name="username" required disabled={busy} maxLength={64} autoComplete="off" spellCheck={false}/></label>
        <label>{t.enrollmentAuthentication}<select value={authentication} disabled={busy}
          onChange={event => setAuthentication(event.currentTarget.value === 'private_key' ? 'private_key' : 'password')}>
          <option value="password">{t.enrollmentPassword}</option>
          <option value="private_key">{t.enrollmentPrivateKey}</option>
        </select></label>
        {authentication === 'password'
          ? <label>{t.enrollmentPassword}<input name="password" type="password" required maxLength={1024} autoComplete="off" disabled={busy}/></label>
          : <label>{t.enrollmentPrivateKey}<textarea name="private_key" required maxLength={8192} autoComplete="off" spellCheck={false} rows={5} disabled={busy}/></label>}
      </>}
      {byId && candidates?.length === 0 && status !== 'enrollmentSuccess' && <p>{t.enrollmentNoCandidates}</p>}
      <label>{t.enrollmentPin}<input name="fingerprint" required disabled={busy} maxLength={50} placeholder="SHA256:…" autoComplete="off" spellCheck={false}/></label>
      <div className="enrollment-actions">
        <button type="submit" disabled={busy}>{t.enrollmentSubmit}</button>
        {!byId && <button type="submit" value="preflight" disabled={busy}>{t.enrollmentPreflight}</button>}
        {!byId && canPrepare && <button type="submit" value="prepare"
          disabled={busy || (preparation !== null && !preparationDone(preparation))}>{t.preparationStart}</button>}
      </div>
      {status && <p role="status">{t[status]}</p>}
      {readiness && <div role="status">
        <p>{t.enrollmentPlatforms[readiness.platform]}</p>
        <p>{t.enrollmentSshChecks[readiness.ssh]}</p>
      </div>}
      <button type="button" className="quiet" disabled={busy} onClick={() => { setById(!byId); setStatus(null); setReadiness(null) }}>
        {byId ? t.enrollmentUseSsh : t.enrollmentUseId}
      </button>
    </form>
    {preparation && <section aria-label={t.preparationHeading}>
      <p role="status">{t.preparationStates[preparation.status as keyof Copy['preparationStates']] ?? t.probeStatus[preparation.status]}
        {preparation.reason && <> <code>{preparation.reason}</code></>}</p>
      <p>{t.probeJob} <code>{preparation.id}</code></p>
      {preparation.status === 'UNKNOWN_OUTCOME' && <p>{t.preparationUnknown}</p>}
      {preparation.status === 'UNKNOWN_OUTCOME' && <button type="button" onClick={() => void loadPreparation()}>{t.probeResume}</button>}
      {pollFailed && <button type="button" onClick={() => setPollFailed(false)}>{t.probeResume}</button>}
      <JobTimeline key={preparation.id} jobId={preparation.id} t={t} lang={lang} expired={expired}/>
    </section>}
  </details>
}
