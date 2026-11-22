import { useEffect, useRef, useState } from 'react'
import { apiErrorDetails, hasApiStatus, request } from './api'
import type { Copy } from './copy'

type Rule = { action: 'allow' | 'deny'; direction: 'in' | 'out'; protocol: 'tcp' | 'udp'; port: number; cidr: string }
type Draft = { id: string; plan_hash: string; revision: number; baseline: { ssh_port: number; rules: Rule[] }; diff: Record<string, unknown> }
type Entry = { seq: number; status: string; reason: string | null; operation_id: string; revision: number; attempt?: number | null }
type Saved = { rules: Rule[]; sshPort: number; draft: Draft | null; etag: string | null; approval: string | null; operation: string | null }
const pending = new Set(['QUEUED', 'INTENT_PREPARED', 'DISPATCHING', 'RECONCILIATION_REQUESTED'])

export function FirewallPlan({ resourceId, csrf, t, expired }: {
  resourceId: string; csrf: string; t: Copy; expired: () => void
}) {
  const storageKey = `vpn-orbit.firewall.${resourceId}`
  const saved = (() => { try { return JSON.parse(localStorage.getItem(storageKey) ?? 'null') as Saved | null } catch { return null } })()
  const [rules, setRules] = useState<Rule[]>(saved?.rules ?? [{ action: 'allow', direction: 'in', protocol: 'tcp', port: 22, cidr: '0.0.0.0/0' }])
  const [sshPort, setSshPort] = useState(saved?.sshPort ?? 22)
  const [draft, setDraft] = useState<Draft | null>(saved?.draft ?? null)
  const [etag, setEtag] = useState<string | null>(saved?.etag ?? null)
  const [approval, setApproval] = useState<string | null>(saved?.approval ?? null)
  const [operation, setOperation] = useState<string | null>(saved?.operation ?? null)
  const [entries, setEntries] = useState<Entry[] | null>(null)
  const [timelineRefresh, refreshTimeline] = useState(0)
  const [previewChecked, setPreviewChecked] = useState(false)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const inFlight = useRef(false)
  const draftId = draft?.id
  const revision = draft?.revision
  const last = entries?.at(-1)
  const attempt = (last?.attempt ?? 0) + 1
  useEffect(() => {
    if (!draft) return
    try { localStorage.setItem(storageKey, JSON.stringify({ rules, sshPort, draft, etag, approval, operation })) } catch { /* Best effort recovery state. */ }
  }, [storageKey, rules, sshPort, draft, etag, approval, operation])
  useEffect(() => {
    if (!draftId || !operation) return
    const abort = new AbortController()
    let timer: number | undefined
    setEntries(null)
    async function load() {
      try {
        const result = await request<{ items: Entry[] }>(`/change-plans/${draftId}/firewall-timeline`, { signal: abort.signal })
        if (abort.signal.aborted) return
        const rows = result.items.filter(item => item.operation_id === operation && item.revision === revision)
        setEntries(rows)
        if (pending.has(rows.at(-1)?.status ?? '')) timer = window.setTimeout(load, 2000)
      } catch (cause) {
        if (abort.signal.aborted) return
        setEntries(null)
        if (hasApiStatus(cause, 401)) expired()
        else setError(apiErrorDetails(cause) ?? t.firewallError)
      }
    }
    void load()
    return () => { abort.abort(); window.clearTimeout(timer) }
  }, [draftId, revision, operation, timelineRefresh, expired, t.firewallError])

  async function run(action: () => Promise<void>) {
    if (inFlight.current) return
    inFlight.current = true
    setBusy(true); setError('')
    try { await action() } catch (cause) {
      if (hasApiStatus(cause, 401)) return expired()
      setError(apiErrorDetails(cause) ?? t.firewallError)
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

  function update(index: number, patch: Partial<Rule>) {
    setRules(values => values.map((rule, current) => current === index ? { ...rule, ...patch } : rule))
  }

  return <section className="firewall-plan" aria-labelledby={`firewall-plan-${resourceId}`}>
    <h3 id={`firewall-plan-${resourceId}`}>{t.firewallPlan}</h3>
    <p>{t.firewallPlanHint}</p>
    {!draft && <>
      <label>{t.firewallSshPort}<input type="number" min="1" max="65535" value={sshPort}
        onChange={event => setSshPort(Number(event.target.value))}/></label>
      {rules.map((rule, index) => <div className="firewall-rule" key={index}>
        <select value={rule.action} aria-label={t.firewallAction} onChange={event => update(index, { action: event.target.value as Rule['action'] })}>
          <option value="allow">{t.firewallAllow}</option><option value="deny">{t.firewallDeny}</option>
        </select>
        <select value={rule.direction} aria-label={t.firewallDirection} onChange={event => update(index, { direction: event.target.value as Rule['direction'] })}>
          <option value="in">{t.firewallInbound}</option><option value="out">{t.firewallOutbound}</option>
        </select>
        <select value={rule.protocol} aria-label={t.firewallProtocol} onChange={event => update(index, { protocol: event.target.value as Rule['protocol'] })}>
          <option value="tcp">TCP</option><option value="udp">UDP</option>
        </select>
        <input aria-label={t.firewallPort} type="number" min="1" max="65535" value={rule.port}
          onChange={event => update(index, { port: Number(event.target.value) })}/>
        <input aria-label={t.firewallCidr} value={rule.cidr} onChange={event => update(index, { cidr: event.target.value })}/>
        <button type="button" onClick={() => setRules(values => values.filter((_, current) => current !== index))}
          disabled={rules.length === 1}>{t.remove}</button>
      </div>)}
      <button type="button" onClick={() => setRules(values => [...values, { ...values[0], port: 443 }])}>{t.firewallAddRule}</button>
      <button type="button" disabled={busy} onClick={() => void run(async () => {
        let tag: string | null = null
        const value = await request<Draft>(`/resources/${resourceId}/firewall-drafts`, {
          csrf, body: { rules, ssh_port: sshPort }, onHeaders: headers => { tag = headers.get('ETag') },
        })
        if (!tag) throw new Error('ETAG_MISSING')
        setDraft(value); setEtag(tag)
      })}>{t.firewallReview}</button>
    </>}
    {draft && !approval && !operation && <div role="status">
      <p>{t.firewallDiff}</p><pre>{JSON.stringify(draft.diff, null, 2)}</pre>
      <button type="button" disabled={busy} onClick={() => void run(async () => {
        setPreviewChecked(false)
        const preview = await request<{ baseline_check: string; draft_id: string; revision: number; plan_hash: string }>(
          `/change-plans/${draft.id}/firewall-preview`, { ifMatch: etag ?? undefined },
        )
        if (preview.baseline_check !== 'MATCHED' || preview.draft_id !== draft.id ||
            preview.revision !== draft.revision || preview.plan_hash !== draft.plan_hash) throw new Error('STALE_BASELINE')
        setPreviewChecked(true)
      })}>{t.firewallCheck}</button>
      <form onSubmit={event => {
        event.preventDefault()
        if (!previewChecked || busy || !password) return
        const secret = password
        setPassword('')
        void run(async () => {
          const grant = await request<{ id: string }>('/auth/reauth', { csrf, body: { password: secret, plan_hash: draft.plan_hash } })
          const result = await request<{ approval_id: string }>(`/change-plans/${draft.id}/firewall-approval`, {
            csrf, ifMatch: etag ?? undefined, body: { reauth_id: grant.id },
          })
          setApproval(result.approval_id)
        })
      }}>
        <label>{t.password}<input type="password" value={password} required disabled={!previewChecked || busy}
          onChange={event => setPassword(event.target.value)}/></label>
        <button disabled={!previewChecked || busy || !password}>{t.firewallApprove}</button>
      </form>
    </div>}
    {approval && !operation && <button type="button" disabled={busy} onClick={() => void run(async () => {
      const result = await request<{ id: string }>(`/change-plans/${draft?.id}/firewall-execution-requests`, {
        csrf, ifMatch: etag ?? undefined, body: { approval_id: approval },
      })
      setOperation(result.id)
    })}>{t.firewallExecute}</button>}
    {operation && draftId && <div role="status"><p>{t.firewallQueued} <code>{operation}</code></p>
      {last && <p><strong>{last.status}</strong>{last.reason && <> · <code>{last.reason}</code></>}</p>}
      {attempt <= 3 && (last?.status === 'UNKNOWN_OUTCOME' || last?.status === 'QUARANTINED') &&
        <button type="button" disabled={busy} onClick={() => void run(async () => {
          try {
            await request(`/change-plans/${draftId}/firewall-execution-requests/${operation}/reconciliations/${attempt}`,
              { csrf, body: {} })
          } finally {
            setEntries(null)
            refreshTimeline(value => value + 1)
          }
        })}>{t.firewallReconcile}</button>}
      {entries === null && error && <button type="button" onClick={() => {
        setError('')
        refreshTimeline(value => value + 1)
      }}>{t.retry}</button>}
    </div>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>
}
