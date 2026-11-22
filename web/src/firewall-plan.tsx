import { useState } from 'react'
import { apiErrorDetails, request } from './api'
import type { Copy } from './copy'

type Rule = { action: 'allow' | 'deny'; direction: 'in' | 'out'; protocol: 'tcp' | 'udp'; port: number; cidr: string }
type Draft = { id: string; plan_hash: string; revision: number; baseline: { ssh_port: number; rules: Rule[] }; diff: Record<string, unknown> }

export function FirewallPlan({ resourceId, csrf, t, expired }: {
  resourceId: string; csrf: string; t: Copy; expired: () => void
}) {
  const [rules, setRules] = useState<Rule[]>([{ action: 'allow', direction: 'in', protocol: 'tcp', port: 22, cidr: '0.0.0.0/0' }])
  const [sshPort, setSshPort] = useState(22)
  const [draft, setDraft] = useState<Draft | null>(null)
  const [etag, setEtag] = useState<string | null>(null)
  const [approval, setApproval] = useState<string | null>(null)
  const [operation, setOperation] = useState<string | null>(null)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function run(action: () => Promise<void>) {
    if (busy) return
    setBusy(true); setError('')
    try { await action() } catch (cause) {
      if ((cause as { status?: number }).status === 401) return expired()
      setError(apiErrorDetails(cause) ?? t.firewallError)
    } finally { setBusy(false) }
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
        const preview = await request<{ baseline_check: string }>(`/change-plans/${draft.id}/firewall-preview`, { ifMatch: etag ?? undefined })
        if (preview.baseline_check !== 'MATCHED') throw new Error('STALE_BASELINE')
      })}>{t.firewallCheck}</button>
      <form onSubmit={event => {
        event.preventDefault(); const secret = password; setPassword('')
        void run(async () => {
          const grant = await request<{ id: string }>('/auth/reauth', { csrf, body: { password: secret, plan_hash: draft.plan_hash } })
          const result = await request<{ approval_id: string }>(`/change-plans/${draft.id}/firewall-approval`, {
            csrf, ifMatch: etag ?? undefined, body: { reauth_id: grant.id },
          })
          setApproval(result.approval_id)
        })
      }}>
        <label>{t.password}<input type="password" value={password} required onChange={event => setPassword(event.target.value)}/></label>
        <button disabled={busy || !password}>{t.firewallApprove}</button>
      </form>
    </div>}
    {approval && !operation && <button type="button" disabled={busy} onClick={() => void run(async () => {
      const result = await request<{ id: string }>(`/change-plans/${draft?.id}/firewall-execution-requests`, {
        csrf, ifMatch: etag ?? undefined, body: { approval_id: approval },
      })
      setOperation(result.id)
    })}>{t.firewallExecute}</button>}
    {operation && <p role="status">{t.firewallQueued} <code>{operation}</code></p>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>
}
