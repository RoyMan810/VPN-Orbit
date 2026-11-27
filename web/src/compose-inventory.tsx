import { Table } from '@mantine/core'
import type { ComposeObservation, DockerContainer } from './api'
import type { Copy } from './copy'

type AttachmentKind = 'networks' | 'volumes'
type ProjectContainer = DockerContainer & Partial<Record<AttachmentKind, string[] | null>>

function Attachments({ containers, kind, t }: { containers: ProjectContainer[]; kind: AttachmentKind; t: Copy }) {
  const observed = containers.map(container => container[kind])
  const names = [...new Set(observed.flatMap(items => items ?? []))].sort()
  const incomplete = observed.some(items => items == null)
  if (!names.length) return incomplete ? t.composeAttachmentsUnavailable : t.composeAttachmentsEmpty
  return <><code>{names.join(', ')}</code>{incomplete && <div>{t.composeAttachmentsIncomplete}</div>}</>
}

export function ComposeInventory({ compose, scoped, historical, t }: {
  compose?: ComposeObservation; scoped: DockerContainer[]; historical: boolean; t: Copy
}) {
  const discovered = compose?.status === 'OBSERVED'
  const showAttachments = discovered && compose.containers.some(container => container.networks !== undefined)
  const projects = new Map<string, ProjectContainer[]>()
  for (const container of discovered ? compose.containers : scoped) {
    if (container.state === 'UNKNOWN' || container.state === 'NOT_FOUND') continue
    const group = projects.get(container.project)
    if (group) group.push(container)
    else projects.set(container.project, [container])
  }

  const shared = (['networks', 'volumes'] as const).flatMap(kind => {
    const members = new Map<string, Set<string>>()
    for (const [project, containers] of projects) {
      for (const container of containers) {
        for (const name of container[kind] ?? []) {
          if (kind === 'networks' && ['bridge', 'host', 'none'].includes(name)) continue
          const owners = members.get(name) ?? new Set<string>()
          owners.add(project)
          members.set(name, owners)
        }
      }
    }
    return [...members].filter(([, owners]) => owners.size > 1).map(([name, owners]) => ({
      kind, name, projects: [...owners].sort(),
    }))
  })

  return <section className="software" aria-labelledby="compose-projects-heading">
    <h3 id="compose-projects-heading">{t.composeProjects}</h3>
    {discovered ? <p>{t.composeAllScope}</p> : scoped.length > 0 && <p>{t.composeScope}</p>}
    {compose && compose.status !== 'OBSERVED' && <p>{t.composeDiscoveryStatus[compose.status]}</p>}
    {historical && <p>{t.composeHistorical}</p>}
    {projects.size ? <Table className="compose-projects">
      <Table.Thead><Table.Tr>
        <Table.Th scope="col">{t.composeProject}</Table.Th>
        <Table.Th scope="col">{t.composeServices}</Table.Th>
        {showAttachments && <Table.Th scope="col">{t.composeNetworks}</Table.Th>}
        {showAttachments && <Table.Th scope="col">{t.composeVolumes}</Table.Th>}
      </Table.Tr></Table.Thead>
      <Table.Tbody>{[...projects].map(([project, containers]) => <Table.Tr key={project}>
        <Table.Th scope="row"><code>{project}</code></Table.Th>
        <Table.Td><code>{[...new Set(containers.map(container => container.service))].join(', ')}</code></Table.Td>
        {showAttachments && <Table.Td><Attachments containers={containers} kind="networks" t={t} /></Table.Td>}
        {showAttachments && <Table.Td><Attachments containers={containers} kind="volumes" t={t} /></Table.Td>}
      </Table.Tr>)}</Table.Tbody>
    </Table> : (discovered || scoped.length > 0) && <p>{t.composeEmpty}</p>}
    {shared.length > 0 && <section aria-labelledby="compose-shared-heading">
      <h4 id="compose-shared-heading">{t.composeShared}</h4>
      <dl>{shared.map(resource => <div key={JSON.stringify([resource.kind, resource.name])}>
        <dt>{resource.kind === 'networks' ? t.composeNetworks : t.composeVolumes} · <code>{resource.name}</code></dt>
        <dd><code>{resource.projects.join(', ')}</code></dd>
      </div>)}</dl>
    </section>}
  </section>
}
