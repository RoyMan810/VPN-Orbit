import { Table } from '@mantine/core'
import type { ComposeObservation, DockerContainer } from './api'
import type { Copy } from './copy'

export function ComposeInventory({ compose, scoped, historical, t }: {
  compose?: ComposeObservation; scoped: DockerContainer[]; historical: boolean; t: Copy
}) {
  const discovered = compose?.status === 'OBSERVED'
  const projects = new Map<string, Set<string>>()
  for (const { project, service, state } of discovered ? compose.containers : scoped) {
    if (state === 'UNKNOWN' || state === 'NOT_FOUND') continue
    const services = projects.get(project)
    if (services) services.add(service)
    else projects.set(project, new Set([service]))
  }

  return <section className="software" aria-labelledby="compose-projects-heading">
    <h3 id="compose-projects-heading">{t.composeProjects}</h3>
    {discovered ? <p>{t.composeAllScope}</p> : scoped.length > 0 && <p>{t.composeScope}</p>}
    {compose && compose.status !== 'OBSERVED' && <p>{t.composeDiscoveryStatus[compose.status]}</p>}
    {historical && <p>{t.composeHistorical}</p>}
    {projects.size ? <Table className="compose-projects">
      <Table.Thead><Table.Tr>
        <Table.Th scope="col">{t.composeProject}</Table.Th>
        <Table.Th scope="col">{t.composeServices}</Table.Th>
      </Table.Tr></Table.Thead>
      <Table.Tbody>{[...projects].map(([project, services]) => <Table.Tr key={project}>
        <Table.Th scope="row"><code>{project}</code></Table.Th>
        <Table.Td><code>{[...services].join(', ')}</code></Table.Td>
      </Table.Tr>)}</Table.Tbody>
    </Table> : (discovered || scoped.length > 0) && <p>{t.composeEmpty}</p>}
  </section>
}
