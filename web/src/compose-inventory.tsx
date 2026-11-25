import { Table } from '@mantine/core'
import type { DockerObservation } from './api'
import type { Copy } from './copy'

export function ComposeInventory({ docker, historical, t }: {
  docker: DockerObservation; historical: boolean; t: Copy
}) {
  const projects = new Map<string, Set<string>>()
  for (const { project, service, state } of docker.containers) {
    if (state === 'UNKNOWN' || state === 'NOT_FOUND') continue
    const services = projects.get(project)
    if (services) services.add(service)
    else projects.set(project, new Set([service]))
  }

  return <section className="software" aria-labelledby="compose-projects-heading">
    <h3 id="compose-projects-heading">{t.composeProjects}</h3>
    <p>{t.composeScope}</p>
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
    </Table> : <p>{t.composeEmpty}</p>}
  </section>
}
