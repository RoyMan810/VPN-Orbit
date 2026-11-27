import { expect, test } from '@playwright/test'

const resource = '01JCYQZ4T9V8MNVYEH3D2M7Q1A'
const password = 'VPN-Orbit fixture password!'

test.beforeEach(async ({ context }, info) => {
  await context.setExtraHTTPHeaders({ 'X-Forwarded-For': `2001:db8:abc::${info.parallelIndex + 1}:${info.retry + 1}` })
})

async function login(page: import('@playwright/test').Page, user = 'fixture-owner') {
  await page.goto('/')
  await page.getByLabel('Username').fill(user)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'VPS inventory' })).toBeVisible()
}

test('application approval survives reload and a lost enqueue response reuses the job', async ({ page }) => {
  await login(page)
  const apps = page.getByRole('region', { name: 'Applications', exact: true })
  await apps.getByLabel('Prepared installation ID').fill(resource)
  await apps.getByLabel('Configuration digest').fill('b'.repeat(64))
  await apps.getByRole('button', { name: 'Review operation', exact: true }).click()
  await expect(apps.getByText('HOST_NETWORK_AND_APPLICATION_DATA', { exact: false })).toBeVisible()
  const approve = apps.getByRole('button', { name: 'Approve revision', exact: true })
  await apps.getByLabel('Owner password').fill(password)
  await expect(approve).toBeDisabled()
  await apps.getByLabel('I confirm this operation and its host network risk').check()
  await approve.click()
  await expect(apps.getByRole('button', { name: 'Execute', exact: true })).toBeVisible()
  expect(await page.evaluate(() => Object.values(localStorage).join('\n'))).not.toContain(password)
  await page.reload()
  let job: string | undefined
  await page.route('**/application-execution-requests', async route => {
    const response = await route.fetch()
    expect(response.status()).toBe(202)
    job = (await response.json()).id
    await route.abort('failed')
  }, { times: 1 })
  await apps.getByRole('button', { name: 'Execute', exact: true }).click()
  await expect(apps.getByRole('alert')).toContainText('Request failed')
  expect(job).toBeTruthy()
  await page.reload()
  const accepted = page.waitForResponse(response => response.url().endsWith('/application-execution-requests') && response.status() === 202)
  await apps.getByRole('button', { name: 'Execute', exact: true }).click()
  expect((await (await accepted).json()).id).toBe(job)
  await expect(apps.getByText(job!, { exact: true })).toBeVisible()
  await expect(apps.getByText('QUEUED', { exact: true })).toBeVisible()
  await page.reload()
  await expect(apps.getByText(job!, { exact: true })).toBeVisible()
  await expect(apps.getByRole('button', { name: 'Execute', exact: true })).toHaveCount(0)
  expect((await page.request.post(`/__fixture__/jobs/${job}/finish`, {
    params: { outcome: 'SUCCEEDED' },
  })).status()).toBe(204)
  expect((await page.request.post('/__fixture__/reset-reauth-budget')).status()).toBe(204)
})

test('application controls require the actual resource permission', async ({ page }) => {
  await page.route('**/api/v1/resources**', async route => {
    const response = await route.fetch()
    const value = await response.json()
    if (Array.isArray(value.items)) {
      value.items = value.items.map((item: { permissions: object }) => ({ ...item, permissions: { ...item.permissions, applications: false } }))
    } else if (value.permissions) value.permissions.applications = false
    await route.fulfill({ response, json: value })
  })
  await login(page)
  await expect(page.locator('.docker-list').getByText('fixture / web', { exact: true })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Applications', exact: true })).toHaveCount(0)
  await page.unrouteAll({ behavior: 'wait' })
})

test('adoption uses the exact tag and project from the reviewed preview', async ({ page }) => {
  let reviewedTag: string | undefined
  await page.route('**/compose/projects/fixture/adoption-preview', async route => {
    const response = await route.fetch()
    reviewedTag = response.headers()['etag']
    await route.fulfill({ response, json: { ...(await response.json()), adoption_ready: true } })
  })
  await page.route('**/application-drafts', async route => {
    expect(route.request().headers()['if-match']).toBe(reviewedTag)
    expect(route.request().postDataJSON()).toEqual({
      installation_id: resource, spec_digest: 'b'.repeat(64), action: 'adopt', project: 'fixture',
    })
    await route.fulfill({
      status: 201, headers: { etag: '"plan-fixture"' }, json: {
        id: resource, plan_hash: 'c'.repeat(64), diff: { operation: 'adopt', project: 'fixture' },
        risk: 'MANAGEMENT_REGISTRATION_ONLY', data_policy: 'PRESERVE_VOLUMES_AND_NETWORKS',
      },
    })
  })
  await login(page)
  await page.getByRole('button', { name: 'Adoption preview · fixture', exact: true }).click()
  await page.getByRole('button', { name: 'Prepare adoption plan', exact: true }).click()
  const apps = page.getByRole('region', { name: 'Applications', exact: true })
  await expect(apps).toBeFocused()
  await apps.getByLabel('Prepared installation ID').fill(resource)
  await apps.getByLabel('Configuration digest').fill('b'.repeat(64))
  await apps.getByRole('button', { name: 'Review operation', exact: true }).click()
  await expect(apps.getByLabel('I confirm the change to the project registration')).toBeVisible()
})
