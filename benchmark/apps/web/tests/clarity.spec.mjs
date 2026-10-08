import { test, expect } from '@playwright/test';

// Synthetic display fixtures only. Every API request is intercepted in the browser.
const applications = ['vllm', 'voice', 'litellm', 'crm'];
const request = 'Review retained benchmark evidence';
const markdownTitle = 'PHORVEX Synthetic Request — Evaluate the Shadow Price of a Retained Fixture Budget';
const markdownSummary = 'Compare the retained fixture records in this separate plan summary.';
const markdownRequest = '\n \n# ' + markdownTitle + ' ###\n\n' + String.raw`## Objective

Inspect **synthetic measurements** and compare $\lambda = \frac{\Delta V}{\Delta H}$.

## Procedure

1. Read the retained fixture budget.
2. Compare two synthetic observations.
3. Keep the displayed values unchanged.

` + Array.from({ length: 8 }, (_, index) => `## Fixture section ${index + 1}

Retain the synthetic observations for this section as opaque display data.

- Record the fixture budget and its measurement.
- Preserve the corresponding observation and its limitations.

`).join('') + 'Request end marker.';
const summary = String.raw`## Scope

**Inspect** the retained observations and compare $x^2$ with \(y^2\).

\[\frac{a}{b}\]

- Keep missing evidence explicit.
` + '\nInline code: `\\(literal\\)`';
const cases = Array.from({ length: 20 }, (_, index) => ({
  id: `fixture-${index}`, name: `Opaque case ${index}`, namespace: applications[index % 4],
  armed: index < 13, compatible: index < 6 || index === 19,
  ...(index === 19 ? { armed: true, benchmarkBlocked: true, benchmarkBlockReason: 'Known producer defect (fixture)' } : {}),
}));
const plan = { id: 'fixture-plan', request, summary, context: '', mode: 'serial', model: 'fixture-model', applications, cases };
const run = {
  id: 'fixture-run', request, summary, mode: 'serial', model: 'fixture-model',
  status: 'completed', progress: { completed: 6, total: 20 }, applications,
  cases: [{
    id: 'fixture-record', namespace: 'vllm', name: 'Opaque retained case', status: 'observed',
    evidenceStatus: 'partial', evidenceKind: 'original-record', actuated: false,
    outcome: { opaque: 'unchanged' }, evidenceCounts: { records: 1 },
    evidence: { opaque: '<script>untrusted</script>' }, result: { id: 'console-fixture', outcome: 'unknown' },
  }],
  artifacts: [{ name: 'evidence.zip', available: true }],
};

async function mockDashboard(page, options = {}) {
  const fixture = options.run || run;
  const history = options.runs || [fixture];
  const meta = { models: ['fixture-model'], applications, ...options.meta };
  const calls = [];
  const errors = [];
  const externalRequests = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    // Fail closed: no external requests, and no API request can reach a server.
    if (url.origin !== 'http://127.0.0.1:14100') {
      externalRequests.push(url.href);
      return route.abort('blockedbyclient');
    }
    if (!url.pathname.startsWith('/api/')) return route.continue();
    const method = route.request().method();
    calls.push({ method, path: url.pathname, body: route.request().postDataJSON() });
    let body;
    if (url.pathname === '/api/auth/session') body = { authenticated: true };
    else if (url.pathname === '/api/meta') body = meta;
    else if (url.pathname === '/api/runs' && method === 'GET') body = { runs: history };
    else if (url.pathname === '/api/plans' && method === 'POST') body = { ...plan, ...route.request().postDataJSON(), ...options.plan };
    else if (history.some(item => url.pathname === `/api/runs/${item.id}`) && method === 'GET') body = history.find(item => url.pathname === `/api/runs/${item.id}`);
    else if (history.some(item => url.pathname === `/api/runs/${item.id}/events`) && method === 'GET') body = { events: [] };
    else { await route.abort('blockedbyclient'); throw new Error(`Unexpected mock API request: ${method} ${url.pathname}`); }
    await route.fulfill({ json: body });
  });
  await page.goto('/');
  await expect(page.getByRole('checkbox', { name: 'vllm' })).toBeVisible();
  return { calls, errors, meta, externalRequests };
}

async function createPlan(page, text = request) {
  await page.getByLabel('What would you like to benchmark?').fill(text);
  await page.getByRole('button', { name: 'Create benchmark plan' }).click();
  await expect(page.locator('.plan-panel')).toBeVisible();
}

test('request counter updates live from empty to the 32000 character boundary', async ({ page }) => {
  const { errors, externalRequests } = await mockDashboard(page);
  const textarea = page.getByLabel('What would you like to benchmark?');
  const counter = page.locator('#request-counter');
  await expect(counter).toHaveText('0 / 32,000 characters');
  await expect(counter).toHaveAttribute('aria-live', 'polite');
  await textarea.fill('Opaque request');
  await expect(counter).toHaveText('14 / 32,000 characters');
  await textarea.fill('x'.repeat(32_000));
  await expect(counter).toHaveText('32,000 / 32,000 characters');
  await expect(page.getByRole('button', { name: 'Create benchmark plan' })).toBeEnabled();
  await expect(textarea).toHaveAttribute('aria-invalid', 'false');
  await expect(page.locator('#request-error')).toHaveCount(0);
  await textarea.fill('');
  await expect(counter).toHaveText('0 / 32,000 characters');
  expect(errors).toEqual([]);
  expect(externalRequests).toEqual([]);
});

test('over-limit requests keep their text, show an error and prevent plan submission', async ({ page }) => {
  const { calls, errors, externalRequests } = await mockDashboard(page);
  const textarea = page.getByLabel('What would you like to benchmark?');
  const button = page.getByRole('button', { name: 'Create benchmark plan' });
  const text = 'x'.repeat(32_000) + ' ';
  await textarea.fill(text);
  await expect(textarea).toHaveValue(text);
  await expect(page.locator('#request-counter')).toHaveText('32,001 / 32,000 characters');
  await expect(textarea).toHaveAttribute('aria-invalid', 'true');
  await expect(textarea).toHaveAttribute('aria-describedby', /request-error/);
  // Next.js adds its own empty route-announcer alert, so target the request error directly.
  await expect(page.locator('#request-error')).toHaveAttribute('role', 'alert');
  await expect(page.locator('#request-error')).toContainText('Request exceeds 32,000 characters.');
  await expect(page.locator('#request-error')).toContainText('Your text has been kept in full.');
  await expect(button).toBeDisabled();
  // Also protect submission paths that bypass the disabled button.
  await textarea.evaluate(element => element.form.requestSubmit());
  expect(calls.filter(call => call.path === '/api/plans')).toEqual([]);
  await expect(page.locator('.plan-panel')).toHaveCount(0);
  await textarea.fill('x'.repeat(32_000));
  await expect(page.locator('#request-error')).toHaveCount(0);
  await expect(textarea).toHaveAttribute('aria-invalid', 'false');
  await expect(button).toBeEnabled();
  expect(errors).toEqual([]);
  expect(externalRequests).toEqual([]);
});

test('native clipboard pastes are never truncated and the full long request reaches planning', async ({ page, context }) => {
  const { calls, errors, externalRequests } = await mockDashboard(page);
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'http://127.0.0.1:14100' });
  const textarea = page.getByLabel('What would you like to benchmark?');
  const button = page.getByRole('button', { name: 'Create benchmark plan' });
  const prefix = 'Opaque pasted request\n\n', suffix = '\nRequest end marker.';
  const text = prefix + 'x'.repeat(32_000 - prefix.length - suffix.length) + suffix;
  await expect(textarea).not.toHaveAttribute('maxlength');
  await page.evaluate(value => navigator.clipboard.writeText(value), text + '!');
  await textarea.focus();
  await textarea.press('Control+V');
  await expect(textarea).toHaveValue(text + '!');
  await expect(page.locator('#request-counter')).toHaveText('32,001 / 32,000 characters');
  await expect(page.locator('#request-error')).toBeVisible();
  await expect(button).toBeDisabled();
  await page.evaluate(value => navigator.clipboard.writeText(value), text);
  await textarea.press('Control+A');
  await textarea.press('Control+V');
  await expect(textarea).toHaveValue(text);
  await expect(page.locator('#request-counter')).toHaveText('32,000 / 32,000 characters');
  await expect(button).toBeEnabled();
  await button.click();
  await expect(page.locator('.plan-panel')).toBeVisible();
  const planned = calls.filter(call => call.path === '/api/plans');
  expect(planned).toHaveLength(1);
  expect(planned[0].body.request).toBe(text);
  expect(planned[0].body.request.endsWith(suffix)).toBe(true);
  expect(errors).toEqual([]);
  expect(externalRequests).toEqual([]);
});

async function openRun(page, title = request) {
  await page.getByRole('button', { name: /^Run history/ }).click();
  await page.locator('.history-row').click();
  await expect(page.getByRole('heading', { name: title, level: 1, exact: true })).toBeVisible();
}

async function expectLongRequest(heading, level) {
  await heading.scrollIntoViewIfNeeded();
  const title = heading.getByRole('heading', { level });
  await expect(title).toHaveText(markdownTitle);
  await expect(title).not.toContainText('#');
  const description = heading.locator('.benchmark-request .benchmark-description');
  await expect(description.locator('strong').filter({ hasText: 'Objective' })).toHaveText('Objective');
  await expect(description.locator('strong').filter({ hasText: 'synthetic measurements' })).toBeVisible();
  await expect(description.locator('ol li')).toHaveText([
    'Read the retained fixture budget.',
    'Compare two synthetic observations.',
    'Keep the displayed values unchanged.',
  ]);
  await expect(description.locator('.katex')).toHaveCount(1);
  await expect(description.locator('h1, h2')).toHaveCount(0);
  await expect(description).not.toContainText('##');
  await expect(description).not.toContainText(markdownSummary);
  const planSummary = heading.getByRole('region', { name: 'Plan summary', exact: true });
  await expect(planSummary.locator('.stat-label')).toHaveText('Plan summary');
  await expect(planSummary.locator('.benchmark-description')).toHaveText(markdownSummary);
  await expect(planSummary).not.toContainText('Request end marker.');
  expect(await title.evaluate(el => parseFloat(getComputedStyle(el).fontSize)))
    .toBeGreaterThan(await description.evaluate(el => parseFloat(getComputedStyle(el).fontSize)));
  expect(await description.evaluate(el => el.getBoundingClientRect().top))
    .toBeGreaterThanOrEqual(await title.evaluate(el => el.getBoundingClientRect().bottom));

  const preview = heading.locator('.benchmark-request-preview');
  const expand = heading.getByRole('button', { name: 'Show full request', exact: true });
  await expect(expand).toHaveAttribute('aria-expanded', 'false');
  await expect(expand).toHaveAttribute('aria-controls', await preview.getAttribute('id'));
  await expect(preview).toHaveClass(/collapsed/);
  const collapsed = await preview.evaluate(el => ({
    height: el.clientHeight, fullHeight: el.scrollHeight,
    limit: getComputedStyle(el).maxHeight, overflow: getComputedStyle(el).overflowY,
  }));
  expect(collapsed.height).toBeLessThanOrEqual(240);
  expect(collapsed.fullHeight).toBeGreaterThan(collapsed.height);
  expect(collapsed.limit).toBe('240px');
  expect(collapsed.overflow).toBe('hidden');
  const end = description.getByText('Request end marker.', { exact: true });
  await expect(end).not.toBeInViewport();
  await expand.click();
  const collapse = heading.getByRole('button', { name: 'Show less', exact: true });
  await expect(collapse).toHaveAttribute('aria-expanded', 'true');
  await expect(preview).not.toHaveClass(/collapsed/);
  const expanded = await preview.evaluate(el => ({ height: el.clientHeight, fullHeight: el.scrollHeight }));
  expect(expanded.height).toBeGreaterThan(collapsed.height);
  expect(expanded.fullHeight).toBeLessThanOrEqual(expanded.height + 1);
  await end.scrollIntoViewIfNeeded();
  await expect(end).toBeInViewport();
  await collapse.click();
  await expect(expand).toHaveAttribute('aria-expanded', 'false');
  await expect(preview).toHaveClass(/collapsed/);
  await expect(end).not.toBeInViewport();
}

test('long markdown run request has only its title in h1 and a collapsible formatted body', async ({ page }) => {
  const { errors, externalRequests } = await mockDashboard(page, {
    run: { ...run, request: markdownRequest, summary: markdownSummary },
  });
  await openRun(page, markdownTitle);
  await expect(page.locator('h1')).toHaveCount(1);
  await expectLongRequest(page.locator('.run-heading'), 1);
  expect(errors).toEqual([]);
  expect(externalRequests).toEqual([]);
});

test('long markdown plan review separates the title, request body and plan summary', async ({ page }) => {
  const { calls, errors, externalRequests } = await mockDashboard(page, {
    plan: { request: markdownRequest, summary: markdownSummary },
  });
  await createPlan(page, markdownRequest);
  await expectLongRequest(page.locator('.plan-panel .benchmark-heading'), 2);
  expect(calls.find(call => call.path === '/api/plans').body.request).toBe(markdownRequest.trim());
  expect(errors).toEqual([]);
  expect(externalRequests).toEqual([]);
});

test('long markdown history rows contain only the title on one line with ellipsis', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockDashboard(page, { run: { ...run, request: markdownRequest, summary: markdownSummary } });
  await page.getByRole('button', { name: /^Run history/ }).click();
  const row = page.locator('.history-row');
  const title = row.locator('.history-title strong');
  await expect(title).toHaveText(markdownTitle);
  await expect(row).not.toContainText('Objective');
  await expect(row).not.toContainText('Request end marker.');
  const style = await title.evaluate(el => ({
    whiteSpace: getComputedStyle(el).whiteSpace, overflow: getComputedStyle(el).overflowX,
    ellipsis: getComputedStyle(el).textOverflow, clipped: el.scrollWidth > el.clientWidth,
    height: el.getBoundingClientRect().height, lineHeight: parseFloat(getComputedStyle(el).lineHeight),
  }));
  expect(style.whiteSpace).toBe('nowrap');
  expect(style.overflow).toBe('hidden');
  expect(style.ellipsis).toBe('ellipsis');
  expect(style.clipped).toBe(true);
  expect(style.height).toBeLessThanOrEqual(style.lineHeight + 1);
  await row.click();
  await expect(page.locator('.run-heading h1')).toHaveText(markdownTitle);
  await expect(page.getByRole('button', { name: 'Show full request', exact: true })).toHaveAttribute('aria-expanded', 'false');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('long plain first lines truncate at a word boundary consistently across views', async ({ page }) => {
  const longRequest = 'Review ' + Array(18).fill('synthetic').join(' ') + ' measurements\n\n## Details\n\nKeep **fixture** data literal.';
  const title = 'Review ' + Array(11).fill('synthetic').join(' ') + '…';
  await mockDashboard(page, { run: { ...run, request: longRequest }, plan: { request: longRequest } });
  await createPlan(page, longRequest);
  await expect(page.locator('.plan-panel h2')).toHaveText(title);
  await expect(page.locator('.plan-panel .benchmark-request strong').filter({ hasText: 'fixture' })).toBeVisible();
  await expect(page.locator('.plan-panel .benchmark-request-toggle')).toHaveCount(0);
  await page.getByRole('button', { name: /^Run history/ }).click();
  await expect(page.locator('.history-title strong')).toHaveText(title);
  await page.locator('.history-row').click();
  await expect(page.locator('.run-heading h1')).toHaveText(title);
  await expect(page.locator('.run-heading .benchmark-request strong').filter({ hasText: 'fixture' })).toBeVisible();
  await expect(page.locator('.run-heading .benchmark-request-toggle')).toHaveCount(0);
});

test('markdown titles ignore leading blank lines, heading markers and CRLF line endings', async ({ page }) => {
  const text = '\r\n \r\n### Synthetic CRLF title ###\r\n\r\n## Details\r\n\r\nKeep the fixture description.';
  const title = 'Synthetic CRLF title';
  await mockDashboard(page, { run: { ...run, request: text }, plan: { request: text } });
  await createPlan(page, text);
  await expect(page.locator('.plan-panel h2')).toHaveText(title);
  await expect(page.locator('.plan-panel .benchmark-request')).toContainText('Keep the fixture description.');
  await openRun(page, title);
  await expect(page.locator('.run-heading h1')).toHaveText(title);
  await expect(page.locator('.run-heading .benchmark-request')).toContainText('Keep the fixture description.');
});

test('short plain requests keep their existing titles without a request toggle', async ({ page }) => {
  await mockDashboard(page);
  await createPlan(page);
  await expect(page.locator('.plan-panel h2')).toHaveText(request);
  await expect(page.locator('.plan-panel .benchmark-request')).toHaveCount(0);
  await expect(page.locator('.plan-panel').getByRole('region', { name: 'Plan summary', exact: true })).toBeVisible();
  await openRun(page);
  await expect(page.locator('.run-heading h1')).toHaveText(request);
  await expect(page.locator('.run-heading .benchmark-request')).toHaveCount(0);
  await expect(page.locator('.run-heading .benchmark-request-toggle')).toHaveCount(0);
});

test('plan title, formatted description and all readiness rows are explicit', async ({ page }) => {
  const { errors } = await mockDashboard(page);
  await createPlan(page);
  const panel = page.locator('.plan-panel');
  await expect(panel.getByRole('heading', { name: request, level: 2 })).toBeVisible();
  await expect(panel.locator('.benchmark-description strong').filter({ hasText: 'Inspect' })).toBeVisible();
  await expect(panel.locator('.benchmark-description .katex')).toHaveCount(3);
  await expect(panel.locator('.benchmark-description code').filter({ hasText: String.raw`\(literal\)` })).toBeVisible();
  await expect(panel.getByText('6 ready · 14 blocked of 20')).toBeVisible();
  await expect(panel.locator('tbody tr')).toHaveCount(20);
  await expect(panel.getByText('Ready', { exact: true })).toHaveCount(6);
  await expect(panel.getByText('Blocked', { exact: true })).toHaveCount(14);
  await expect(panel.getByText('Known producer defect (fixture)')).toBeVisible();
  await expect(panel.getByText(/never counted as defended passes/)).toBeVisible();
  const sizes = await panel.evaluate(el => ({
    title: parseFloat(getComputedStyle(el.querySelector('h2')).fontSize),
    description: parseFloat(getComputedStyle(el.querySelector('.benchmark-description p')).fontSize),
    below: el.querySelector('.benchmark-description').getBoundingClientRect().top >= el.querySelector('h2').getBoundingClientRect().bottom,
  }));
  expect(sizes.title).toBeGreaterThan(sizes.description);
  expect(sizes.below).toBe(true);
  expect(errors).toEqual([]);
});

test('missing readiness flags stay unknown and remain in the total', async ({ page }) => {
  await mockDashboard(page, { plan: { cases: [...cases, { id: 'unknown-fixture', namespace: 'crm' }] } });
  await createPlan(page);
  await expect(page.getByText('6 ready · 14 blocked · 1 unknown of 21')).toBeVisible();
  await expect(page.locator('.plan-panel tbody tr')).toHaveCount(21);
  await expect(page.getByText('Readiness flags not recorded')).toBeVisible();
});

test('application selection supports the keyboard and an empty selection', async ({ page }) => {
  const { calls } = await mockDashboard(page);
  await expect(page.getByText(/4 of 4 applications selected/)).toBeVisible();
  const vllm = page.getByRole('checkbox', { name: 'vllm' });
  await vllm.focus();
  await page.keyboard.press('Space');
  await expect(vllm).toHaveAttribute('aria-checked', 'false');
  expect(await vllm.locator('.chip-check').evaluate(el => getComputedStyle(el).color)).toBe('rgba(0, 0, 0, 0)');
  await expect(page.getByText(/3 of 4 applications selected/)).toBeVisible();
  await createPlan(page);
  expect(calls.find(call => call.path === '/api/plans').body.applications).toEqual(['voice', 'litellm', 'crm']);
  for (const name of applications.slice(1)) await page.getByRole('checkbox', { name }).click();
  await expect(page.getByText('Select at least one application to create a plan.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create benchmark plan' })).toBeDisabled();
  await expect(page.locator('.plan-panel')).toHaveCount(0);
});

test('run evidence legend and expanded records preserve the API data', async ({ page }) => {
  const { errors } = await mockDashboard(page);
  await openRun(page);
  await expect(page.locator('.run-heading .benchmark-description .katex')).toHaveCount(3);
  await page.getByText('Evidence labels and records', { exact: true }).click();
  await expect(page.getByText(/raw decision and outcome record from the Console/)).toBeVisible();
  const row = page.locator('.case-table tbody tr');
  await expect(row.getByText('Partial evidence', { exact: true })).toHaveAttribute('title', /required coverage is missing/);
  await expect(row.getByText('Original result record (Console)', { exact: true })).toBeVisible();
  for (const [label, expected] of [
    ['Evidence coverage', run.cases[0].evidenceCounts],
    ['Evidence record', run.cases[0].evidence],
    ['Original result record', run.cases[0].result],
  ]) {
    const details = row.locator('details').filter({ has: page.getByText(label, { exact: true }) });
    await details.locator('summary').click();
    await expect(details.locator('pre')).toHaveText(JSON.stringify(expected, null, 2));
    await expect(details.locator('pre')).toHaveAttribute('dir', 'ltr');
  }
  expect(errors).toEqual([]);
});

for (const evidenceStatus of ['complete', 'gap', 'incomplete', 'original-record']) {
  test(`evidence status ${evidenceStatus} has a contextual explanation`, async ({ page }) => {
    await mockDashboard(page, { run: { ...run, cases: [{ ...run.cases[0], evidenceStatus }] } });
    await openRun(page);
    const badge = page.locator('.evidence-cell .badge');
    await expect(badge).toHaveAttribute('title', /.+/);
    if (evidenceStatus === 'complete') await expect(badge).toHaveText('Evidence');
  });
}

test('progress uses service counters and labels application counts as retained records', async ({ page }) => {
  await mockDashboard(page);
  await openRun(page);
  const bar = page.getByRole('progressbar', { name: 'Case completion' });
  await expect(bar).toHaveAttribute('aria-valuenow', '30');
  await expect(bar).toHaveAttribute('aria-valuetext', '6 of 20 cases completed');
  await expect(page.getByText('6 / 20 cases completed')).toBeVisible();
  expect(await page.locator('.progress-card > strong').evaluate(el => getComputedStyle(el).display)).toBe('flex');
  expect(await bar.evaluate(el => getComputedStyle(el).height)).toBe('8px');
  await expect(page.getByText('Retained case records by application (includes blocked records)')).toBeVisible();
  await expect(page.locator('.app-progress-chip').filter({ hasText: 'crm' })).toHaveText('crm0 records');
  await expect(page.locator('.app-progress-chip').filter({ hasText: 'vllm' })).toHaveText('vllm1 record');
  await expect(page.getByText('A finished run alone does not confirm a defense.')).toBeVisible();
});

for (const [name, progress, text, value] of [
  ['zero total', { completed: 0, total: 0 }, '0 / 0 cases completed', '0'],
  ['missing counters', undefined, 'Progress not reported', null],
  ['unfinished ratio', { completed: 199, total: 200 }, '199 / 200 cases completed', '99'],
  ['finished ratio', { completed: 20, total: 20 }, '20 / 20 cases completed', '100'],
]) {
  test(`progress handles ${name} without inferring counts from retained rows`, async ({ page }) => {
    await mockDashboard(page, { run: { ...run, progress } });
    await openRun(page);
    await expect(page.getByText(text, { exact: true })).toBeVisible();
    const bar = page.getByRole('progressbar');
    if (value === null) {
      await expect(bar).not.toHaveAttribute('aria-valuenow');
      await expect(page.locator('.progress-card > strong > span').first()).toHaveText('—');
    }
    else await expect(bar).toHaveAttribute('aria-valuenow', value);
  });
}

for (const [status, message] of [
  ['queued', 'Queued; waiting to start.'],
  ['cancelled', 'Run stopped; progress reflects retained completion.'],
  ['failed', 'Run failed; inspect retained limitations and errors.'],
  ['interrupted', 'Run interrupted; inspect retained records before reconciliation.'],
]) {
  test(`${status} progress has accurate state messaging`, async ({ page }) => {
    await mockDashboard(page, { run: { ...run, status } });
    await openRun(page);
    await expect(page.getByText(message, { exact: true })).toBeVisible();
    await expect(page.getByText('Run finished.', { exact: true })).toHaveCount(0);
  });
}

test('paused notice keeps plans, history and export links available and clears on refresh', async ({ page }) => {
  const { calls, meta } = await mockDashboard(page, { meta: { executionBlockedReason: 'Reconcile producer results (fixture).' } });
  const notice = page.getByRole('status');
  await expect(notice).toContainText('history, plans and exports remain available');
  await expect(notice).toContainText('Reconcile producer results (fixture).');
  await expect(page.locator('.main-content').getByRole('alert')).toHaveCount(0);
  await createPlan(page);
  await expect(page.getByRole('button', { name: 'New runs paused' })).toBeDisabled();
  await openRun(page);
  await expect(notice).toBeVisible();
  await expect(page.getByRole('link', { name: /evidence.zip/ })).toHaveAttribute('href', '/api/runs/fixture-run/artifacts/evidence.zip');
  expect(calls.filter(call => call.path === '/api/runs' && call.method === 'POST')).toEqual([]);
  delete meta.executionBlockedReason;
  await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
  await expect(notice).toHaveCount(0);
  await page.getByRole('button', { name: 'New benchmark', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Start benchmark', exact: true })).toBeEnabled();
});

test('untrusted markdown, HTML and math cannot execute or load remote content', async ({ page }) => {
  const malicious = String.raw`# Untrusted heading

<script>window.fixtureXss = true</script>

<img src="https://untrusted.invalid/html" onerror="window.fixtureXss = true">

![Remote image](https://untrusted.invalid/image)

[Unsafe link](javascript:window.fixtureXss=true)

$\href{javascript:alert(1)}{unsafe}$

$\includegraphics{https://untrusted.invalid/math}$

$\notARealCommand{bad}$`;
  const { errors, externalRequests } = await mockDashboard(page, { plan: { summary: malicious } });
  await createPlan(page);
  const description = page.locator('.benchmark-description');
  await expect(description.getByText('Untrusted heading', { exact: true })).toBeVisible();
  await expect(description.locator('script, img, iframe, a, h1')).toHaveCount(0);
  await expect(description).toContainText(String.raw`\notARealCommand`);
  expect(await page.evaluate(() => window.fixtureXss)).toBeUndefined();
  expect(externalRequests).toEqual([]);
  expect(errors).toEqual([]);
});

test('description falls back to existing context when summary is absent', async ({ page }) => {
  await mockDashboard(page, { run: { ...run, summary: undefined, context: 'Inspect **retained** context.' } });
  await openRun(page);
  await expect(page.locator('.run-heading .benchmark-description strong')).toHaveText('retained');
});

test('mobile headers, description and progress fit with table-only horizontal scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockDashboard(page);
  await createPlan(page);
  await expect(page.locator('.plan-panel h2')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await openRun(page);
  const card = page.locator('.progress-card');
  await expect(card).toBeVisible();
  expect(await card.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('[dir="auto"], [dir="rtl"]')).toHaveCount(0);
});

const retainedVersion = {
  operator: 'operator-fixture-a', console: 'console-fixture-a', source: 'a'.repeat(40),
  operatorImage: 'registry.invalid/operator@sha256:' + 'b'.repeat(64),
  consoleImage: 'registry.invalid/console@sha256:' + 'c'.repeat(64),
  apiVersion: { version: 'compile-fixture-a', gitCommit: 'compile-fixture-commit' },
};
const requestVersionNote = 'The request text guides the plan summary only. It does not change code or configuration; this run tested the deployed version shown here.';

async function expectRerunPrefill(page, fixture, model = fixture.model) {
  await expect(page.locator('.breadcrumb strong')).toHaveText('New benchmark');
  await expect(page.getByLabel('What would you like to benchmark?')).toHaveValue(fixture.request);
  await expect(page.getByLabel('Context and notes')).toHaveValue(fixture.context || '');
  await expect(page.getByLabel('Planning model')).toHaveValue(model);
  await expect(page.getByRole('button', { name: /^Serial/ })).toHaveAttribute('aria-pressed', String(fixture.mode === 'serial'));
  await expect(page.getByRole('button', { name: /^Parallel/ })).toHaveAttribute('aria-pressed', String(fixture.mode === 'parallel'));
  for (const name of applications) {
    await expect(page.getByRole('checkbox', { name })).toHaveAttribute('aria-checked', String(fixture.applications.includes(name)));
  }
  await expect(page.locator('.plan-panel')).toHaveCount(0);
}

test('Run again from run details preserves opaque inputs, clears the old plan and allows a fresh edited plan', async ({ page }) => {
  const fixture = {
    ...run, request: '  # Retained rerun goal\n\nKeep **opaque** $x$ and <script>literal</script> data.\n  ',
    context: '  Retained context\nSecond line.  ', mode: 'parallel', model: 'retained-model', applications: ['voice', 'crm'],
  };
  const { calls, errors, externalRequests } = await mockDashboard(page, {
    run: fixture, meta: { models: ['fixture-model', { id: 'retained-model', label: 'Retained model' }] },
    plan: { id: 'fresh-fixture-plan' },
  });
  await createPlan(page, 'An unrelated old plan');
  await openRun(page, 'Retained rerun goal');
  const mutationsBeforeRerun = calls.filter(call => call.method === 'POST').length;
  await page.getByRole('button', { name: 'Run again', exact: true }).click();
  await expectRerunPrefill(page, fixture);
  expect(calls.filter(call => call.method === 'POST')).toHaveLength(mutationsBeforeRerun);
  await page.getByLabel('What would you like to benchmark?').fill(fixture.request + '\nEdited goal.');
  await page.getByLabel('Context and notes').fill('Edited context.');
  await page.getByLabel('Planning model').selectOption('fixture-model');
  await page.getByRole('button', { name: /^Serial/ }).click();
  await page.getByRole('checkbox', { name: 'crm' }).click();
  await page.getByRole('button', { name: 'Create benchmark plan' }).click();
  await expect(page.locator('.plan-panel')).toBeVisible();
  const planned = calls.filter(call => call.path === '/api/plans');
  expect(planned).toHaveLength(2);
  expect(planned[1].body).toEqual({
    request: (fixture.request + '\nEdited goal.').trim(), context: 'Edited context.',
    model: 'fixture-model', mode: 'serial', applications: ['voice'],
  });
  await expect(page.getByRole('button', { name: 'Start benchmark', exact: true })).toBeEnabled();
  expect(calls.filter(call => call.path === '/api/runs' && call.method === 'POST')).toEqual([]);
  expect(errors).toEqual([]);
  expect(externalRequests).toEqual([]);
});

test('each history row can prefill its own run without fetching details or creating a plan', async ({ page }) => {
  const fixture = { ...run, id: 'older-fixture-run', request: 'An older opaque request\nRetained body.', context: 'Older context.', mode: 'parallel', applications: ['litellm'] };
  const { calls, errors, externalRequests } = await mockDashboard(page, { runs: [run, fixture] });
  await page.getByRole('button', { name: /^Run history/ }).click();
  const entries = page.locator('.history-entry');
  await expect(entries).toHaveCount(2);
  await expect(entries.getByRole('button', { name: 'Run again', exact: true })).toHaveCount(2);
  await entries.nth(1).getByRole('button', { name: 'Run again', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expectRerunPrefill(page, fixture);
  expect(calls.filter(call => call.path.startsWith('/api/runs/'))).toEqual([]);
  expect(calls.filter(call => call.method === 'POST')).toEqual([]);
  await page.getByRole('button', { name: 'Create benchmark plan' }).click();
  await expect(page.locator('.plan-panel')).toBeVisible();
  expect(calls.find(call => call.path === '/api/plans').body).toEqual({
    request: fixture.request, context: fixture.context, model: fixture.model, mode: fixture.mode, applications: fixture.applications,
  });
  expect(calls.filter(call => call.path === '/api/runs' && call.method === 'POST')).toEqual([]);
  expect(errors).toEqual([]);
  expect(externalRequests).toEqual([]);
});

for (const source of ['run page', 'history']) {
  test(`Run again from ${source} falls back to the first allowed model when the retained model was removed`, async ({ page }) => {
    const fixture = { ...run, model: 'removed-fixture-model' };
    const { calls, errors } = await mockDashboard(page, {
      run: fixture, meta: { models: [{ id: 'replacement-fixture-model', label: 'Replacement model' }, 'fixture-model'] },
    });
    if (source === 'run page') await openRun(page);
    else await page.getByRole('button', { name: /^Run history/ }).click();
    await page.getByRole('button', { name: 'Run again', exact: true }).click();
    await expectRerunPrefill(page, fixture, 'replacement-fixture-model');
    expect(calls.filter(call => call.method === 'POST')).toEqual([]);
    await page.getByRole('button', { name: 'Create benchmark plan' }).click();
    await expect(page.locator('.plan-panel')).toBeVisible();
    expect(calls.find(call => call.path === '/api/plans').body.model).toBe('replacement-fixture-model');
    expect(calls.filter(call => call.path === '/api/runs' && call.method === 'POST')).toEqual([]);
    expect(errors).toEqual([]);
  });
}

test('Run again keeps an empty model list explicit and prevents plan submission', async ({ page }) => {
  const { calls } = await mockDashboard(page, { meta: { models: [] } });
  await openRun(page);
  await page.getByRole('button', { name: 'Run again', exact: true }).click();
  await expectRerunPrefill(page, run, '');
  await expect(page.getByRole('button', { name: 'Create benchmark plan' })).toBeDisabled();
  expect(calls.filter(call => call.method === 'POST')).toEqual([]);
});

test('run details show retained operator, console, source and image versions separately from the current version', async ({ page }) => {
  const { errors } = await mockDashboard(page, {
    run: { ...run, version: retainedVersion }, meta: { version: { operator: 'currently-deployed-fixture' } },
  });
  await openRun(page);
  const version = page.getByRole('region', { name: 'Tested version', exact: true });
  for (const [label, value] of [
    ['Operator', retainedVersion.operator], ['Console', retainedVersion.console], ['Source commit', retainedVersion.source],
    ['Operator image', retainedVersion.operatorImage], ['Console image', retainedVersion.consoleImage],
    ['API reported version (compile stamp)', JSON.stringify(retainedVersion.apiVersion)],
  ]) {
    const field = version.locator('.version-field').filter({ has: page.getByText(label + ':', { exact: true }) });
    await expect(field.locator('code')).toHaveText(value);
  }
  await expect(version).not.toContainText('currently-deployed-fixture');
  await expect(page.locator('.version-pill')).toContainText('currently-deployed-fixture');
  expect(errors).toEqual([]);
});

test('history shows each retained version and preserves support for string versions', async ({ page }) => {
  await mockDashboard(page, { runs: [
    { ...run, version: retainedVersion },
    { ...run, id: 'legacy-fixture-run', request: 'Legacy fixture', version: 'legacy-retained-version' },
  ] });
  await page.getByRole('button', { name: /^Run history/ }).click();
  const versions = page.locator('.history-version');
  await expect(versions.nth(0)).toContainText('Tested version');
  for (const value of [retainedVersion.operator, retainedVersion.console, retainedVersion.source]) {
    await expect(versions.nth(0)).toContainText(value);
  }
  await expect(versions.nth(1)).toContainText('legacy-retained-version');
  await page.locator('.history-row').nth(1).click();
  await expect(page.getByRole('region', { name: 'Tested version', exact: true }).locator('code')).toHaveText('legacy-retained-version');
});

for (const field of ['operator', 'console', 'source', 'operatorImage', 'consoleImage']) {
  test(`history marks a retained ${field} change against the previous older run`, async ({ page }) => {
    await mockDashboard(page, { runs: [
      { ...run, id: 'newer-fixture-run', createdAt: '2026-01-03T00:00:00Z', version: { ...retainedVersion, [field]: 'changed-fixture-value' } },
      { ...run, id: 'middle-fixture-run', createdAt: '2026-01-02T00:00:00Z', version: retainedVersion },
      { ...run, id: 'oldest-fixture-run', createdAt: '2026-01-01T00:00:00Z', version: retainedVersion },
    ] });
    await page.getByRole('button', { name: /^Run history/ }).click();
    const rows = page.locator('.history-row');
    await expect(rows.nth(0).getByText('Version changed since previous run', { exact: true })).toBeVisible();
    await expect(rows.nth(1).locator('.version-change')).toHaveCount(0);
    await expect(rows.nth(2).locator('.version-change')).toHaveCount(0);
    await expect(page.locator('.version-change')).toHaveCount(1);
  });
}

test('history ignores snapshot metadata and object key order when the retained version stays the same', async ({ page }) => {
  const earlierVersion = { ...retainedVersion, apiVersion: undefined, apiReported: { gitCommit: 'compile-fixture-commit', version: 'compile-fixture-a' } };
  await mockDashboard(page, { runs: [
    { ...run, id: 'newer-fixture-run', version: { ...retainedVersion, time: '2026-01-02T00:00:00Z', pods: [{ uid: 'new-pod' }], errors: ['snapshot warning'] } },
    { ...run, id: 'older-fixture-run', version: { ...earlierVersion, time: '2026-01-01T00:00:00Z', pods: [{ uid: 'old-pod' }], errors: [] } },
  ] });
  await page.getByRole('button', { name: /^Run history/ }).click();
  await expect(page.locator('.history-row')).toHaveCount(2);
  await expect(page.locator('.version-change')).toHaveCount(0);
});

test('missing retained versions are explicit and never borrow the current deployment version', async ({ page }) => {
  await mockDashboard(page, { meta: { version: { operator: 'current-fixture-version' } }, runs: [
    { ...run, version: undefined },
    { ...run, id: 'empty-version-run', version: {} },
    { ...run, id: 'recorded-version-run', version: retainedVersion },
  ] });
  await page.getByRole('button', { name: /^Run history/ }).click();
  await expect(page.locator('.history-version').nth(0)).toContainText('Not recorded');
  await expect(page.locator('.history-version').nth(1)).toContainText('Not recorded');
  await expect(page.locator('.history-panel')).not.toContainText('current-fixture-version');
  await expect(page.locator('.version-change')).toHaveCount(0);
  await page.locator('.history-row').nth(0).click();
  const version = page.getByRole('region', { name: 'Tested version', exact: true });
  await expect(version).toContainText('Not recorded');
  await expect(version).not.toContainText('current-fixture-version');
});

test('the request clarification note is visible near the request on both plan and run views', async ({ page }) => {
  await mockDashboard(page, {
    plan: { version: retainedVersion, summary: '', context: '' },
    run: { ...run, version: retainedVersion, summary: '', context: '' },
  });
  await createPlan(page);
  await expect(page.locator('.plan-panel .benchmark-heading .request-version-note')).toHaveText(requestVersionNote);
  await expect(page.getByRole('region', { name: 'Deployed version at planning' })).toContainText(retainedVersion.operator);
  await openRun(page);
  await expect(page.locator('.run-heading .request-version-note')).toHaveText(requestVersionNote);
  await expect(page.locator('.run-heading .request-version-note')).toBeVisible();
});

test('mobile history and run versions wrap without hiding rerun actions or overflowing the page', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockDashboard(page, { run: { ...run, version: retainedVersion } });
  await page.getByRole('button', { name: /^Run history/ }).click();
  await expect(page.locator('.history-version')).toContainText(retainedVersion.source);
  await expect(page.getByRole('button', { name: 'Run again', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.locator('.history-row').click();
  const version = page.getByRole('region', { name: 'Tested version', exact: true });
  await expect(version).toContainText(retainedVersion.operatorImage);
  expect(await version.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Run again', exact: true }).click();
  await expectRerunPrefill(page, run);
});
