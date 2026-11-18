import { test, expect, type Locator, type Page } from '@playwright/test';
import { boot } from './gate';

/* Exhibit 07, the negative-test bench.
 *
 * The unit suite (src/bench/cases.test.ts) pins what each toy computes. This
 * spec pins that the production page really runs them and renders what they
 * found: vectors matching as shipped, the negative test failing, the repair
 * making it pass, and a verdict from one setting never standing under the other.
 *
 * Numbers are read off the page and compared with each other wherever the page
 * prints both sides. The few literals below are structural facts of the toys
 * (512 single-bit changes to a 64-byte ciphertext, 64 bytes drawn) that the
 * unit suite derives.
 */

const card = (page: Page, id: string): Locator => page.locator(`[data-bench="${id}"]`);
const negative = (c: Locator): Locator => c.locator('[data-field="negative"]');
const measure = (c: Locator, label: string): Locator =>
  negative(c).locator('dt', { hasText: label }).locator('xpath=following-sibling::dd[1]');

async function ready(page: Page): Promise<void> {
  await boot(page);
  await expect(page.locator('#bench-tally')).toHaveAttribute('data-matching', /\d+/);
}

test('bench: every implementation matches its stored vectors as shipped, and every negative test fails', async ({ page }) => {
  await ready(page);
  const cards = page.locator('.bench-case');
  const count = await cards.count();
  expect(count).toBeGreaterThan(1);
  // The tally is the number of cards whose own line says all vectors matched.
  await expect(page.locator('#bench-tally')).toHaveAttribute('data-matching', String(count));
  await expect(page.locator('#bench-heading')).toContainText(`${count} more implementations`);

  for (let i = 0; i < count; i++) {
    const c = cards.nth(i);
    const kat = c.locator('[data-field="kat"]');
    await expect(kat).toHaveAttribute('data-matched', /\d+/);
    expect(await kat.getAttribute('data-matched')).toBe(await kat.getAttribute('data-total'));
    await expect(kat).toContainText('✓ Known-answer tests');
    // Nothing is claimed about the negative test until it is run.
    await expect(negative(c)).toHaveAttribute('data-outcome', 'NOT-RUN');
    await c.locator('[data-action="negative"]').click();
    await expect(negative(c)).toHaveAttribute('data-outcome', 'FAIL');
    await expect(negative(c).locator('[data-verdict="negative"]')).toHaveText('✗ Negative test FAILED');
    // Each card names the report it is modelled on, and says it is a toy.
    await expect(c.locator('.bench-model')).toContainText('Modelled on the reported');
    await expect(c.locator('.bench-model')).toContainText('not the submitted code');
    expect(new URL((await c.locator('.bench-model a').getAttribute('href'))!).hostname).toBe('ngcc.dev');
  }
});

test('bench: the repair makes each negative test pass, and retires the verdict from the other setting', async ({ page }) => {
  await ready(page);
  const cards = page.locator('.bench-case');
  const count = await cards.count();
  let keeps = 0;
  for (let i = 0; i < count; i++) {
    const c = cards.nth(i);
    await c.locator('[data-action="negative"]').click();
    await expect(negative(c)).toHaveAttribute('data-outcome', 'FAIL');

    await c.locator('[data-action="repair"]').check();
    // The failing verdict was computed for the shipped code; it must not stand.
    await expect(negative(c)).toHaveAttribute('data-outcome', 'NOT-RUN');
    await expect(c).toHaveAttribute('data-repaired', 'true');
    const kat = c.locator('[data-field="kat"]');
    await expect(kat).toHaveAttribute('data-matched', /\d+/);
    if ((await kat.getAttribute('data-matched')) === (await kat.getAttribute('data-total'))) {
      keeps += 1;
      await expect(kat).toContainText('with the repair in place');
    } else {
      await expect(kat).toContainText('they encode the bug');
    }

    await c.locator('[data-action="negative"]').click();
    await expect(negative(c)).toHaveAttribute('data-outcome', 'PASS');
    await expect(negative(c).locator('[data-verdict="negative"]')).toHaveText('✓ Negative test PASSED');

    // And back: the passing verdict is retired too, and the bug is still there.
    await c.locator('[data-action="repair"]').uncheck();
    await expect(negative(c)).toHaveAttribute('data-outcome', 'NOT-RUN');
    await c.locator('[data-action="negative"]').click();
    await expect(negative(c)).toHaveAttribute('data-outcome', 'FAIL');
  }
  // The closing paragraph's two counts are the ones just observed.
  await expect(page.locator('#bench-keeps')).toHaveText(`${keeps} of the ${count}`);
  await expect(page.locator('#bench-breaks')).toHaveText(String(count - keeps));
  expect(keeps).toBeGreaterThan(0);
  expect(count - keeps).toBeGreaterThan(0);
});

test('bench: the measurements are the ones the toys produce', async ({ page }) => {
  await ready(page);

  // Dead rejection: 512 single-bit changes, and exactly the check half is blind.
  const dead = card(page, 'rejection-never-applied');
  await dead.locator('[data-action="negative"]').click();
  await expect(measure(dead, 'Single-bit ciphertext changes tried')).toHaveText('512');
  await expect(measure(dead, 'Returned the original secret')).toHaveText('256');

  // Partial mask: the weaker test passes, which is why the card uses a stronger one.
  const mask = card(page, 'rejection-mask-partial');
  await mask.locator('[data-action="negative"]').click();
  await expect(measure(mask, 'The weaker test')).toHaveText('0 of 512');
  await expect(negative(mask)).toHaveAttribute('data-outcome', 'FAIL');

  // Every fourth byte: nothing escapes at a checked position.
  const fourth = card(page, 'compare-every-fourth-byte');
  await fourth.locator('[data-action="negative"]').click();
  await expect(measure(fourth, '≡ 0 (mod 4)')).toHaveText('0');
  for (const offset of [1, 2, 3]) await expect(measure(fourth, `≡ ${offset} (mod 4)`)).not.toHaveText('0');

  // Bits versus bytes: consumed bits are eight times the bytes that mattered.
  const bits = card(page, 'bits-versus-bytes');
  await bits.locator('[data-action="negative"]').click();
  const used = Number(await measure(bits, 'Random bytes that change the secret').innerText());
  const drawn = Number(await measure(bits, 'Random bytes drawn').innerText());
  expect(used).toBeLessThan(drawn);
  await expect(measure(bits, 'Bits of randomness actually consumed')).toHaveText(String(used * 8));
  await bits.locator('[data-action="repair"]').check();
  await bits.locator('[data-action="negative"]').click();
  await expect(measure(bits, 'Random bytes that change the secret')).toHaveText(String(drawn));

  // Ignored generator: the two keys on the page are equal as shipped.
  const rng = card(page, 'keygen-ignores-rng');
  await rng.locator('[data-action="negative"]').click();
  const a = await measure(rng, 'Public key from seed A').innerText();
  expect(await measure(rng, 'Public key from seed B').innerText()).toBe(a);
  await rng.locator('[data-action="repair"]').check();
  await rng.locator('[data-action="negative"]').click();
  expect(await measure(rng, 'Public key from seed B').innerText()).not.toBe(await measure(rng, 'Public key from seed A').innerText());

  // Padding: one fewer distinct digest than messages, and the pair is named.
  const padding = card(page, 'padding-collision');
  await padding.locator('[data-action="negative"]').click();
  const hashed = Number(await measure(padding, 'Messages hashed').innerText());
  const distinct = Number(await measure(padding, 'Distinct digests').innerText());
  const pairs = Number(await measure(padding, 'Colliding pairs').innerText());
  expect(hashed - distinct).toBe(pairs);
  expect(pairs).toBe(1);
  await expect(negative(padding).locator('[data-field="summary"]')).toContainText('the empty message and the 7-bit message 0000000');
});

test('bench: it is independent of the switch above, and carries its status and labels', async ({ page }) => {
  await ready(page);
  const verifier = card(page, 'verifier-returns-success');
  await verifier.locator('[data-action="negative"]').click();
  await expect(negative(verifier)).toHaveAttribute('data-outcome', 'FAIL');
  const before = await negative(verifier).innerText();

  // Entering broken mode re-runs the Ed25519 exhibits. The bench is not theirs.
  await page.locator('#enter-broken').click();
  await expect(page.locator('#app')).toHaveAttribute('data-range', 'omitted');
  expect(await negative(verifier).innerText()).toBe(before);
  // And the centrepiece is untouched by the bench: the hostile case is accepted
  // because of the switch, exactly as before.
  await expect(page.locator('#case-results .case').nth(2).locator('[data-verdict="decision"]')).toHaveAttribute('data-outcome', 'ACCEPT');

  const status = page.locator('#bench-status');
  await expect(status).toContainText('As of November 2026, NGCC is in its first round');
  await expect(status).toContainText('Every implementation below is modelled');
  await expect(status).toContainText('Nothing in round one is standardized or deployed');
  // The one finding the primary report classes as design is labelled as such.
  await expect(card(page, 'challenge-read-mod-2').locator('.bench-model')).toContainText('classed there as design');
  await expect(card(page, 'verifier-returns-success').locator('.bench-model')).toContainText('classed there as implementation');
  // The bench does not push the page sideways.
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});
