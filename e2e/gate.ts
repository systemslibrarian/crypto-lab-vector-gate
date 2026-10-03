// Adapted from crypto-lab-schnorr-forge's current gate (fetched 2026-10-02).
// Retains separate WCAG/landmark scans, incomplete-result enforcement, composite
// text contrast, and per-side non-text measurements. No injected styles or exemptions.
import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';
export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
export const NARROW = { width: 380, height: 800 };
export async function boot(page: Page) {
 await page.emulateMedia({ reducedMotion:'reduce' });
 await page.goto('./');
 await expect(page.locator('#app')).toHaveAttribute('data-ready','true');
 await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
 await expect(page.locator('h1')).toHaveCount(1);
 await expect(page.locator('[role="banner"]')).toHaveCount(1);
 await expect(page.locator('#repair')).toBeChecked();
 await expect(page.locator('details[open]')).toHaveCount(0);
 expect(await page.evaluate(()=>matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
}
export async function settle(page: Page) {
 await page.waitForFunction(()=>document.getAnimations().every(a=>a.playState!=='running'));
}
export async function scan(page: Page,label: string) {
 await settle(page);
 const wcag=await new AxeBuilder({page}).withTags(TAGS).analyze();
 const landmarks=await new AxeBuilder({page}).withRules(['landmark-no-duplicate-banner','landmark-unique','landmark-one-main','landmark-complementary-is-top-level']).analyze();
 expect([...wcag.violations,...landmarks.violations].map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),`axe violations: ${label}`).toEqual([]);
 expect([...wcag.incomplete,...landmarks.incomplete].filter(v=>v.id!=='color-contrast').map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),`unexplained axe incomplete: ${label}`).toEqual([]);
 expect(formatContrastFailures(await auditContrast(page)),`measured text contrast: ${label}`).toEqual([]);
 expect(formatContrastFailures(await auditContrast(page,'[aria-hidden="true"], [aria-hidden="true"] *',true)),`aria-hidden contrast: ${label}`).toEqual([]);
 expect(formatNonTextFailures(await auditNonText(page)),`non-text contrast: ${label}`).toEqual([]);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`page reflow: ${label}`).toBe(true);
 const unreachable=await page.locator('.byte-panel').evaluateAll(nodes=>nodes.filter(n=>n.scrollWidth>n.clientWidth&&(!(n as HTMLElement).hasAttribute('tabindex')||!n.hasAttribute('aria-label'))).length);
 expect(unreachable,`keyboard-reachable hex regions: ${label}`).toBe(0);
}
