import { test, expect } from '@playwright/test';
import { boot, scan } from './gate';
for(const width of [1280,380,320])test(`WCAG gate: dark theme / ${width}px`,async({page})=>{
 await page.setViewportSize({width,height:900});
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 await boot(page);await scan(page,'arrival');
 await page.keyboard.press('Tab');await expect(page.locator('.cl-skip-link')).toBeFocused();await scan(page,'skip link focus');
 await page.getByRole('radio',{name:'The system is secure',exact:true}).check();await scan(page,'prediction feedback');
 await page.locator('#enter-broken').click();await expect(page.locator('#app')).toHaveAttribute('data-range','omitted');await scan(page,'hostile accepted');
 for(const summary of await page.locator('summary').all()){await summary.click();await scan(page,'disclosure open');}
 await page.locator('#repair').focus();await page.keyboard.press('Space');
 await expect(page.locator('#app')).toHaveAttribute('data-range','enforced');await scan(page,'same hostile bytes rejected');
 // Exhibit 07. One card is driven through every colour it can render: a failed
 // negative test, a known-answer line that stops matching under the repair, and
 // a passed negative test. The cards share one renderer.
 const bench=page.locator('[data-bench="padding-collision"]');
 await expect(page.locator('#bench-tally')).toHaveAttribute('data-matching',/\d+/);await scan(page,'bench: stored vectors match as shipped');
 await bench.locator('[data-action="negative"]').click();await expect(bench.locator('[data-field="negative"]')).toHaveAttribute('data-outcome','FAIL');await scan(page,'bench: negative test failed');
 await bench.locator('[data-action="repair"]').focus();await page.keyboard.press('Space');
 await expect(bench.locator('[data-field="kat"]')).toContainText('encode the bug');await scan(page,'bench: repaired, stored vectors no longer match');
 await bench.locator('[data-action="negative"]').click();await expect(bench.locator('[data-field="negative"]')).toHaveAttribute('data-outcome','PASS');await scan(page,'bench: negative test passed');
 expect(errors).toEqual([]);
});
