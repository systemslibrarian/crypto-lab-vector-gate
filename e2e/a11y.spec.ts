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
 expect(errors).toEqual([]);
});
