// Capture the admin console and webmail from a running demo instance (see capture.sh)
// and write them as WebP files to the directory given as the first argument.
import { chromium } from 'playwright';

const out = process.argv[2];
const password = 'Demo-pass-123';
const admin = 'https://127.0.0.1:18080';
const webmail = 'https://127.0.0.1:18081';

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const encoder = await browser.newPage();

// Playwright only writes PNG/JPEG; re-encode through a canvas to get WebP.
async function shot(page, name) {
  const png = (await page.screenshot()).toString('base64');
  const webp = await encoder.evaluate(async (data) => {
    const img = new Image();
    img.src = `data:image/png;base64,${data}`;
    await img.decode();
    const canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    canvas.getContext('2d').drawImage(img, 0, 0);
    return canvas.toDataURL('image/webp', 0.85).split(',')[1];
  }, png);
  const { writeFile } = await import('node:fs/promises');
  await writeFile(`${out}/${name}.webp`, Buffer.from(webp, 'base64'));
  console.log(`  ${name}.webp`);
}

const desktop = { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, ignoreHTTPSErrors: true };
const mobile = { viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true, ignoreHTTPSErrors: true };

// Admin console
{
  const ctx = await browser.newContext(desktop);
  const page = await ctx.newPage();
  await page.goto(admin);
  await page.waitForSelector('input[type=password]');
  await shot(page, 'admin-login');
  await page.fill('input[type=password]', password);
  await page.click('button.primary');
  await page.waitForSelector('.sidebar');
  // Delivery is left out until its queue table handles long error messages.
  for (const [path, name] of [
    ['/', 'admin-overview'],
    ['/accounts', 'admin-mailboxes'],
    ['/routing', 'admin-routing'],
    ['/settings', 'admin-settings'],
    ['/observability', 'admin-observability'],
    ['/system', 'admin-system'],
  ]) {
    await page.goto(admin + path);
    await page.waitForSelector('.sidebar');
    await page.waitForTimeout(1200);
    await shot(page, name);
  }
  await ctx.close();
}

// Webmail
async function signIn(page) {
  await page.goto(webmail);
  await page.waitForSelector('.login-panel');
  await page.fill('input[autocomplete=username]', 'alice@example.com');
  await page.fill('input[type=password]', password);
  await page.click('button[type=submit]');
  await page.waitForSelector('.message-list .row');
}

{
  const ctx = await browser.newContext(desktop);
  const page = await ctx.newPage();
  await page.goto(webmail);
  await page.waitForSelector('.login-panel');
  await shot(page, 'webmail-login');
  await signIn(page);
  // Read a few messages so the list shows both read and unread mail.
  for (const subject of ['Lunch Friday?', 'CI passed on main', 'Photos from the offsite', 'Report domain']) {
    await page.click(`text=${subject}`);
    await page.waitForTimeout(400);
  }
  await page.reload();
  await page.waitForSelector('.message-list .row');
  await page.waitForTimeout(500);
  await shot(page, 'webmail-inbox');
  await page.click('text=Q4 infrastructure review');
  await page.waitForTimeout(700);
  await shot(page, 'webmail-message');
  await page.click('text=This week: Rust 2024');
  await page.waitForTimeout(900);
  await shot(page, 'webmail-remote-blocked');
  await ctx.close();
}

{
  const ctx = await browser.newContext(mobile);
  const page = await ctx.newPage();
  await signIn(page);
  await page.waitForTimeout(500);
  await shot(page, 'mobile-inbox');
  await page.click('text=Q4 infrastructure review');
  await page.waitForTimeout(700);
  await shot(page, 'mobile-message');
  await page.click('.back');
  await page.waitForTimeout(400);
  await page.click('text=This week: Rust 2024');
  await page.waitForTimeout(900);
  await shot(page, 'mobile-remote-blocked');
  await ctx.close();
}

await browser.close();
