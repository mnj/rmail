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
  for (const [path, name] of [
    ['/', 'admin-overview'],
    ['/accounts', 'admin-mailboxes'],
    ['/routing', 'admin-routing'],
    ['/domains', 'admin-domains'],
    ['/delivery', 'admin-delivery'],
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
  // A folder Bob shares with Alice, and sharing one of hers.
  await page.click('text=Team Projects');
  await page.waitForSelector('text=Migration runbook v3');
  await page.waitForTimeout(400);
  await shot(page, 'webmail-shared');
  await page.hover('.folder:has-text("Inbox")');
  await page.click('button[aria-label="Share Inbox"]');
  await page.fill('input[aria-label="Address to share with"]', 'bob@example.com');
  await page.click('.share-add button');
  await page.waitForSelector('.share-list li');
  await shot(page, 'webmail-share-dialog');
  await page.keyboard.press('Escape');
  await ctx.close();
}

// Composing: address suggestions, the rich-text editor and compose settings,
// in light and dark.
async function compose(page, name, mobile = false) {
  if (mobile) await page.click('button[title=Folders]');
  await page.click('.compose-button');
  await page.waitForSelector('.compose .editor-root');
  await page.fill('.compose label:has-text("Subject") input', 'Infrastructure review notes');
  await page.click('.compose .editor-root');
  await page.keyboard.type('Hi Priya,');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await page.keyboard.type('Thanks for the agenda. A few ');
  await page.keyboard.press('Control+b');
  await page.keyboard.type('notes');
  await page.keyboard.press('Control+b');
  await page.keyboard.type(' before Thursday:');
  await page.keyboard.press('Enter');
  await page.click('button[aria-label="Bulleted list"]');
  await page.keyboard.type('Migration is on track for the cut-over weekend');
  await page.keyboard.press('Enter');
  await page.keyboard.type('ACME renewals now run automatically');
  await page.click('.compose input[aria-label=To]');
  await page.keyboard.type('pri');
  await page.waitForSelector('.suggestions li');
  await page.waitForTimeout(300);
  await shot(page, name);
}

for (const theme of ['light', 'dark']) {
  const ctx = await browser.newContext(desktop);
  const page = await ctx.newPage();
  await page.addInitScript((t) => localStorage.setItem('rmail-webmail-theme', t), theme);
  await signIn(page);
  await compose(page, `webmail-compose-${theme}`);
  await page.keyboard.press('Escape');
  await page.click('.compose button[aria-label="Discard"]');
  // Let the "Discarded" notice go before the next shot.
  await page.waitForSelector('.toast', { state: 'detached', timeout: 10000 });
  await page.click('text=Compose settings');
  await page.waitForSelector('.settings-dialog .editor-root');
  await page.waitForTimeout(300);
  await shot(page, `webmail-compose-settings-${theme}`);
  await ctx.close();
}

{
  const ctx = await browser.newContext(mobile);
  const page = await ctx.newPage();
  await signIn(page);
  await page.waitForTimeout(500);
  await shot(page, 'mobile-inbox');
  await page.click('button[title=Folders]');
  await page.waitForTimeout(400);
  await shot(page, 'mobile-folders');
  await page.click('button.folder-name:has-text("Inbox")');
  await page.waitForSelector('.message-list .row');
  await page.waitForTimeout(400);
  await page.click('text=Q4 infrastructure review');
  await page.waitForTimeout(700);
  await shot(page, 'mobile-message');
  await page.click('button[aria-label=Back]');
  await page.waitForTimeout(400);
  await page.click('text=This week: Rust 2024');
  await page.waitForTimeout(900);
  await shot(page, 'mobile-remote-blocked');
  await page.click('button[aria-label=Back]');
  await page.waitForTimeout(300);
  await compose(page, 'mobile-compose', true);
  await ctx.close();
}

await browser.close();
