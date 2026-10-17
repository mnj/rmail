// Capture the admin console and webmail from a running demo instance (see capture.sh)
// and write them as WebP files to the directory given as the first argument.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
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

// The console checks the demo domains' DNS and the machine's own address
// live, but example.com's real zone says nothing about this server and the
// build machine's address has no place in a published image. Rewrite the
// answer to what an admin who published the suggested records would see, with
// a little left to do, so the shots do not depend on the network.
async function showPublishedZone(route) {
  const response = await route.fetch();
  const report = await response.json();
  report.addresses = ['203.0.113.25'];
  const lists = [['zen.spamhaus.org', 'Spamhaus ZEN'], ['bl.spamcop.net', 'SpamCop'], ['b.barracudacentral.org', 'Barracuda'], ['psbl.surriel.com', 'PSBL']];
  report.outbound = {
    port25: { v4: { state: 'open', target: 'gmail-smtp-in.l.google.com' }, v6: { state: 'unavailable' } },
    addresses: [{
      address: '203.0.113.25',
      source: 'seen',
      reverse: { status: 'ok', names: ['mail.example.com'], detail: null },
      blocklists: lists.map(([zone, name]) => ({ zone, name, status: 'clean', code: null, detail: null })),
    }],
  };
  for (const step of report.server) {
    if (['port25', 'reverse_dns', 'blocklists'].includes(step.id)) Object.assign(step, { state: 'done', detail: null });
  }
  // Two weeks of DMARC reports for the first domain, and the advice they lead to.
  report.recommendations.push({
    id: 'dmarc-tighten-example.com',
    title: 'Tighten the DMARC policy of example.com',
    detail: 'In the last 14 days, 26 DMARC reports from google.com, outlook.com, yahoo.com covered 1210 messages claiming to be from example.com, and all but 6 passed. Your own mail is authenticating, so it is safe to change p=none to p=quarantine in the _dmarc.example.com record: receivers will then junk forgeries instead of delivering them.',
    page: 'domains',
  });
  for (const domain of report.domains) {
    const second = domain.domain !== 'example.com';
    domain.provider = second ? null : 'cloudflare';
    if (!second) domain.dmarc_reports = { domain: domain.domain, reports: 26, reporters: ['google.com', 'outlook.com', 'yahoo.com'], messages: 1210, passed: 1204, begin: 0, end: 0, failing: [{ source_ip: '198.51.100.9', messages: 6, dkim: 'fail', spf: 'fail' }] };
    for (const record of domain.records) {
      Object.assign(record, { status: 'ok', published: [record.value], detail: null });
      if (record.name.startsWith('_dmarc.')) {
        Object.assign(record, {
          status: 'improve',
          detail: 'The policy is still p=none: receivers report forgeries but deliver them. Once the reports show your own mail passing, tighten it to quarantine or reject.',
        });
      }
      if (second && record.type === 'SRV') Object.assign(record, { status: 'missing', published: [] });
    }
    for (const step of domain.steps) {
      if (step.id === 'mta_sts') continue; // off in the demo's settings
      if (step.id === 'dkim' && second) continue; // no signing key for this domain
      Object.assign(step, { state: 'done', detail: null });
      if (step.id === 'dmarc') step.detail = domain.records.find((record) => record.name.startsWith('_dmarc.')).detail;
      if (step.id === 'clients' && second) Object.assign(step, { state: 'todo', detail: '5 of 9 records are missing or wrong.' });
    }
  }
  await route.fulfill({ response, json: report });
}

// Admin console
{
  const ctx = await browser.newContext(desktop);
  await ctx.route('**/api/dns-checks', showPublishedZone);
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
    // The checks behind the checklist take a few seconds on a cold start.
    if (path === '/') await page.waitForSelector('.checklist');
    await page.waitForTimeout(1200);
    await shot(page, name);
  }
  // Sharing a domain's free-busy times with the whole server.
  await page.goto(admin + '/accounts');
  const fb = page.locator('tr:has-text("example.com") >> text=Visible to every domain here');
  await fb.scrollIntoViewIfNeeded();
  await fb.click();
  await page.waitForSelector('tr:has-text("example.com") input[type=checkbox]:checked');
  await shot(page, 'admin-directory-freebusy');
  await fb.click();
  await page.waitForTimeout(800);
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
  await page.waitForSelector('.login-panel .sso-button');
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
  await page.click('text=Q4 infrastructure review — agenda');
  await page.waitForTimeout(700);
  await shot(page, 'webmail-message');
  // Dates and a contact found in the agenda mail by the (fake) model.
  await page.click('.ai-actions button:has-text("Find dates and contacts")');
  await page.waitForSelector('.ai-found-item:has-text("Q4 infrastructure review")', { timeout: 30000 });
  await page.waitForTimeout(300);
  await shot(page, 'webmail-ai-found');
  await page.click('.ai-found-item button:has-text("Add to calendar")');
  await page.waitForSelector('.ai-found-item >> text=Added to your calendar');
  await page.click('.ai-found-item button:has-text("Save contact")');
  // Priya is a contact already: her card opens with the new details added.
  await page.waitForFunction(() => [...document.querySelectorAll('.contacts-dialog input')].some((input) => input.value === 'Northwind Traders'));
  await page.click('.contacts-dialog button[aria-label=Close]');
  await page.click('text=This week: Rust 2024');
  await page.waitForTimeout(900);
  await shot(page, 'webmail-remote-blocked');
  await page.click('.message-list >> text=Invitation: Q4 infrastructure review');
  await page.waitForSelector('.invite-card');
  await page.waitForTimeout(500);
  await shot(page, 'webmail-invitation');
  // Answering stores the event and sends the reply through scheduling.
  await page.click('.invite-actions button:has-text("Accept")');
  await page.waitForSelector('.invite-card >> text=You answered: Accepted');
  await page.click('.invite-actions button:has-text("Propose a new time")');
  await page.waitForSelector('.invite-propose');
  await page.fill('.invite-propose textarea', 'Could we start an hour later?');
  await shot(page, 'webmail-invitation-propose');
  await page.click('.invite-propose button:has-text("Cancel")');
  // A guest's proposal for a meeting Alice organizes.
  await page.click('.message-list >> text=New time proposed: Fabrikam onboarding sync');
  await page.waitForSelector('.invite-card >> text=Accept new time');
  await page.waitForTimeout(400);
  await shot(page, 'webmail-invitation-counter');
  // Taking it moves the event and updates the guests.
  await page.click('.invite-actions button:has-text("Accept new time")');
  await page.waitForSelector('.invite-card >> text=Your calendar has this time now');
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
  await page.click('.dialog button[aria-label="Close"]');
  await page.waitForSelector('.dialog-scrim', { state: 'detached' });
  // Filters: a rule that files a newsletter and marks it read.
  await page.click('.sidebar-link:has-text("Filters")');
  await page.waitForSelector('.filters-dialog >> text=No rules yet.');
  await page.click('.filters-dialog button:has-text("New rule")');
  await page.fill('.rule-editor input[placeholder="e.g. Newsletters"]', 'Newsletters');
  await page.fill('.rule-editor input[aria-label=Value]', 'news@northwind.test');
  await page.selectOption('.rule-editor select[aria-label=Folder]', 'Archive');
  await page.click('.rule-editor button:has-text("Add action")');
  await page.waitForTimeout(300);
  await shot(page, 'webmail-filters');
  await page.click('.rule-editor button:has-text("Done")');
  await page.click('.filters-dialog button.primary');
  await page.waitForSelector('.filters-dialog', { state: 'detached' });
  // Out of office until a week from now.
  await page.click('.sidebar-link:has-text("Out of office")');
  await page.check('.dialog[aria-label="Out of office"] input[type=checkbox]');
  const week = new Date(Date.now() + 7 * 86400000);
  const pad = (n) => String(n).padStart(2, '0');
  await page.fill('.dialog[aria-label="Out of office"] input[type=date] >> nth=1', `${week.getFullYear()}-${pad(week.getMonth() + 1)}-${pad(week.getDate())}`);
  await page.fill('.dialog[aria-label="Out of office"] label:has-text("Subject") input', 'Out of office');
  await page.fill('.dialog[aria-label="Out of office"] textarea', "Hi,\n\nI'm at a conference this week with limited email. For anything urgent, please contact bob@example.com.\n\nAlice");
  await page.waitForTimeout(300);
  await shot(page, 'webmail-vacation');
  await page.click('.dialog[aria-label="Out of office"] button.primary');
  await page.waitForSelector('.away-banner');
  await page.waitForTimeout(300);
  await shot(page, 'webmail-away');
  // Contacts: the sender of a message is already a contact (from the seed),
  // so "Add to contacts" opens the card; fill it in.
  await page.click('button.folder-name:has-text("Inbox")');
  await page.click('text=Q4 infrastructure review — agenda');
  await page.click('button:has-text("Add to contacts")');
  await page.waitForSelector('.contact-details');
  await page.click('.contact-actions button:has-text("Edit")');
  await page.click('.contact-editor button:has-text("Add phone")');
  await page.fill('.contact-editor input[aria-label=Phone]', '+45 31 23 45 67');
  await page.fill('.contact-editor label:has-text("Company") input', 'Northwind');
  await page.fill('.contact-editor label:has-text("Job title") input', 'Infrastructure lead');
  await page.click('.contact-editor button.primary');
  await page.waitForSelector('.contact-details >> text=Infrastructure lead');
  await page.waitForTimeout(300);
  await shot(page, 'webmail-contacts');
  await page.click('.contacts-dialog button[aria-label=Close]');
  // Calendar: a meeting with a guest this week, then the month.
  await page.click('.sidebar-link:has-text("Calendar")');
  await page.waitForSelector('.calendar-pane .week');
  await page.click('.calendar-bar button:has-text("New")');
  await page.fill('.event-editor label:has-text("Title") input', 'Design review');
  await page.fill('.event-editor label:has-text("Place") input', 'Room 2');
  await page.fill('.event-editor label:has-text("Guests") input', 'bob@example.com');
  await page.click('.event-editor button.primary');
  await page.waitForSelector('.week-event:has-text("Design review")');
  await page.waitForTimeout(400);
  await shot(page, 'webmail-calendar');
  await page.click('.segmented button:has-text("Month")');
  await page.waitForSelector('.month');
  await page.waitForTimeout(400);
  await shot(page, 'webmail-calendar-month');
  // Tasks: the seeded ones, one added and one ticked off here.
  await page.click('.sidebar-link:has-text("Tasks")');
  await page.waitForSelector('.task-row:has-text("Book flights")');
  await page.fill('input[aria-label="New task"]', 'Order a new laptop dock');
  await page.press('input[aria-label="New task"]', 'Enter');
  await page.waitForSelector('.task-row:has-text("Order a new laptop dock")');
  await page.click('.task-row:has-text("Review the DMARC") input[type=checkbox]');
  await page.click('.calendar-bar label:has-text("Show done") input');
  await page.waitForSelector('.task-group.done .task-row:has-text("Review the DMARC")');
  await page.waitForTimeout(300);
  await shot(page, 'webmail-tasks');
  // Security: an app password for a phone, then the start of 2FA setup.
  await page.click('.sidebar-link:has-text("Security")');
  await page.waitForSelector('.security-dialog >> text=New app password');
  await page.click('.security-dialog button:has-text("New app password")');
  await page.fill('.security-dialog input[placeholder="e.g. iPhone mail"]', 'iPhone mail');
  await page.fill('.security-dialog input[type=password]', password);
  await page.click('.security-dialog button:has-text("Create")');
  await page.waitForSelector('.app-password code');
  await page.waitForTimeout(300);
  await shot(page, 'webmail-app-password');
  await page.click('.security-dialog button:has-text("Done")');
  await page.click('.security-dialog button:has-text("Turn on")');
  await page.fill('.security-dialog input[type=password]', password);
  await page.click('.security-dialog button:has-text("Continue")');
  await page.waitForSelector('.totp-qr svg');
  await page.waitForTimeout(300);
  await shot(page, 'webmail-two-factor');
  await page.click('.security-dialog button:has-text("Cancel")');
  await page.click('.security-dialog button[aria-label=Close]');
  await ctx.close();
}

// Search by meaning: once the classifier has indexed the inbox, "boat trip"
// finds the sailing club's mail, which never says either word.
{
  const ctx = await browser.newContext(desktop);
  const page = await ctx.newPage();
  await signIn(page);
  for (let i = 0; i < 60; i++) {
    const indexed = await page.evaluate(async () => (await (await fetch('/api/organize', { headers: { 'X-Rmail-Webmail': '1' } })).json()).search_indexed);
    if (indexed > 5) break;
    await page.waitForTimeout(1000);
  }
  await page.fill('input[aria-label="Search mail"]', 'boat trip');
  await page.click('.search button.meaning');
  await page.press('input[aria-label="Search mail"]', 'Enter');
  await page.waitForSelector('.folder-title:has-text("Closest to")');
  await page.waitForSelector('.message-list .row:first-child:has-text("Regatta on Saturday")');
  await page.waitForTimeout(300);
  await shot(page, 'webmail-search-meaning');
  // The open message lists others close in meaning, from the same index,
  // once the archived one is indexed too.
  for (let i = 0; i < 60; i++) {
    const found = await page.evaluate(async () => {
      const headers = { 'X-Rmail-Webmail': '1' };
      const list = await (await fetch('/api/folders/INBOX/messages?limit=50', { headers })).json();
      const regatta = list.messages.find((m) => m.subject === 'Regatta on Saturday');
      const related = await (await fetch(`/api/folders/INBOX/messages/${regatta.uid}/related`, { headers })).json();
      return related.messages.some((m) => m.subject === 'Marina berth renewal');
    });
    if (found) break;
    await page.waitForTimeout(1000);
  }
  await openMessage(page, 'Regatta on Saturday');
  await page.waitForSelector('.related li');
  await page.locator('.related').scrollIntoViewIfNeeded();
  await page.waitForTimeout(300);
  await shot(page, 'webmail-related');
  await ctx.close();
}

// A file too large to attach goes as a download link, which works for the
// recipient (here Alice herself) without signing in.
{
  const ctx = await browser.newContext(desktop);
  const page = await ctx.newPage();
  await signIn(page);
  await page.click('.compose-button');
  await page.waitForSelector('.compose .editor-root');
  await page.fill('.compose input[aria-label=To]', 'alice@example.com');
  await page.fill('.compose label:has-text("Subject") input', 'Site photos');
  await page.click('.compose .editor-root');
  await page.keyboard.type('Here are the photos from the data-centre visit.');
  const big = Buffer.alloc(12 * 1024 * 1024, 7);
  const chooser = page.waitForEvent('filechooser');
  await page.click('.compose button[aria-label="Attach files"]');
  await (await chooser).setFiles({ name: 'site-photos.zip', mimeType: 'application/zip', buffer: big });
  await page.click('.link-offer button:has-text("Send as link")');
  await page.waitForSelector('.file-chip.link:has-text("site-photos.zip")', { timeout: 60000 });
  await page.waitForTimeout(300);
  await shot(page, 'webmail-file-link');
  await page.click('.compose button:has-text("Send")');
  await page.waitForSelector('.compose', { state: 'detached', timeout: 20000 });
  await page.click('button.folder-name:has-text("Inbox")');
  for (let i = 0; i < 30 && !(await page.isVisible('.message-list .row:has-text("Site photos")')); i++) {
    await page.waitForTimeout(1000);
    await page.click('button.folder-name:has-text("Sent")');
    await page.click('button.folder-name:has-text("Inbox")');
  }
  await openMessage(page, 'Site photos');
  const link = await page.frameLocator('iframe.html-message').locator('a:has-text("site-photos.zip")').getAttribute('href', { timeout: 10000 });
  const anonymous = await browser.newContext({ ignoreHTTPSErrors: true });
  const response = await anonymous.request.get(link);
  if (response.status() !== 200 || (await response.body()).length !== big.length) throw new Error(`the link gave ${response.status()}`);
  if (!String(response.headers()['content-disposition']).startsWith('attachment')) throw new Error('the link is not a download');
  await anonymous.close();
  await ctx.close();
}

// Files: a folder, an upload, a rename and a download in webmail's Files view.
{
  const ctx = await browser.newContext({ ...desktop, acceptDownloads: true });
  const page = await ctx.newPage();
  await signIn(page);
  await page.click('.sidebar-link:has-text("Files")');
  await page.waitForSelector('.files-dialog >> text=Nothing here yet');
  page.once('dialog', (dialog) => dialog.accept('Projects'));
  await page.click('.files-dialog button:has-text("New folder")');
  await page.click('.files-list button.files-name:has-text("Projects")');
  await page.waitForSelector('.files-path >> text=Projects');
  const chooser = page.waitForEvent('filechooser');
  await page.click('.files-dialog button:has-text("Upload")');
  await (await chooser).setFiles([
    { name: 'migration-plan.pdf', mimeType: 'application/pdf', buffer: Buffer.alloc(240 * 1024, 1) },
    { name: 'budget 2027.xlsx', mimeType: 'application/octet-stream', buffer: Buffer.alloc(56 * 1024, 2) },
  ]);
  await page.waitForSelector('.files-list a.files-name:has-text("budget 2027.xlsx")');
  page.once('dialog', (dialog) => dialog.accept('budget-2027.xlsx'));
  await page.click('.files-list button[aria-label="Rename budget 2027.xlsx"]');
  await page.waitForSelector('.files-list a.files-name:has-text("budget-2027.xlsx")');
  const download = page.waitForEvent('download');
  await page.click('.files-list a[aria-label="Download migration-plan.pdf"]');
  if ((await (await download).createReadStream()) === null) throw new Error('no download');
  await page.waitForTimeout(300);
  await shot(page, 'webmail-files');
  await ctx.close();
}

// Encryption: an OpenPGP key made in the browser and an S/MIME certificate
// imported, mail signed and encrypted with each, then read back. The raw
// messages are left for crypto_check.py to check with GnuPG and OpenSSL.
async function sendProtected(page, to, subject, text, security, technology, passphrase) {
  await page.click('.compose-button');
  await page.waitForSelector('.compose .editor-root');
  await page.fill('.compose input[aria-label=To]', to);
  await page.fill('.compose label:has-text("Subject") input', subject);
  await page.click('.compose .editor-root');
  await page.keyboard.type(text);
  await page.selectOption('.compose select[aria-label="Sign or encrypt"]', security);
  if (technology) await page.selectOption('.compose select[aria-label=With]', technology);
  await page.click('.compose button:has-text("Send")');
  const unlock = page.locator('form[aria-label="Unlock key"]');
  const asked = await Promise.race([
    unlock.waitFor({ timeout: 20000 }).then(() => true),
    page.waitForSelector('.compose', { state: 'detached', timeout: 20000 }).then(() => false),
  ]).catch(() => false);
  if (asked) {
    await unlock.locator('input[type=password]').fill(passphrase);
    await unlock.locator('button:has-text("Unlock")').click();
  }
  await page.waitForSelector('.compose', { state: 'detached', timeout: 20000 }).catch(async (err) => {
    const problem = await page.locator('.compose-error').textContent().catch(() => null);
    throw new Error(`sending "${subject}" failed: ${problem ?? err.message}`);
  });
}

async function openMessage(page, subject) {
  for (let i = 0; i < 5; i++) {
    await page.click(`.message-list .row:has-text("${subject}")`);
    if (await page.waitForSelector(`.subject-line:has-text("${subject}")`, { timeout: 3000 }).then(() => true, () => false)) return;
  }
  throw new Error(`could not open "${subject}"`);
}

async function saveRaw(page, folder, subject, file) {
  const raw = await page.evaluate(async ([folder, subject]) => {
    const headers = { 'X-Rmail-Webmail': '1' };
    const list = await (await fetch(`/api/folders/${encodeURIComponent(folder)}/messages?limit=50`, { headers })).json();
    const message = list.messages.find((m) => m.subject === subject);
    return (await fetch(`/api/folders/${encodeURIComponent(folder)}/messages/${message.uid}/raw`, { headers })).text();
  }, [folder, subject]);
  writeFileSync(join(process.env.DEMO_DIR, 'crypto', file), raw);
}

if (process.env.DEMO_DIR) {
  const ctx = await browser.newContext({ ...desktop, acceptDownloads: true });
  const page = await ctx.newPage();
  await signIn(page);
  const phrase = 'correct horse battery';
  await page.click('.sidebar-link:has-text("Encryption")');
  await page.waitForSelector('.crypto-dialog');
  await page.click('.crypto-dialog button:has-text("New OpenPGP key")');
  await page.fill('.crypto-dialog label:has-text("Your name") input', 'Alice Chen');
  await page.fill('.crypto-dialog label:has-text("Passphrase to lock it") input', phrase);
  await page.fill('.crypto-dialog label:has-text("Again") input', phrase);
  await page.click('.crypto-dialog button:has-text("Create key")');
  await page.waitForSelector('.crypto-keys li:has-text("Alice Chen <alice@example.com>")', { timeout: 30000 });
  await page.click('.crypto-dialog button:has-text("Import S/MIME certificate")');
  await page.setInputFiles('.crypto-dialog input[type=file]', join(process.env.DEMO_DIR, 'alice.p12'));
  await page.fill('.crypto-dialog label:has-text("The file\'s password") input', password);
  await page.fill('.crypto-dialog label:has-text("Passphrase to lock it here") input', phrase);
  await page.click('.crypto-dialog button:has-text("Import")');
  await page.waitForSelector('.crypto-keys li:has-text("S/MIME")', { timeout: 30000 });
  await page.waitForTimeout(300);
  await shot(page, 'webmail-encryption');
  const download = page.waitForEvent('download');
  await page.click('.crypto-dialog button[aria-label="Download public key"]');
  await (await download).saveAs(join(process.env.DEMO_DIR, 'crypto', 'alice.asc'));
  await page.click('.crypto-dialog button[aria-label=Close]');

  await sendProtected(page, 'alice@example.com', 'OpenPGP hello', 'Only you can read this.', 'sign-encrypt', 'pgp', phrase);
  await sendProtected(page, 'alice@example.com', 'S/MIME hello', 'Sealed with S/MIME.', 'sign-encrypt', 'smime', phrase);
  await sendProtected(page, 'bob@example.com', 'OpenPGP signed', 'Signed, not sealed.', 'sign', 'pgp', phrase);
  await sendProtected(page, 'bob@example.com', 'S/MIME signed', 'Signed with a certificate.', 'sign', 'smime', phrase);

  await page.click('button.folder-name:has-text("Inbox")');
  // Delivery to the inbox takes a moment.
  for (let i = 0; i < 30 && !(await page.isVisible('.message-list >> text=S/MIME hello')); i++) {
    await page.waitForTimeout(1000);
    await page.click('button.folder-name:has-text("Sent")');
    await page.click('button.folder-name:has-text("Inbox")');
  }
  await openMessage(page, 'OpenPGP hello');
  await page.click('.crypto-locked button:has-text("Decrypt")');
  await page.waitForSelector('.crypto-badge.valid', { timeout: 20000 });
  await page.frameLocator('.crypto-panel iframe').locator('text=Only you can read this.').waitFor();
  await page.waitForTimeout(300);
  await shot(page, 'webmail-decrypted');
  await openMessage(page, 'S/MIME hello');
  await page.click('.crypto-locked button:has-text("Decrypt")');
  await page.waitForSelector('.crypto-badge.valid', { timeout: 20000 });
  await page.frameLocator('.crypto-panel iframe').locator('text=Sealed with S/MIME.').waitFor();
  await page.click('button.folder-name:has-text("Sent")');
  await openMessage(page, 'OpenPGP signed');
  await page.waitForSelector('.crypto-badge.valid', { timeout: 20000 });
  await openMessage(page, 'S/MIME signed');
  await page.waitForSelector('.crypto-badge.valid', { timeout: 20000 });
  // Keys moved to the server work in a fresh tab, after the passphrase.
  await page.click('.sidebar-link:has-text("Encryption")');
  await page.click('.crypto-choice label:has-text("On the server")');
  await page.waitForSelector('.crypto-choice label.selected:has-text("On the server")');
  await page.waitForSelector('.crypto-keys li:has-text("S/MIME")');
  await page.click('.crypto-dialog button[aria-label=Close]');
  await page.reload();
  await page.waitForSelector('.message-list .row');
  await page.click('button.folder-name:has-text("Inbox")');
  await openMessage(page, 'S/MIME hello');
  await page.click('.crypto-locked button:has-text("Decrypt")');
  const unlock = page.locator('form[aria-label="Unlock key"]');
  await unlock.locator('input[type=password]').fill(phrase);
  await unlock.locator('button:has-text("Unlock")').click();
  await page.waitForSelector('.crypto-badge.valid', { timeout: 20000 });
  await page.frameLocator('.crypto-panel iframe').locator('text=Sealed with S/MIME.').waitFor();
  for (const [folder, subject, file] of [
    ['Sent', 'OpenPGP signed', 'pgp-signed.eml'], ['Sent', 'S/MIME signed', 'smime-signed.eml'],
    ['INBOX', 'OpenPGP hello', 'pgp-encrypted.eml'], ['INBOX', 'S/MIME hello', 'smime-encrypted.eml'],
  ]) await saveRaw(page, folder, subject, file);
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

// Writing suggestions (answered by fake_ai.py): ghost text after the caret,
// then a rewrite of the selection.
async function ghostText(page, name, mobile = false) {
  if (mobile) await page.click('button[title=Folders]');
  await page.click('.compose-button');
  await page.waitForSelector('.compose .editor-root');
  await page.fill('.compose input[aria-label=To]', 'Priya Raman <priya@northwind.test>');
  await page.fill('.compose label:has-text("Subject") input', 'Re: Q4 infrastructure review — agenda');
  await page.click('.compose .editor-root');
  await page.keyboard.type('Hi Priya,');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await page.keyboard.type('Thanks for the agenda. Could we add a short item on');
  await page.waitForSelector('.ghost-text:not([hidden])');
  await page.waitForTimeout(200);
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
  if (theme === 'light') {
    await page.click('.settings-dialog button:has-text("Cancel")');
    await ghostText(page, 'webmail-compose-ai');
    await page.keyboard.press('Tab');
    await page.evaluate(() => {
      const root = document.querySelector('.compose .editor-root');
      root.focus();
      const block = [...root.children].find((element) => element.textContent.startsWith('Thanks'));
      const range = document.createRange();
      range.selectNodeContents(block);
      getSelection().removeAllRanges();
      getSelection().addRange(range);
    });
    await page.click('.compose button[aria-label="Rewrite selection"]');
    await page.click('.rewrite-menu button:has-text("More formal")');
    await page.waitForSelector('.rewrite-result');
    await page.waitForTimeout(200);
    await shot(page, 'webmail-compose-rewrite');
  }
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
  await page.click('text=Q4 infrastructure review — agenda');
  await page.waitForTimeout(700);
  await shot(page, 'mobile-message');
  await page.click('button[aria-label=Back]');
  await page.waitForTimeout(400);
  await page.click('text=This week: Rust 2024');
  await page.waitForTimeout(900);
  await shot(page, 'mobile-remote-blocked');
  await page.click('button[aria-label=Back]');
  await page.waitForTimeout(300);
  await page.click('.message-list >> text=Invitation: Q4 infrastructure review');
  await page.waitForSelector('.invite-card');
  await page.waitForTimeout(500);
  await shot(page, 'mobile-invitation');
  await page.click('button[aria-label=Back]');
  await page.waitForTimeout(300);
  await page.click('button[title=Folders]');
  await page.click('.sidebar-link:has-text("Contacts")');
  await page.waitForSelector('.contacts-list');
  await page.waitForTimeout(300);
  await shot(page, 'mobile-contacts');
  await page.click('.contacts-list button:has-text("Priya Raman")');
  await page.waitForSelector('.contact-details');
  await page.waitForTimeout(300);
  await shot(page, 'mobile-contact');
  await page.click('.contacts-dialog button[aria-label=Close]');
  await page.click('.sidebar-link:has-text("Calendar")');
  await page.waitForSelector('.calendar-pane .agenda, .calendar-pane .agenda-empty');
  await page.waitForTimeout(400);
  await shot(page, 'mobile-calendar');
  await page.click('.calendar-pane button[aria-label=Folders]');
  await page.click('button.folder-name:has-text("Inbox")');
  await page.waitForTimeout(300);
  await compose(page, 'mobile-compose', true);
  await page.keyboard.press('Escape');
  await page.click('.compose button[aria-label="Discard"]');
  await page.waitForSelector('.toast', { state: 'detached', timeout: 10000 });
  await ghostText(page, 'mobile-compose-ai', true);
  await ctx.close();
}

// Single sign-on: the button goes to the provider and back, signed in.
{
  const ctx = await browser.newContext(desktop);
  const page = await ctx.newPage();
  await page.goto(webmail);
  await page.click('.login-panel .sso-button');
  await page.waitForSelector('.message-list .row');
  console.log('Single sign-on check: good');
  await ctx.close();
}

await browser.close();
