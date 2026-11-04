import { test, expect, type BrowserContext, type Page } from '@playwright/test';

// The whole hub in a real browser: Telegram and passkey logins, per-app login methods, step-up,
// denial, logout everywhere, enrollment by link on another device, and the admin UI. The tests
// share one database and run in order. Every page is watched for CSP violations.

const HUB = 'http://localhost:4455';
const TG = 'http://127.0.0.1:4454';
const app = {
	tg: 'http://127.0.0.1:4461', // Telegram only: Alice, Bob
	pk: 'http://127.0.0.1:4462', // passkey only: Alice, Bob, Carol
	both: 'http://127.0.0.1:4463', // either: group club (Alice)
	closed: 'http://127.0.0.1:4464' // Telegram only: Bob
};

const violations: string[] = [];

/** SCREENSHOTS=dir saves the admin UI's pages there, for a look by eye. */
async function shot(page: Page, name: string) {
	if (process.env.SCREENSHOTS) await page.screenshot({ path: `${process.env.SCREENSHOTS}/${name}.png`, fullPage: true });
}

function watch(page: Page) {
	page.on('console', (msg) => {
		const text = msg.text();
		if (/Content Security Policy|Refused to (load|execute|apply|connect)/i.test(text)) violations.push(`${page.url()}: ${text}`);
	});
	page.on('pageerror', (err) => violations.push(`${page.url()}: ${err.message}`));
}

/** Chromium's virtual authenticator answers passkey prompts itself, with user verification. */
async function withPasskeys(context: BrowserContext, page: Page) {
	const cdp = await context.newCDPSession(page);
	await cdp.send('WebAuthn.enable');
	await cdp.send('WebAuthn.addVirtualAuthenticator', {
		options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true }
	});
}

async function device(context: BrowserContext) {
	const page = await context.newPage();
	watch(page);
	await withPasskeys(context, page);
	return page;
}

/** The app's page after a login: who it says, and how they proved it. */
async function expectIn(page: Page, origin: string, sub: string, amr: string) {
	await expect(page).toHaveURL(`${origin}/`);
	await expect(page.locator('#who')).toHaveAttribute('data-sub', sub);
	await expect(page.locator('#who')).toHaveAttribute('data-amr', amr);
}

async function botMessages(page: Page): Promise<string[]> {
	const res = await page.request.get(`${TG}/bot-messages`);
	return res.json();
}

test.describe.serial('login hub', () => {
	let alice: Page;
	let aliceContext: BrowserContext;
	let telegramScreens = 0;

	test.beforeAll(async ({ browser }) => {
		aliceContext = await browser.newContext();
		alice = await device(aliceContext);
		alice.on('request', (r) => {
			if (r.isNavigationRequest() && r.url().startsWith(`${TG}/auth`)) telegramScreens++;
		});
	});

	test.afterAll(async () => {
		await aliceContext.close();
		expect(violations, 'CSP violations or page errors').toEqual([]);
	});

	test('Telegram login on a Telegram-only app', async () => {
		await alice.goto(app.tg);
		await alice.locator('#login').click();
		await expect(alice).toHaveURL(/127\.0\.0\.1:4454\/auth/);
		await alice.getByRole('link', { name: 'Войти как Alice Telegram' }).click();
		await expectIn(alice, app.tg, 'Alice', 'telegram');
		expect(telegramScreens).toBe(1);
	});

	test('a second app opens without the Telegram screen', async () => {
		await alice.goto(app.both);
		await alice.locator('#login').click();
		await expectIn(alice, app.both, 'Alice', 'telegram');
		expect(telegramScreens).toBe(1);
	});

	test('an app she is not allowed in says so, and the bot tells the admin', async () => {
		await alice.goto(app.closed);
		await alice.locator('#login').click();
		await expect(alice.getByRole('heading', { name: 'Нет доступа' })).toBeVisible();
		await expect(alice.getByText('«Closed App»')).toBeVisible();
		await expect.poll(async () => (await botMessages(alice)).join('\n')).toContain('Closed App');
	});

	test('a passkey-only app asks for a passkey she does not have yet', async () => {
		await alice.goto(app.pk);
		await alice.locator('#login').click();
		await expect(alice.getByRole('heading', { name: 'Нужен passkey' })).toBeVisible();
	});

	test('she adds a passkey on this device from the hub', async () => {
		await alice.goto(HUB);
		await alice.getByRole('link', { name: 'Добавить passkey на этом устройстве' }).click();
		await alice.getByLabel('Как назвать это устройство').fill('Chrome');
		await alice.getByRole('button', { name: 'Создать passkey' }).click();
		await expect(alice.getByText('Готово: passkey сохранён')).toBeVisible();
		await expect.poll(async () => (await botMessages(alice)).join('\n')).toContain('Новый passkey: Alice («Chrome»');
	});

	test('now the passkey-only app opens silently, with both proofs', async () => {
		await alice.goto(app.pk);
		await alice.locator('#login').click();
		await expectIn(alice, app.pk, 'Alice', 'telegram,passkey');
	});

	test('logout everywhere asks first, then every app needs a login again', async () => {
		await alice.goto(app.tg);
		await alice.locator('#logout').click();
		await expect(alice.getByRole('heading', { name: 'Выйти на всех сайтах?' })).toBeVisible();
		await alice.getByRole('button', { name: 'Выйти на всех сайтах' }).click();
		await expect(alice).toHaveURL(`${app.tg}/`);
		await expect(alice.locator('#anon')).toBeVisible();

		// the hub forgot her
		await alice.goto(HUB);
		await expect(alice.getByRole('heading', { name: 'Один вход на все сайты' })).toBeVisible();

		// other apps keep their own sessions until they re-check; end this one to see the hub ask
		await aliceContext.clearCookies({ name: 'rp_session_both-app' });
		await alice.goto(app.both);
		await alice.locator('#login').click();
		await expect(alice.getByRole('heading', { name: 'Вход на «Both App»' })).toBeVisible();
		await expect(alice.getByRole('link', { name: 'Войти через Telegram' })).toBeVisible();
		await expect(alice.getByRole('link', { name: 'Войти с passkey' })).toBeVisible();
	});

	test('passkey login from the chooser', async () => {
		await alice.getByRole('link', { name: 'Войти с passkey' }).click();
		await expect(alice.getByRole('heading', { name: 'Вход с passkey' })).toBeVisible();
		await alice.getByRole('button', { name: 'Войти с passkey' }).click();
		await expectIn(alice, app.both, 'Alice', 'passkey');
	});

	test('a Telegram-only app asks for Telegram on top of the passkey', async () => {
		await alice.goto(app.tg);
		await alice.locator('#login').click();
		await expect(alice.getByText('нужен вход через Telegram')).toBeVisible();
		await alice.getByRole('link', { name: 'Войти через Telegram' }).click();
		await alice.getByRole('link', { name: 'Войти как Alice Telegram' }).click();
		await expectIn(alice, app.tg, 'Alice', 'telegram,passkey');
	});

	let carolLink = '';

	test('admin UI: people, a passkey link, a new person, groups, apps, the audit log', async () => {
		await alice.goto(`${HUB}/admin`);
		await expect(alice.getByRole('heading', { name: 'Люди' })).toBeVisible();
		for (const name of ['Алиса', 'Боб', 'Кэрол']) await expect(alice.getByRole('article', { name })).toBeVisible();
		await expect(alice.getByRole('article', { name: 'Алиса' }).getByText('🔑 Chrome')).toBeVisible();

		const carol = alice.getByRole('article', { name: 'Кэрол' });
		await carol.getByRole('button', { name: 'Ссылка для passkey' }).click();
		const link = carol.locator('.success .mono');
		await expect(link).toContainText(`${HUB}/enroll?t=`);
		carolLink = (await link.textContent())!.trim();

		await alice.getByLabel('Ключ').fill('Erin');
		await alice.getByLabel('Имя', { exact: true }).last().fill('Эрин');
		await alice.getByRole('button', { name: 'Добавить' }).click();
		await expect(alice.getByRole('article', { name: 'Эрин' })).toBeVisible();

		// a bad Telegram id is refused, with the hub's message
		const erin = alice.getByRole('article', { name: 'Эрин' });
		await erin.getByRole('button', { name: 'Изменить' }).click();
		await erin.getByLabel('Telegram id').fill('@erin');
		await erin.getByRole('button', { name: 'Сохранить' }).click();
		await expect(alice.getByRole('alert')).toContainText('Telegram id — это число');
		await erin.getByRole('button', { name: 'Отмена' }).click();
		await expect(alice.getByRole('alert')).toHaveCount(0);

		await shot(alice, 'admin-people');
		await alice.getByRole('link', { name: 'Группы' }).click();
		await expect(alice).toHaveURL(`${HUB}/admin/groups`);
		const club = alice.getByRole('article', { name: 'club' });
		await club.getByLabel('Боб').check();
		await expect(club.getByText('2 чел.')).toBeVisible();

		await alice.getByRole('link', { name: 'Сайты' }).click();
		for (const name of ['Telegram App', 'Passkey App', 'Both App', 'Closed App']) await expect(alice.getByRole('article', { name })).toBeVisible();

		await shot(alice, 'admin-apps');
		await alice.getByRole('link', { name: 'Журнал' }).click();
		await expect(alice.getByRole('cell', { name: 'group members' })).toBeVisible();
		await shot(alice, 'admin-audit');
		await expect(alice.getByRole('cell', { name: 'person add' })).toBeVisible();

		// a deep link loads the app too
		await alice.goto(`${HUB}/admin/apps`);
		await expect(alice.getByRole('heading', { name: 'Сайты' })).toBeVisible();
	});

	test('Carol enrolls with the link on her own device and is in', async ({ browser }) => {
		const context = await browser.newContext();
		const carol = await device(context);
		await carol.goto(carolLink);
		await expect(carol.getByText('Для Кэрол')).toBeVisible();
		await shot(carol, 'enroll');
		await carol.getByLabel('Как назвать это устройство').fill('Телефон Кэрол');
		await carol.getByRole('button', { name: 'Создать passkey' }).click();
		await expect(carol.getByText('Готово: passkey сохранён')).toBeVisible();

		await carol.goto(app.pk);
		await carol.locator('#login').click();
		await expectIn(carol, app.pk, 'Carol', 'passkey');

		// the link worked once
		await carol.goto(carolLink);
		await expect(carol.getByRole('heading', { name: 'Ссылка не работает' })).toBeVisible();
		await context.close();
	});

	test('Bob, now in the club, opens the app that accepts either', async ({ browser }) => {
		const context = await browser.newContext();
		const bob = await device(context);
		await bob.goto(app.both);
		await bob.locator('#login').click();
		await bob.getByRole('link', { name: 'Войти через Telegram' }).click();
		await bob.getByRole('link', { name: 'Войти как Bob Telegram' }).click();
		await expectIn(bob, app.both, 'Bob', 'telegram');
		// and the admin UI is not for him
		const res = await bob.goto(`${HUB}/admin`);
		expect(res?.status()).toBe(403);
		await context.close();
	});

	test('a Telegram account the hub does not know is refused everywhere', async ({ browser }) => {
		const context = await browser.newContext();
		const dave = await device(context);
		await dave.goto(app.tg);
		await dave.locator('#login').click();
		await dave.getByRole('link', { name: 'Войти как Dave Telegram' }).click();
		await expect(dave.getByRole('heading', { name: 'Нет доступа' })).toBeVisible();
		await expect.poll(async () => (await botMessages(dave)).join('\n')).toContain('такого человека нет');
		await context.close();
	});
});
