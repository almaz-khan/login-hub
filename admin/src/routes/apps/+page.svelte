<script lang="ts">
	import { api, enc } from '#lib/api.js';
	import { change, hub } from '#lib/hub.svelte.js';
	import { date, methodName } from '#lib/format.js';
	import type { App, AppDraft } from '#lib/types.js';
	import AppForm from '#lib/AppForm.svelte';
	import Confirm from '#lib/Confirm.svelte';
	import Copy from '#lib/Copy.svelte';

	const s = $derived(hub.state!);
	const issuer = location.origin;

	const blank = (): AppDraft => ({ name: '', redirects: '', logouts: '', login: ['telegram'], allow: [] });
	let newID = $state('');
	let newDraft = $state<AppDraft>(blank());
	let editing = $state<string | null>(null);
	let draft = $state<AppDraft>(blank());
	// a client secret, shown once: right after it was made
	let secret = $state<{ app: string; value: string } | null>(null);

	const lines = (s: string) =>
		s
			.split('\n')
			.map((l) => l.trim())
			.filter(Boolean);

	const body = (d: AppDraft) => ({
		name: d.name,
		redirect_uris: lines(d.redirects),
		post_logout_redirect_uris: lines(d.logouts),
		login: d.login,
		allow: d.allow
	});

	function who(a: App) {
		return a.allow
			.map((x) => (x.startsWith('group:') ? `group ${x.slice(6)}` : (s.people.find((p) => p.key === x)?.name ?? x)))
			.join(', ');
	}

	function edit(a: App) {
		editing = a.id;
		draft = {
			name: a.name,
			redirects: a.redirect_uris.join('\n'),
			logouts: a.post_logout_redirect_uris.join('\n'),
			login: [...a.login],
			allow: [...a.allow]
		};
	}

	async function save(id: string) {
		if (await change(() => api('PUT', `/apps/${enc(id)}`, body(draft)))) editing = null;
	}

	async function create() {
		const id = newID.trim();
		await change(async () => {
			const out = await api<{ secret: string }>('POST', '/apps', { id, ...body(newDraft) });
			secret = { app: id, value: out.secret };
			newID = '';
			newDraft = blank();
		});
	}

	async function rotate(id: string) {
		await change(async () => {
			const out = await api<{ secret: string }>('POST', `/apps/${enc(id)}/secret`);
			secret = { app: id, value: out.secret };
		});
	}
</script>

{#if secret}
	<section class="success" aria-live="polite">
		<strong>Secret for {secret.app}: shown only now</strong>
		<span>Put it in the app's variables, next to the others:</span>
		<span class="mono">OIDC_ISSUER={issuer}<br />OIDC_CLIENT_ID={secret.app}<br />OIDC_CLIENT_SECRET={secret.value}</span>
		<div class="row">
			<Copy text={secret.value} label="Copy the secret" />
			<button class="ghost" onclick={() => (secret = null)}>Saved it, hide</button>
		</div>
	</section>
{/if}

<section class="panel">
	<h1>Apps</h1>
	<div class="list">
		{#each s.apps as a (a.id)}
			<article class="stack" aria-label={a.name}>
				{#if editing === a.id}
					<AppForm bind:draft people={s.people} groups={s.groups} busy={hub.busy} submit="Save" onsubmit={() => save(a.id)}>
						<div class="spread">
							<h2>{a.name} <span class="muted mono small">{a.id}</span></h2>
							<button type="button" class="ghost" onclick={() => (editing = null)}>Cancel</button>
						</div>
					</AppForm>
				{:else}
					<div class="spread">
						<div>
							<h2>{a.name}</h2>
							<p class="muted small"><span class="mono">{a.id}</span> · since {date(a.created)}</p>
						</div>
						<div class="row">
							<button class="ghost" onclick={() => edit(a)}>Edit</button>
							<Confirm label="New secret" question="The old secret stops working at once. Make a new one?" onconfirm={() => rotate(a.id)} />
							<Confirm label="Delete" question={`Delete ${a.name}? Signing in to it stops working.`} onconfirm={() => change(() => api('DELETE', `/apps/${enc(a.id)}`))} />
						</div>
					</div>
					<div class="row small">
						<span class="muted">Sign-in:</span>
						{#each a.login as m (m)}<span class="chip on">{methodName[m]}</span>{/each}
						<span class="muted">Who:</span>
						<span>{who(a) || 'nobody'}</span>
					</div>
					<div class="small mono muted">
						{#each a.redirect_uris as u (u)}<div>↩ {u}</div>{/each}
						{#each a.post_logout_redirect_uris as u (u)}<div>⇥ {u}</div>{/each}
					</div>
				{/if}
			</article>
		{/each}
	</div>
</section>

<section class="panel">
	<h2>New app</h2>
	<AppForm bind:draft={newDraft} people={s.people} groups={s.groups} busy={hub.busy} submit="Add and make a secret" onsubmit={create}>
		<label>
			Client id
			<input bind:value={newID} required pattern="[a-z0-9][a-z0-9\-]{'{0,62}'}" placeholder="for example, running-club" />
			<span class="muted">Lowercase Latin letters, digits and -. It can't change later.</span>
		</label>
	</AppForm>
</section>
