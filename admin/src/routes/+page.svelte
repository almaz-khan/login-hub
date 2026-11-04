<script lang="ts">
	import { api, enc } from '#lib/api.js';
	import { change, hub } from '#lib/hub.svelte.js';
	import { date } from '#lib/format.js';
	import type { Person } from '#lib/types.js';
	import Confirm from '#lib/Confirm.svelte';
	import Copy from '#lib/Copy.svelte';

	const s = $derived(hub.state!);

	let adding = $state({ key: '', name: '', telegram_id: '' });
	let editing = $state<string | null>(null);
	let draft = $state({ name: '', telegram_id: '' });
	let links = $state<Record<string, { link: string; expires: number }>>({});

	function appName(id: string) {
		return s.apps.find((a) => a.id === id)?.name ?? id;
	}

	async function add(event: SubmitEvent) {
		event.preventDefault();
		const ok = await change(() => api('POST', '/people', { ...adding, key: adding.key.trim(), telegram_id: adding.telegram_id.trim() }));
		if (ok) adding = { key: '', name: '', telegram_id: '' };
	}

	function edit(p: Person) {
		editing = p.key;
		draft = { name: p.name, telegram_id: p.telegram_id };
	}

	async function save(event: SubmitEvent, key: string) {
		event.preventDefault();
		if (await change(() => api('PUT', `/people/${enc(key)}`, { name: draft.name, telegram_id: draft.telegram_id.trim() }))) {
			editing = null;
		}
	}

	async function makeLink(key: string) {
		await change(async () => {
			links[key] = await api<{ link: string; expires: number }>('POST', `/people/${enc(key)}/enroll`);
		});
	}
</script>

<section class="panel">
	<div class="spread">
		<h1>People</h1>
		<label class="row small">
			The bot reports refusals to
			<select
				value={s.notify}
				onchange={(e) => change(() => api('PUT', '/settings', { notify: e.currentTarget.value }))}
			>
				<option value="">nobody</option>
				{#each s.people.filter((p) => p.telegram_id) as p (p.key)}
					<option value={p.key}>{p.name}</option>
				{/each}
			</select>
		</label>
	</div>

	<div class="list">
		{#each s.people as p (p.key)}
			<article class="stack" aria-label={p.name}>
				{#if editing === p.key}
					<form class="grid2" onsubmit={(e) => save(e, p.key)}>
						<label>Name<input bind:value={draft.name} required /></label>
						<label>Telegram id<input bind:value={draft.telegram_id} inputmode="numeric" placeholder="none" /></label>
						<div class="row">
							<button disabled={hub.busy}>Save</button>
							<button type="button" class="ghost" onclick={() => ((editing = null), (hub.error = ''))}>Cancel</button>
						</div>
					</form>
				{:else}
					<div class="spread">
						<div>
							<h2>{p.name}</h2>
							<p class="muted small">
								<span class="mono">{p.key}</span> · Telegram {p.telegram_id || '—'} · last seen {date(p.last_seen)}
							</p>
						</div>
						<div class="row">
							<button class="ghost" onclick={() => edit(p)}>Edit</button>
							{#if p.key !== s.me}
								<Confirm label="Delete" question={`Delete ${p.name}? Their access and passkeys go too.`} onconfirm={() => change(() => api('DELETE', `/people/${enc(p.key)}`))} />
							{/if}
						</div>
					</div>
				{/if}

				<div class="row small">
					<span class="muted">Groups:</span>
					{#each p.groups as g (g)}<span class="chip">{g}</span>{:else}<span class="muted">—</span>{/each}
					<span class="muted">Apps:</span>
					{#each p.apps as a (a)}<span class="chip on">{appName(a)}</span>{:else}<span class="muted">—</span>{/each}
				</div>

				<div class="stack small">
					{#each p.passkeys as k (k.id)}
						<div class="spread">
							<span>🔑 {k.label} <span class="muted">· since {date(k.created)} · last used {date(k.last_used)}</span></span>
							<Confirm label="Delete passkey" question={`Delete the passkey “${k.label}”?`} onconfirm={() => change(() => api('DELETE', `/passkeys/${enc(k.id)}`))} />
						</div>
					{/each}
					{#if links[p.key]}
						<div class="success">
							<span>Link for {p.name}: works once, for 24 hours.</span>
							<span class="mono">{links[p.key].link}</span>
							<Copy text={links[p.key].link} />
						</div>
					{:else}
						<div><button class="link" onclick={() => makeLink(p.key)} disabled={hub.busy}>Passkey link</button></div>
					{/if}
				</div>
			</article>
		{/each}
	</div>
</section>

<section class="panel">
	<h2>New person</h2>
	<form class="grid2" onsubmit={add}>
		<label>
			Key
			<input bind:value={adding.key} required pattern="[A-Za-z0-9][A-Za-z0-9_\-]{'{0,63}'}" placeholder="For example, Anna" />
			<span class="muted">Apps see it as sub. It can't change later.</span>
		</label>
		<label>Name<input bind:value={adding.name} required /></label>
		<label>
			Telegram id
			<input bind:value={adding.telegram_id} inputmode="numeric" placeholder="optional" />
			<span class="muted">The number in the bot's “No access” message.</span>
		</label>
		<div class="row"><button disabled={hub.busy}>Add</button></div>
	</form>
</section>
