<script lang="ts">
	import { api, enc } from '#lib/api.js';
	import { change, hub } from '#lib/hub.svelte.js';
	import Confirm from '#lib/Confirm.svelte';

	const s = $derived(hub.state!);
	let name = $state('');

	function usedBy(group: string) {
		return s.apps.filter((a) => a.allow.includes(`group:${group}`)).map((a) => a.name);
	}

	function toggle(group: string, members: string[], key: string, on: boolean) {
		const next = on ? [...members, key] : members.filter((m) => m !== key);
		return change(() => api('PUT', `/groups/${enc(group)}/members`, { members: next }));
	}

	async function add(event: SubmitEvent) {
		event.preventDefault();
		if (await change(() => api('POST', '/groups', { name: name.trim() }))) name = '';
	}
</script>

<section class="panel">
	<h1>Groups</h1>
	<p class="muted small">An app can be opened to a whole group: whoever is in it gets in.</p>
	<div class="list">
		{#each s.groups as g (g.name)}
			<article class="stack" aria-label={g.name}>
				<div class="spread">
					<div>
						<h2 class="mono">{g.name}</h2>
						<p class="muted small">
							{g.members.length} {g.members.length === 1 ? 'person' : 'people'} · apps: {usedBy(g.name).join(', ') || '—'}
						</p>
					</div>
					<Confirm label="Delete" question={`Delete the group ${g.name}? Its access to apps goes with it.`} onconfirm={() => change(() => api('DELETE', `/groups/${enc(g.name)}`))} />
				</div>
				<div class="row">
					{#each s.people as p (p.key)}
						<label class="check">
							<input
								type="checkbox"
								checked={g.members.includes(p.key)}
								disabled={hub.busy}
								onchange={(e) => toggle(g.name, g.members, p.key, e.currentTarget.checked)}
							/>
							{p.name}
						</label>
					{/each}
				</div>
			</article>
		{:else}
			<p class="muted">No groups yet.</p>
		{/each}
	</div>
</section>

<section class="panel">
	<h2>New group</h2>
	<form class="row" onsubmit={add}>
		<label>
			Name
			<input bind:value={name} required pattern="[a-z0-9][a-z0-9\-]{'{0,62}'}" placeholder="for example, club" />
		</label>
		<button disabled={hub.busy}>Add</button>
	</form>
</section>
