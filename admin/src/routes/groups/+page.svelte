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
	<h1>Группы</h1>
	<p class="muted small">Сайту можно дать доступ целой группе: кто в ней, тот и входит.</p>
	<div class="list">
		{#each s.groups as g (g.name)}
			<article class="stack" aria-label={g.name}>
				<div class="spread">
					<div>
						<h2 class="mono">{g.name}</h2>
						<p class="muted small">
							{g.members.length} чел. · сайты: {usedBy(g.name).join(', ') || '—'}
						</p>
					</div>
					<Confirm label="Удалить" question={`Удалить группу ${g.name}? Её доступы к сайтам пропадут.`} onconfirm={() => change(() => api('DELETE', `/groups/${enc(g.name)}`))} />
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
			<p class="muted">Групп пока нет.</p>
		{/each}
	</div>
</section>

<section class="panel">
	<h2>Новая группа</h2>
	<form class="row" onsubmit={add}>
		<label>
			Имя
			<input bind:value={name} required pattern="[a-z0-9][a-z0-9\-]{'{0,62}'}" placeholder="например, club" />
		</label>
		<button disabled={hub.busy}>Добавить</button>
	</form>
</section>
