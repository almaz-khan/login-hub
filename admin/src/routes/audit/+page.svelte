<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '#lib/api.js';
	import { hub } from '#lib/hub.svelte.js';
	import { when } from '#lib/format.js';
	import type { AuditEntry } from '#lib/types.js';

	let entries = $state<AuditEntry[]>([]);
	let more = $state(true);
	let loading = $state(false);

	async function load() {
		loading = true;
		try {
			const before = entries.length ? entries[entries.length - 1].id : 0;
			const page = await api<AuditEntry[]>('GET', `/audit${before ? `?before=${before}` : ''}`);
			entries = [...entries, ...page];
			more = page.length === 100;
		} catch (e) {
			hub.error = (e as Error).message;
		} finally {
			loading = false;
		}
	}

	onMount(load);
</script>

<section class="panel">
	<h1>Журнал</h1>
	<p class="muted small">Каждое изменение: кто, когда и что. Входы и отказы — в логе хаба на Railway.</p>
	<div class="scroll">
		<table>
			<thead><tr><th>Когда</th><th>Кто</th><th>Что</th><th>Подробно</th></tr></thead>
			<tbody>
				{#each entries as a (a.id)}
					<tr><td>{when(a.at)}</td><td>{a.actor}</td><td>{a.action}</td><td class="mono">{a.detail}</td></tr>
				{/each}
			</tbody>
		</table>
	</div>
	{#if more}
		<div><button class="ghost" onclick={load} disabled={loading}>Ещё</button></div>
	{/if}
</section>
