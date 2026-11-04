<script lang="ts">
	// An app's settings: name, exact URLs, login methods, who may open it.
	import type { AppDraft, Group, Method, Person } from './types.js';
	import { methodName } from './format.js';

	let {
		draft = $bindable(),
		people,
		groups,
		busy,
		submit,
		onsubmit,
		children
	}: {
		draft: AppDraft;
		people: Person[];
		groups: Group[];
		busy: boolean;
		submit: string;
		onsubmit: () => void;
		children?: import('svelte').Snippet;
	} = $props();

	const methods: Method[] = ['telegram', 'passkey'];

	function toggle<T>(list: T[], v: T, on: boolean): T[] {
		return on ? [...list, v] : list.filter((x) => x !== v);
	}
</script>

<form
	class="stack"
	onsubmit={(e) => {
		e.preventDefault();
		onsubmit();
	}}
>
	{@render children?.()}
	<label>Название<input bind:value={draft.name} required /></label>
	<div class="grid2">
		<label>
			Адреса возврата после входа
			<textarea bind:value={draft.redirects} required placeholder="https://app.almaz.dev/auth/callback"></textarea>
			<span class="muted">По одному в строке, точно как их шлёт сайт. Только https.</span>
		</label>
		<label>
			Адреса после выхода
			<textarea bind:value={draft.logouts} placeholder="https://app.almaz.dev/"></textarea>
			<span class="muted">Необязательно.</span>
		</label>
	</div>
	<fieldset class="stack">
		<legend>Как входить</legend>
		<div class="row">
			{#each methods as m (m)}
				<label class="check">
					<input type="checkbox" checked={draft.login.includes(m)} onchange={(e) => (draft.login = toggle(draft.login, m, e.currentTarget.checked))} />
					{methodName[m]}
				</label>
			{/each}
		</div>
	</fieldset>
	<fieldset class="stack">
		<legend>Кто может открыть</legend>
		<div class="row">
			{#each groups as g (g.name)}
				<label class="check">
					<input type="checkbox" checked={draft.allow.includes(`group:${g.name}`)} onchange={(e) => (draft.allow = toggle(draft.allow, `group:${g.name}`, e.currentTarget.checked))} />
					группа <span class="mono">{g.name}</span>
				</label>
			{/each}
		</div>
		<div class="row">
			{#each people as p (p.key)}
				<label class="check">
					<input type="checkbox" checked={draft.allow.includes(p.key)} onchange={(e) => (draft.allow = toggle(draft.allow, p.key, e.currentTarget.checked))} />
					{p.name}
				</label>
			{/each}
		</div>
	</fieldset>
	<div class="row"><button disabled={busy}>{submit}</button></div>
</form>

<style>
	fieldset {
		border: 1px solid var(--line);
		border-radius: 12px;
		padding: 10px 12px 12px;
		margin: 0;
	}
	legend {
		font-size: 13px;
		color: var(--soft);
		padding: 0 4px;
	}
</style>
