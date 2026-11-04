<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import { hub, reload } from '#lib/hub.svelte.js';

	let { children } = $props();

	const tabs = [
		{ href: resolve('/'), label: 'Люди' },
		{ href: resolve('/groups'), label: 'Группы' },
		{ href: resolve('/apps'), label: 'Сайты' },
		{ href: resolve('/audit'), label: 'Журнал' }
	];

	onMount(reload);
</script>

<header>
	<div class="spread">
		<div class="row">
			<strong>Админка</strong>
			{#if hub.state}<span class="muted small">вошёл как {hub.state.me}</span>{/if}
		</div>
		<div class="row small">
			<a href="/admin/backup" download>Скачать копию базы</a>
			<a href="/">Хаб</a>
		</div>
	</div>
	<nav class="row" aria-label="Разделы">
		{#each tabs as tab (tab.href)}
			<a href={tab.href} aria-current={page.url.pathname === tab.href ? 'page' : undefined}>{tab.label}</a>
		{/each}
	</nav>
</header>

<main>
	{#if hub.error}
		<p class="banner" role="alert">{hub.error}</p>
	{/if}
	{#if hub.state}
		{@render children()}
	{:else if !hub.error}
		<p class="muted">Загружаю…</p>
	{/if}
</main>

<style>
	header {
		position: sticky;
		top: 0;
		z-index: 1;
		display: grid;
		gap: 10px;
		padding: 14px 16px 0;
		background: var(--bg);
		border-bottom: 1px solid var(--line);
	}
	nav a {
		padding: 8px 4px 10px;
		margin-right: 12px;
		color: var(--muted);
		text-decoration: none;
		border-bottom: 2px solid transparent;
	}
	nav a[aria-current='page'] {
		color: var(--text);
		border-bottom-color: var(--accent);
	}
	main {
		max-width: 980px;
		margin: 0 auto;
		padding: 18px 16px 48px;
		display: grid;
		gap: 16px;
	}
</style>
