<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { afterNavigate } from '$app/navigation';
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import { hub, reload } from '#lib/hub.svelte.js';

	let { children } = $props();

	const tabs = [
		{ href: resolve('/'), label: 'People' },
		{ href: resolve('/groups'), label: 'Groups' },
		{ href: resolve('/apps'), label: 'Apps' },
		{ href: resolve('/audit'), label: 'Audit log' }
	];

	onMount(reload);
	// an error belongs to the page it happened on
	afterNavigate(() => (hub.error = ''));
</script>

<header>
	<div class="spread">
		<div class="row">
			<strong>Admin</strong>
			{#if hub.state}<span class="muted small">signed in as {hub.state.me}</span>{/if}
		</div>
		<div class="row small">
			<a href="/admin/backup" download>Download a database backup</a>
			<a href="/">Hub</a>
		</div>
	</div>
	<nav class="row" aria-label="Sections">
		{#each tabs as tab (tab.href)}
			<a href={tab.href} aria-current={page.url.pathname === tab.href ? 'page' : undefined}>{tab.label}</a>
		{/each}
	</nav>
</header>

<main>
	{#if hub.error}
		<div class="banner spread" role="alert">
			<span>{hub.error}</span>
			<button class="link" onclick={() => (hub.error = '')}>Close</button>
		</div>
	{/if}
	{#if hub.state}
		{@render children()}
	{:else if !hub.error}
		<p class="muted">Loading…</p>
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
