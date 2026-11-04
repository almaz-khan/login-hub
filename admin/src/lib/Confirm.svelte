<script lang="ts">
	// A destructive button that asks first, in place (no browser dialog).
	let { label, question, onconfirm }: { label: string; question: string; onconfirm: () => unknown } = $props();
	let asking = $state(false);
</script>

{#if asking}
	<span class="row small" role="group" aria-label={question}>
		<span>{question}</span>
		<button
			class="danger"
			onclick={async () => {
				await onconfirm();
				asking = false;
			}}>Yes, go ahead</button
		>
		<button class="ghost" onclick={() => (asking = false)}>No</button>
	</span>
{:else}
	<button class="danger" onclick={() => (asking = true)}>{label}</button>
{/if}
