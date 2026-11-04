<script lang="ts">
	let { text, label = 'Скопировать' }: { text: string; label?: string } = $props();
	let done = $state(false);

	async function copy() {
		try {
			await navigator.clipboard.writeText(text);
			done = true;
			setTimeout(() => (done = false), 2000);
		} catch {
			done = false;
		}
	}
</script>

<div><button class="ghost" type="button" onclick={copy}>{done ? 'Скопировано' : label}</button></div>
