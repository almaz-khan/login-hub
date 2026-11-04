import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// The admin UI, served by the hub at /admin. The hub owns /admin/api; in dev, Vite proxies it
// (log in to a local hub first, so the browser has its session cookie for localhost).
const hub = process.env.HUB_URL ?? 'http://localhost:8080';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			// SPA: the hub serves 200.html for any /admin path without a built file, and makes
			// the page's CSP header itself from the inline scripts in it (internal/hub/adminui.go)
			adapter: adapter({ fallback: '200.html' }),
			paths: { base: '/admin' },
			output: { bundleStrategy: 'single' }
		})
	],
	server: { proxy: { '/admin/api': hub } }
});
