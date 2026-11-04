// The whole admin state, loaded once and after every change. It is small: a few people and apps.
import { api } from './api.js';
import type { State } from './types.js';

export const hub = $state<{ state: State | null; error: string; busy: boolean }>({
	state: null,
	error: '',
	busy: false
});

export async function reload() {
	try {
		hub.state = await api<State>('GET', '/state');
		hub.error = '';
	} catch (e) {
		hub.error = (e as Error).message;
	}
}

// change: run one API call, then reload; a refusal goes to hub.error, and false is returned
export async function change(fn: () => Promise<unknown>): Promise<boolean> {
	hub.busy = true;
	try {
		await fn();
		await reload();
		return true;
	} catch (e) {
		hub.error = (e as Error).message;
		return false;
	} finally {
		hub.busy = false;
	}
}
