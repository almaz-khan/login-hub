// The hub's admin API. Same origin, JSON; the hub refuses anything else. A refusal comes back as
// {error} and is thrown as an Error with that message, ready to show.

export async function api<T = { ok: true }>(method: string, path: string, body?: unknown): Promise<T> {
	const res = await fetch(`/admin/api${path}`, {
		method,
		headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
		body: body === undefined ? undefined : JSON.stringify(body),
		credentials: 'same-origin'
	});
	const data = await res.json().catch(() => ({}));
	if (!res.ok) throw new Error(data.error ?? `The hub answered ${res.status}`);
	return data as T;
}

export const enc = encodeURIComponent;
