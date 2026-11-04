// What GET /admin/api/state returns (internal/store/admin.go)

export type Passkey = { id: string; label: string; created: number; last_used: number };

export type Person = {
	key: string;
	name: string;
	telegram_id: string;
	last_seen: number;
	groups: string[];
	apps: string[];
	passkeys: Passkey[];
};

export type Group = { name: string; members: string[] };

export type Method = 'telegram' | 'passkey';

export type App = {
	id: string;
	name: string;
	redirect_uris: string[];
	post_logout_redirect_uris: string[];
	login: Method[];
	allow: string[]; // "group:<name>" or a person key
	created: number;
};

export type State = { me: string; notify: string; people: Person[]; groups: Group[]; apps: App[] };

export type AuditEntry = { id: number; at: number; actor: string; action: string; detail: string };

// An app being edited: URLs as text, one per line
export type AppDraft = {
	name: string;
	redirects: string;
	logouts: string;
	login: Method[];
	allow: string[];
};
