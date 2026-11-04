const day = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
const moment = new Intl.DateTimeFormat('en-GB', {
	day: 'numeric',
	month: 'short',
	hour: '2-digit',
	minute: '2-digit'
});

export const date = (unix: number) => (unix ? day.format(new Date(unix * 1000)) : '—');
export const when = (unix: number) => (unix ? moment.format(new Date(unix * 1000)) : '—');

export const methodName = { telegram: 'Telegram', passkey: 'passkey' } as const;
