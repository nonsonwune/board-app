export function formatRelativeTime(input: number | Date, now: number = Date.now()): string {
  const value = typeof input === 'number' ? input : input.valueOf();
  const diffMs = value - now;
  const diffSeconds = Math.round(diffMs / 1000);

  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

  const divisions: Array<{ amount: number; unit: Intl.RelativeTimeFormatUnit }> = [
    { amount: 60, unit: 'second' },
    { amount: 60, unit: 'minute' },
    { amount: 24, unit: 'hour' },
    { amount: 7, unit: 'day' },
    { amount: 4.34524, unit: 'week' },
    { amount: 12, unit: 'month' },
    { amount: Infinity, unit: 'year' }
  ];

  let duration = diffSeconds;
  for (const division of divisions) {
    if (Math.abs(duration) < division.amount) {
      return formatter.format(Math.round(duration), division.unit);
    }
    duration /= division.amount;
  }

  return formatter.format(Math.round(duration), 'year');
}

export function formatBoardDistance(meters?: number | null): string {
  if (!meters || meters <= 0) return '~1.5 km';
  if (meters < 1000) {
    return `${Math.round(meters)} m`;
  }
  const km = meters / 1000;
  const rounded = km >= 10 ? Math.round(km) : Math.round(km * 10) / 10;
  return `~${rounded} km`;
}
