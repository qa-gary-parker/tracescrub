/**
 * Masked preview of a secret. Shows at most 4 leading characters (and never
 * more than a sixth of the value), followed by stars and the length.
 * The full value is never returned.
 */
export function mask(value: string): string {
  const chars = [...value.replace(/\s+/g, ' ')];
  const n = chars.length;
  const show = n >= 12 ? Math.min(4, Math.floor(n / 6)) : 0;
  return `${chars.slice(0, show).join('')}****** (${n} chars)`;
}
