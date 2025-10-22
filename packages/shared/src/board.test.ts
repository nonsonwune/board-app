import { describe, expect, it } from 'vitest';
import { formatBoardName } from './utils';

describe('formatBoardName', () => {
  it('capitalizes and removes dashes', () => {
    expect(formatBoardName('demo-board')).toBe('Demo Board');
  });

  it('handles empty string', () => {
    expect(formatBoardName('')).toBe('');
  });
});
