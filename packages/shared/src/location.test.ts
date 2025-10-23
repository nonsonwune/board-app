
import { describe, expect, it } from 'vitest';
import { getAdaptiveRadius, type RadiusConfig, type RadiusState } from './location';

describe('getAdaptiveRadius', () => {
  const config: RadiusConfig = {
    minimumMeters: 250,
    maximumMeters: 2000,
    expansionStepMeters: 200,
    contractionStepMeters: 200,
    initialMeters: 1500
  };

  it('contracts radius when feed is fresh, respecting hysteresis', () => {
    const initialState: RadiusState = {
      currentMeters: 1500,
      lastExpandedAt: null,
      lastContractedAt: null
    };

    const first = getAdaptiveRadius(initialState, { postsInWindow: 8, freshThreshold: 5, staleThreshold: 2, now: 1_000 }, config);
    expect(first.currentMeters).toBe(1300);

    const second = getAdaptiveRadius(first, { postsInWindow: 8, freshThreshold: 5, staleThreshold: 2, now: 5_000 }, config);
    expect(second.currentMeters).toBe(1300);

    const third = getAdaptiveRadius(second, { postsInWindow: 6, freshThreshold: 5, staleThreshold: 2, now: 1_000_000 }, config);
    expect(third.currentMeters).toBe(1100);
  });

  it('expands radius when feed is stale, respecting maximum and hysteresis', () => {
    const state: RadiusState = {
      currentMeters: 500,
      lastExpandedAt: null,
      lastContractedAt: 0
    };

    const expanded = getAdaptiveRadius(state, { postsInWindow: 0, freshThreshold: 5, staleThreshold: 2, now: 1_000 }, config);
    expect(expanded.currentMeters).toBe(700);

    const suppressed = getAdaptiveRadius(expanded, { postsInWindow: 0, freshThreshold: 5, staleThreshold: 2, now: 10_000 }, config);
    expect(suppressed.currentMeters).toBe(700);

    const maxed = getAdaptiveRadius({ ...expanded, currentMeters: 1_900, lastExpandedAt: 0 }, { postsInWindow: 0, freshThreshold: 5, staleThreshold: 2, now: 2_000_000 }, config);
    expect(maxed.currentMeters).toBe(2000);
  });
});
