export interface RadiusConfig {
  minimumMeters?: number;
  maximumMeters?: number;
  initialMeters?: number;
  expansionStepMeters?: number;
  contractionStepMeters?: number;
}

export interface RadiusState {
  currentMeters: number;
  lastExpandedAt: number | null;
  lastContractedAt: number | null;
}

export interface RadiusInputs {
  postsInWindow: number;
  freshThreshold: number;
  staleThreshold: number;
  now: number;
}

export function getAdaptiveRadius(
  state: RadiusState | null,
  inputs: RadiusInputs,
  config: RadiusConfig
): RadiusState {
  const minimum = Math.max(100, config.minimumMeters ?? 250);
  const maximum = Math.max(minimum, config.maximumMeters ?? 2000);
  const expansionStep = Math.max(50, config.expansionStepMeters ?? 150);
  const contractionStep = Math.max(50, config.contractionStepMeters ?? 150);
  const initial = clamp(config.initialMeters ?? 1500, minimum, maximum);

  const currentState: RadiusState = state
    ? { ...state }
    : {
        currentMeters: initial,
        lastExpandedAt: null,
        lastContractedAt: null
      };

  const { postsInWindow, freshThreshold, staleThreshold, now } = inputs;

  if (postsInWindow >= freshThreshold) {
    if (
      currentState.currentMeters > minimum &&
      (currentState.lastContractedAt === null || now - currentState.lastContractedAt > 15 * 60 * 1000)
    ) {
      currentState.currentMeters = Math.max(minimum, currentState.currentMeters - contractionStep);
      currentState.lastContractedAt = now;
    }
    return currentState;
  }

  if (postsInWindow <= staleThreshold) {
    if (
      currentState.currentMeters < maximum &&
      (currentState.lastExpandedAt === null || now - currentState.lastExpandedAt > 30 * 60 * 1000)
    ) {
      currentState.currentMeters = Math.min(maximum, currentState.currentMeters + expansionStep);
      currentState.lastExpandedAt = now;
    }
  }

  return currentState;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}
