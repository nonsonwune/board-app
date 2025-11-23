export const ONBOARDING_JOINED_KEY = 'boardapp:onboarding:joined';
export const ONBOARDING_SNOOZE_KEY = 'boardapp:onboarding:snooze';
export const ONBOARDING_JOINED_EVENT = 'boardapp:onboarding-joined';

export function markBoardJoined() {
  if (typeof window === 'undefined') return;
  const alreadyMarked = window.localStorage.getItem(ONBOARDING_JOINED_KEY) === 'true';
  if (!alreadyMarked) {
    window.localStorage.setItem(ONBOARDING_JOINED_KEY, 'true');
    window.dispatchEvent(new CustomEvent(ONBOARDING_JOINED_EVENT));
  }
}

export function readBoardJoinedFlag(): boolean {
  if (typeof window === 'undefined') return false;
  return window.localStorage.getItem(ONBOARDING_JOINED_KEY) === 'true';
}

export function readSnoozeFlag(): boolean {
  if (typeof window === 'undefined') return false;
  return window.sessionStorage.getItem(ONBOARDING_SNOOZE_KEY) === 'true';
}

export function setSnoozeFlag(value: boolean) {
  if (typeof window === 'undefined') return;
  if (value) {
    window.sessionStorage.setItem(ONBOARDING_SNOOZE_KEY, 'true');
  } else {
    window.sessionStorage.removeItem(ONBOARDING_SNOOZE_KEY);
  }
}
