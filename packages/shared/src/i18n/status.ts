export type AliasStatusKey =
  | 'requireIdentity'
  | 'requireSession'
  | 'boardRequired'
  | 'aliasRequired'
  | 'saving'
  | 'saved'
  | 'fetching'
  | 'fetched'
  | 'cleared'
  | 'conflict'
  | 'error';

export type SessionStatusKey = 'refreshing' | 'restored' | 'expired' | 'error';

export type AccessLinkStatusKey = 'linking' | 'linked' | 'unavailable' | 'forbidden' | 'error';

export interface AliasStatusMessages {
  requireIdentity: string;
  requireSession: string;
  boardRequired: string;
  aliasRequired: string;
  saving: string;
  saved: (options: { boardId: string; alias: string }) => string;
  fetching: string;
  fetched: (options: { boardId: string; alias?: string | null }) => string;
  cleared: (options: { boardId: string }) => string;
  conflict: string;
  error: string;
}

export interface SessionStatusMessages {
  refreshing: string;
  restored: (options: { expiresAt: Date }) => string;
  expired: string;
  error: string;
}

export interface AccessLinkStatusMessages {
  linking: string;
  linked: (options: { pseudonym: string }) => string;
  unavailable: string;
  forbidden: string;
  error: string;
}

export interface StatusMessages {
  alias: AliasStatusMessages;
  session: SessionStatusMessages;
  access: AccessLinkStatusMessages;
}

export const statusMessages: StatusMessages = {
  alias: {
    requireIdentity: 'Register your campus identity before setting an alias.',
    requireSession: 'Session expired. Refresh to keep your alias live.',
    boardRequired: 'Enter the board slug to choose the right alias.',
    aliasRequired: 'Alias is required. Choose something classmates will recognize.',
    saving: 'Saving your campus alias…',
    saved: ({ boardId, alias }) => `Alias locked for ${boardId}: ${alias}.`,
    fetching: 'Fetching your saved alias…',
    fetched: ({ boardId, alias }) =>
      alias ? `Alias on ${boardId} is set to ${alias}.` : `No alias saved on ${boardId} yet.`,
    cleared: ({ boardId }) => `Alias cleared on ${boardId}.`,
    conflict: 'That alias is already in use. Try a different variation.',
    error: 'We ran into an issue saving your alias. Please try again.'
  },
  session: {
    refreshing: 'Refreshing your campus session…',
    restored: ({ expiresAt }) => `Session restored. Next refresh ${expiresAt.toLocaleString()}.`,
    expired: 'Session expired. Re-register your identity to stay verified.',
    error: 'We could not refresh your session. Try again in a moment.'
  },
  access: {
    linking: 'Checking for an Access identity…',
    linked: ({ pseudonym }) => `Access identity linked to ${pseudonym}.`,
    unavailable: 'No Access identity detected. Make sure you are signed in with your campus SSO.',
    forbidden: 'Access token is invalid or expired. Reauthenticate with campus SSO.',
    error: 'We could not link your Access identity right now.'
  }
};

export default statusMessages;
