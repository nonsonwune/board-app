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
    requireIdentity: 'Create your profile before setting a nickname.',
    requireSession: 'Session expired. Refresh to keep your nickname live.',
    boardRequired: 'Enter the board name to choose the right nickname.',
    aliasRequired: 'Nickname is required. Choose something classmates will recognize.',
    saving: 'Saving your nickname…',
    saved: ({ boardId, alias }) => `Nickname saved for ${boardId}: ${alias}.`,
    fetching: 'Fetching your saved nickname…',
    fetched: ({ boardId, alias }) =>
      alias ? `Nickname on ${boardId} is set to ${alias}.` : `No nickname saved on ${boardId} yet.`,
    cleared: ({ boardId }) => `Nickname cleared on ${boardId}.`,
    conflict: 'That nickname is already in use. Try a different variation.',
    error: 'We ran into an issue saving your nickname. Please try again.'
  },
  session: {
    refreshing: 'Refreshing your campus session…',
    restored: ({ expiresAt }) => `Session restored. Next refresh ${expiresAt.toLocaleString()}.`,
    expired: 'Session expired. Update your profile to stay verified.',
    error: 'We could not refresh your session. Try again in a moment.'
  },
  access: {
    linking: 'Checking for an Access profile…',
    linked: ({ pseudonym }) => `Access profile linked to ${pseudonym}.`,
    unavailable: 'No Access profile detected. Make sure you are signed in with your campus SSO.',
    forbidden: 'Access token is invalid or expired. Reauthenticate with campus SSO.',
    error: 'We could not link your Access profile right now.'
  }
};

export default statusMessages;
