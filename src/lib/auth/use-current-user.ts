import { authClient, authEnabled } from './client.ts';

export interface CurrentUser {
  id: string;
  displayName: string | null;
  primaryEmail: string | null;
  profileImageUrl: string | null;
}

function mapUser(user: { id: string; name?: string | null; email?: string | null; image?: string | null }): CurrentUser {
  return {
    id: user.id,
    displayName: user.name ?? null,
    primaryEmail: user.email ?? null,
    profileImageUrl: user.image ?? null,
  };
}

/** React hook for the Better Auth session used by the reusable auth gates. */
export function useCurrentUserState(): { user: CurrentUser | null; isPending: boolean } {
  const session = authClient.useSession();
  if (!authEnabled) return { user: null, isPending: false };
  return {
    user: session.data?.user ? mapUser(session.data.user) : null,
    isPending: session.isPending,
  };
}

export function useCurrentUser(): CurrentUser | null {
  return useCurrentUserState().user;
}
