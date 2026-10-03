import { authClient, authEnabled } from './client.ts';

export type CurrentUser = {
  id: string;
  displayName: string | null;
  primaryEmail: string | null;
  profileImageUrl: string | null;
};

/** Normalize Better Auth's session hook for the app's small auth UI surface. */
export function useCurrentUserState(): { user: CurrentUser | null; isPending: boolean } {
  const session = authClient.useSession();
  if (!authEnabled) {
    return {
      user: { id: 'dev-user', displayName: 'Demo user', primaryEmail: null, profileImageUrl: null },
      isPending: false,
    };
  }
  const user = session.data?.user;
  return {
    user: user
      ? {
          id: user.id,
          displayName: user.name ?? null,
          primaryEmail: user.email ?? null,
          profileImageUrl: user.image ?? null,
        }
      : null,
    isPending: session.isPending,
  };
}

export function useCurrentUser(): CurrentUser | null {
  return useCurrentUserState().user;
}
