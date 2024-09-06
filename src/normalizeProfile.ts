import { AppBskyActorDefs } from '@atproto/api';

import { ATprotocolProfile } from './types';

export function normalizeProfile(profile: AppBskyActorDefs.ProfileViewDetailed): ATprotocolProfile {
  return {
    did: profile.did,
    handle: profile.handle,
    displayName: profile.displayName,
    avatar: profile.avatar || '',
  };
}
