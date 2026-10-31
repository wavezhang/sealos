import { NextApiRequest, NextApiResponse } from 'next';
import { jsonRes } from '@/services/backend/response';
import { enablePassword } from '@/services/enable';
import { getGlobalToken } from '@/services/backend/globalAuth';
import { AuthError } from '@/services/backend/errors';
import { webRegistrationFromRequest } from '@/services/backend/activity/registration';
import {
  checkPasswordLoginAllowed,
  getPasswordLoginRateLimitKey,
  recordPasswordLoginFailure,
  resetPasswordLoginFailures
} from '@/services/backend/passwordLoginRateLimit';
import { ProviderType } from 'prisma/global/generated/client';

const INVALID_CREDENTIALS_MESSAGE = 'Invalid username or password.';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  let rateLimitKey: string | null = null;
  try {
    if (!enablePassword()) {
      throw new Error('PASSWORD_SALT is not defined');
    }
    const { user: name, password, semData, adClickData } = req.body;
    if (typeof name !== 'string' || !name.trim() || typeof password !== 'string') {
      return jsonRes(res, {
        message: INVALID_CREDENTIALS_MESSAGE,
        code: 400
      });
    }

    rateLimitKey = getPasswordLoginRateLimitKey(req, name);
    const rateLimit = checkPasswordLoginAllowed(rateLimitKey);
    if (!rateLimit.allowed) {
      res.setHeader('Retry-After', String(rateLimit.retryAfter));
      return jsonRes(res, {
        message: 'Too many login attempts. Please try again later.',
        code: 429
      });
    }

    const data = await getGlobalToken({
      provider: ProviderType.PASSWORD,
      providerId: name,
      avatar_url: '',
      password,
      name,
      semData,
      adClickData,
      // Web password signups read invite context from cookies; server-side
      // validation failures never block registration
      registration: webRegistrationFromRequest(req)
    });

    if (data?.isRestricted) {
      return jsonRes(res, {
        code: 401,
        message: 'Account banned'
      });
    }

    if (!data)
      return jsonRes(res, {
        code: 401,
        message: 'Unauthorized'
      });
    resetPasswordLoginFailures(rateLimitKey);
    return jsonRes(res, {
      data: {
        token: data.token,
        needInit: data.needInit
      },
      code: 200,
      message: 'Successfully'
    });
  } catch (err) {
    console.log(err);

    // Never reveal whether the account exists. Both failure modes look and
    // behave identically and count toward the same throttle.
    if (
      err instanceof AuthError &&
      (err.errorCode === 'USER_NOT_FOUND' || err.errorCode === 'INCORRECT_PASSWORD')
    ) {
      if (rateLimitKey) recordPasswordLoginFailure(rateLimitKey);
      return jsonRes(res, {
        message: INVALID_CREDENTIALS_MESSAGE,
        code: 401
      });
    }

    let message = 'Failed to authorize with password';

    if (err instanceof AuthError) {
      message = err.message;
    } else if (err instanceof Error) {
      message = err.message;
    }

    return jsonRes(res, {
      message,
      code: 500
    });
  }
}
