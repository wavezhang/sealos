import {
  WECHAT_LOGIN_TICKET_COOKIE,
  consumeWechatCode,
  consumeWechatLoginTicket,
  findWechatLoginTicket,
  getWeChatAccessToken,
  verifyWechatCode
} from '@/services/backend/db/wechatCode';
import { jsonRes } from '@/services/backend/response';
import { TWechatUser } from '@/types/user';
import { getBase64FromRemote } from '@/utils/tools';
import { NextApiRequest, NextApiResponse } from 'next';
import { getGlobalToken } from '@/services/backend/globalAuth';
import { ProviderType } from 'prisma/global/generated/client';
import { getRegionToken } from '@/services/backend/regionAuth';
import { webRegistrationFromRequest } from '@/services/backend/activity/registration';

const reject = (res: NextApiResponse, message: string) =>
  res.status(401).json({ code: 401, message, data: null });

const clearTicketCookie = (res: NextApiResponse) => {
  res.setHeader(
    'Set-Cookie',
    `${WECHAT_LOGIN_TICKET_COOKIE}=; Path=/api/auth/publicWechat; HttpOnly; SameSite=Lax; Max-Age=0`
  );
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const access_token = await getWeChatAccessToken();
    const { code } = req.query as { code: string };
    if (!code) {
      return jsonRes(res, {
        code: 400,
        data: 'Parameter error'
      });
    }

    // The QR scene must be redeemed by the browser that requested it. Without
    // the HttpOnly ticket cookie the code cannot be exchanged at all.
    const ticket = req.cookies[WECHAT_LOGIN_TICKET_COOKIE];
    if (!ticket) {
      return reject(res, 'Login session expired');
    }
    const ticketBinding = await findWechatLoginTicket({ code, ticket });
    if (!ticketBinding) {
      return reject(res, 'Login session expired');
    }

    const verifyInfo = await verifyWechatCode({ code });
    if (!verifyInfo?.openid) {
      return jsonRes(res, {
        code: 201,
        data: 'Verification code expired'
      });
    }

    const userUrl = `https://api.weixin.qq.com/cgi-bin/user/info?access_token=${access_token}&openid=${verifyInfo.openid}&lang=zh_CN`;
    const userInfo = (await (await fetch(userUrl)).json()) as TWechatUser;
    const avatar_url = (await getBase64FromRemote(userInfo?.headimgurl)) as string;

    if (!userInfo?.openid) {
      return jsonRes(res, {
        code: 500,
        message: 'Failed to obtain WeChat information'
      });
    }

    // One-time consumption: only one concurrent poll can win both atomic
    // deletes, and any later replay of the same code/ticket fails.
    const consumedTicket = await consumeWechatLoginTicket({ code, ticket });
    if (!consumedTicket) {
      return reject(res, 'Login session expired');
    }
    const consumedCode = await consumeWechatCode({ code });
    if (!consumedCode?.openid) {
      return reject(res, 'Login session expired');
    }
    clearTicketCookie(res);

    const openid = consumedCode.openid;
    const _data = await getGlobalToken({
      provider: ProviderType.WECHAT,
      providerId: openid,
      avatar_url,
      name: userInfo?.nickname,
      // Official-account signups likewise read invite context from cookies;
      // server-side validation failures never block registration
      registration: webRegistrationFromRequest(req)
    });

    if (_data?.isRestricted) {
      return jsonRes(res, {
        code: 401,
        message: 'Account banned'
      });
    }

    if (!_data)
      return jsonRes(res, {
        code: 401,
        message: 'Unauthorized'
      });

    const data = await getRegionToken({
      userUid: _data.user!.userUid,
      userId: _data.user!.name
    });
    return jsonRes(res, {
      code: 200,
      message: 'Successfully',
      data
    });
  } catch (err) {
    console.log(err);
    jsonRes(res, {
      code: 500,
      message: 'service getWechatResult error'
    });
  }
}
