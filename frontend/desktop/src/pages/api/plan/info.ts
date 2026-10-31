import { generateBillingToken, verifyAccessToken } from '@/services/backend/auth';
import { prisma } from '@/services/backend/db/init';
import { jsonRes } from '@/services/backend/response';
import { JoinStatus } from 'prisma/region/generated/client';
import type { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method !== 'POST') {
      return jsonRes(res, { code: 405, message: 'Method not allowed' });
    }

    const payload = await verifyAccessToken(req.headers);
    if (!payload) return jsonRes(res, { code: 401, message: 'failed to get info' });

    const regionDomain = global.AppConfig.cloud.domain;
    const { workspace } = req.body as {
      workspace: string;
    };

    if (!workspace || typeof workspace !== 'string') {
      return jsonRes(res, { code: 400, message: 'workspace is required' });
    }

    // Only forward requests for workspaces the caller actually belongs to.
    if (!payload.userCrUid) {
      return jsonRes(res, { code: 403, message: 'You are not a member of this workspace' });
    }
    const membership = await prisma.userWorkspace.findFirst({
      where: {
        userCrUid: payload.userCrUid,
        status: JoinStatus.IN_WORKSPACE,
        workspace: { id: workspace }
      },
      select: { uid: true }
    });
    if (!membership) {
      return jsonRes(res, { code: 403, message: 'You are not a member of this workspace' });
    }

    const billingUrl = global.AppConfig.desktop.auth.billingUrl;
    if (!billingUrl) {
      return jsonRes(res, { code: 500, message: 'Billing service not configured' });
    }

    const billingToken = generateBillingToken({
      userUid: payload.userUid,
      userId: payload.userId
    });

    const response = await fetch(`${billingUrl}/account/v1alpha1/workspace-subscription/info`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${billingToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        workspace,
        regionDomain
      })
    });
    const data = await response.json();
    return jsonRes(res, {
      code: 200,
      data: data
    });
  } catch (error: any) {
    console.error('Plan info API error:', error);
    return jsonRes(res, {
      code: 500,
      message: 'Internal server error'
    });
  }
}
