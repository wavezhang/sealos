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

    const { workspaces } = req.body as {
      workspaces: string[];
    };

    if (
      !Array.isArray(workspaces) ||
      workspaces.some((workspace) => typeof workspace !== 'string')
    ) {
      return jsonRes(res, { code: 400, message: 'workspaces is required' });
    }

    // Only forward requests for workspaces the caller actually belongs to.
    const workspaceIds = Array.from(new Set(workspaces));
    if (!payload.userCrUid) {
      return jsonRes(res, { code: 403, message: 'You are not a member of this workspace' });
    }
    if (workspaceIds.length > 0) {
      const memberships = await prisma.userWorkspace.findMany({
        where: {
          userCrUid: payload.userCrUid,
          status: JoinStatus.IN_WORKSPACE,
          workspace: { id: { in: workspaceIds } }
        },
        select: { workspace: { select: { id: true } } }
      });
      const joinedWorkspaceIds = new Set(memberships.map((item) => item.workspace.id));
      if (workspaceIds.some((id) => !joinedWorkspaceIds.has(id))) {
        return jsonRes(res, { code: 403, message: 'You are not a member of this workspace' });
      }
    }

    const billingUrl = global.AppConfig.desktop.auth.billingUrl;
    if (!billingUrl) {
      return jsonRes(res, { code: 500, message: 'Billing service not configured' });
    }

    const billingToken = generateBillingToken({
      userUid: payload.userUid,
      userId: payload.userId
    });

    const response = await fetch(`${billingUrl}/account/v1alpha1/workspace-subscription/plans`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${billingToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        namespaces: workspaces
      })
    });
    const data = await response.json();
    return jsonRes(res, {
      code: 200,
      data: data
    });
  } catch (error: any) {
    console.error('Plan workspace list API error:', error);
    return jsonRes(res, {
      code: 500,
      message: 'Internal server error'
    });
  }
}
