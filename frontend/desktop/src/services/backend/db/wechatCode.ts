import { createHash, randomBytes } from 'crypto';
import { connectToDatabase } from './mongodb';

type TWechatVerifyCode = {
  openid: string;
  code: string;
  createTime: Date;
  expireTime: Date;
};

// The login ticket is delivered to the initiating browser only (HttpOnly) and
// is stored hashed, so a leaked database row cannot be replayed as a ticket.
type TWechatLoginTicket = {
  code: string;
  ticketHash: string;
  createdAt: Date;
  expireAt: Date;
};

export const WECHAT_LOGIN_TICKET_COOKIE = 'sealos_wechat_login_ticket';
export const WECHAT_LOGIN_TICKET_TTL_MS = 2 * 60 * 1000;

async function connectToUserCollection() {
  const client = await connectToDatabase();
  const collection = client.db().collection<TWechatVerifyCode>('wechat-verify-code');
  return collection;
}

async function connectToLoginTicketCollection() {
  const client = await connectToDatabase();
  const collection = client.db().collection<TWechatLoginTicket>('wechat-login-ticket');
  await collection.createIndex({ code: 1 }, { unique: true });
  await collection.createIndex({ expireAt: 1 }, { expireAfterSeconds: 0 });
  return collection;
}

const hashTicket = (ticket: string) => createHash('sha256').update(ticket).digest('hex');

/**
 * Issues a random login ticket bound to the QR scene code. The raw ticket is
 * returned to the caller exactly once (for the HttpOnly cookie).
 */
export async function createWechatLoginTicket(code: string) {
  const ticket = randomBytes(32).toString('base64url');
  const now = new Date();
  const tickets = await connectToLoginTicketCollection();
  await tickets.insertOne({
    code,
    ticketHash: hashTicket(ticket),
    createdAt: now,
    expireAt: new Date(now.getTime() + WECHAT_LOGIN_TICKET_TTL_MS)
  });
  return ticket;
}

export async function findWechatLoginTicket({ code, ticket }: { code: string; ticket: string }) {
  const tickets = await connectToLoginTicketCollection();
  return tickets.findOne({
    code,
    ticketHash: hashTicket(ticket),
    expireAt: { $gt: new Date() }
  });
}

/**
 * Atomically consumes the login ticket. Returns null when the ticket does not
 * match the code or was already used.
 */
export async function consumeWechatLoginTicket({ code, ticket }: { code: string; ticket: string }) {
  const tickets = await connectToLoginTicketCollection();
  const result = await tickets.findOneAndDelete({
    code,
    ticketHash: hashTicket(ticket),
    expireAt: { $gt: new Date() }
  });
  return result.value;
}

export async function addOrUpdateWechatCode({ openid, code }: { openid: string; code: string }) {
  const codes = await connectToUserCollection();
  const currentTime = new Date();
  const expireTime = new Date(currentTime.getTime() + 5 * 60 * 1000);
  const result = await codes.updateOne(
    {
      openid
    },
    {
      $set: {
        code,
        createTime: currentTime,
        expireTime: expireTime
      }
    },
    {
      upsert: true
    }
  );
  return result;
}

export async function verifyWechatCode({ code }: { code: string }) {
  const codes = await connectToUserCollection();
  const result = await codes.findOne({
    code,
    expireTime: { $gt: new Date() }
  });
  return result;
}

/**
 * Atomically consumes a scanned WeChat code so it can be exchanged only once.
 */
export async function consumeWechatCode({ code }: { code: string }) {
  const codes = await connectToUserCollection();
  const result = await codes.findOneAndDelete({
    code,
    expireTime: { $gt: new Date() }
  });
  return result.value;
}

export async function hasWeChatAppSecret() {
  const APP_ID = global.AppConfig?.desktop.auth?.idp.wechat?.clientID;
  const APP_SECRET = global.AppConfig?.desktop.auth?.idp.wechat?.clientSecret;
  if (!APP_ID || !APP_SECRET) {
    throw new Error('Missing WeChat public account key');
  }
  return {
    APP_ID,
    APP_SECRET
  };
}

export async function getWeChatAccessToken() {
  const { APP_ID, APP_SECRET } = await hasWeChatAppSecret();

  function isAccessTokenValid(expiresIn: number) {
    const currentTime = Date.now();
    return expiresIn > currentTime;
  }

  if (
    global.WechatAccessToken &&
    global.WechatExpiresIn &&
    isAccessTokenValid(global.WechatExpiresIn)
  ) {
    return global.WechatAccessToken;
  } else {
    const response = await fetch(
      `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${APP_ID}&secret=${APP_SECRET}`,
      { headers: { Accept: 'application/json' } }
    );
    const { access_token: newAccessToken, expires_in: newExpiresIn } = (await response.json()) as {
      access_token: string;
      expires_in: number;
    };
    global.WechatAccessToken = newAccessToken;
    global.WechatExpiresIn = Date.now() + newExpiresIn * 1000 - 10 * 60 * 1000; //ms
    return global.WechatAccessToken;
  }
}
