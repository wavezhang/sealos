import { addOrUpdateWechatCode } from '@/services/backend/db/wechatCode';
import crypto from 'crypto';
import { NextApiRequest, NextApiResponse } from 'next';
const xml2js = require('xml2js');

type MessageType = 'event' | 'text' | 'image';
type EventType = 'SCAN' | 'unsubscribe' | 'subscribe';
type WechatMessage = {
  ToUserName: string[];
  FromUserName: string[];
  CreateTime: number[];
  MsgType: [MessageType];
  Event: [EventType];
  EventKey: string[];
  Content: string[];
};
type WeChatRequest = {
  signature: string;
  timestamp: string;
  nonce: string;
  echostr: string;
};

const MAX_BODY_BYTES = 64 * 1024;
const MAX_XML_NODES = 64;
const TIMESTAMP_WINDOW_SECONDS = 5 * 60;
const ECHOSTR_PATTERN = /^\d{1,20}$/;
const NONCE_PATTERN = /^[A-Za-z0-9]{1,64}$/;
const FORBIDDEN_XML_PATTERN = /<!DOCTYPE|<!ENTITY/i;

// The callback token is configured both in the WeChat official account console
// and in the deployment config. Fail closed when it is missing or empty.
function getCallbackToken(): string | null {
  const token =
    global.AppConfig?.desktop.auth.idp.wechat?.callbackToken ||
    process.env.WECHAT_CALLBACK_TOKEN;
  return typeof token === 'string' && token.length > 0 ? token : null;
}

function verifyWeChatSignature(query: Partial<WeChatRequest>): boolean {
  const { signature, timestamp, nonce } = query;
  if (
    typeof signature !== 'string' ||
    typeof timestamp !== 'string' ||
    typeof nonce !== 'string'
  ) {
    return false;
  }
  if (!/^\d{1,20}$/.test(timestamp) || !NONCE_PATTERN.test(nonce)) return false;

  const timestampSeconds = Number(timestamp);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (
    !Number.isFinite(timestampSeconds) ||
    Math.abs(nowSeconds - timestampSeconds) > TIMESTAMP_WINDOW_SECONDS
  ) {
    return false;
  }

  const token = getCallbackToken();
  if (!token) return false;

  const encryptedStr = crypto
    .createHash('sha1')
    .update([token, timestamp, nonce].sort().join(''))
    .digest('hex');
  const expected = Buffer.from(encryptedStr, 'utf8');
  const received = Buffer.from(signature.toLowerCase(), 'utf8');
  return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}

function setPlainTextHeaders(res: NextApiResponse, contentType = 'text/plain; charset=utf-8') {
  res.setHeader('Content-Type', contentType);
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

class WeChatEventHandler {
  private handlers: { [key in EventType]: (message: WechatMessage) => Promise<string> };
  constructor() {
    this.handlers = {
      subscribe: this.handleSubscribeEvent,
      unsubscribe: this.handleUnsubscribeEvent,
      SCAN: this.handleScanEvent
    };
  }
  async handleEvent(message: WechatMessage) {
    console.log('处理事件消息:', message);
    const eventType = message.Event[0];
    const handler = this.handlers[eventType];
    if (handler) {
      return handler(message);
    } else {
      console.log('无此事件处理方法:', eventType);
      return 'success';
    }
  }
  async handleSubscribeEvent(message: WechatMessage) {
    console.log('处理订阅事件:', message);
    if (!message?.EventKey[0]) {
      return 'fail';
    }
    const openid = message.FromUserName[0];
    const code = message.EventKey[0]?.replace('qrscene_', '');
    if (openid && code) {
      const result = await addOrUpdateWechatCode({
        openid,
        code
      });
      console.log(result);
    }
    return 'success';
  }
  async handleUnsubscribeEvent(message: WechatMessage) {
    console.log('处理取消订阅事件:', message);
    return 'success';
  }
  async handleScanEvent(message: WechatMessage) {
    console.log('处理扫描带参二维码事件:', message);
    if (!message?.EventKey[0]) {
      return 'fail';
    }
    const openid = message.FromUserName[0];
    const code = message.EventKey[0];
    if (openid && code) {
      const result = await addOrUpdateWechatCode({
        openid,
        code
      });
      console.log(result);
    }
    return 'success';
  }
}

export function textMsg(message: WechatMessage, content: string) {
  const str = `<xml>
      <ToUserName><![CDATA[${message.FromUserName}]]></ToUserName>
      <FromUserName><![CDATA[${message.ToUserName}]]></FromUserName>
      <CreateTime>${Math.floor(Date.now() / 1000)}</CreateTime>
      <MsgType><![CDATA[text]]></MsgType>
      <Content><![CDATA[${content}]]></Content>
    </xml>`;
  return str;
}

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '64kb'
    }
  }
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method === 'GET') {
      if (!verifyWeChatSignature(req.query as Partial<WeChatRequest>)) {
        return res.status(403).send('Forbidden');
      }
      const { echostr } = req.query as Partial<WeChatRequest>;
      if (typeof echostr !== 'string' || !ECHOSTR_PATTERN.test(echostr)) {
        return res.status(403).send('Forbidden');
      }
      setPlainTextHeaders(res);
      return res.status(200).send(echostr);
    }

    if (req.method !== 'POST') {
      return res.status(405).send('Method not allowed');
    }

    // The WeChat platform signs every delivery (including event pushes). Verify
    // before touching the XML body.
    if (!verifyWeChatSignature(req.query as Partial<WeChatRequest>)) {
      return res.status(403).send('Forbidden');
    }

    const body = req.body as unknown;
    if (typeof body !== 'string') {
      return res.status(400).send('Invalid body');
    }
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) {
      return res.status(413).send('Payload too large');
    }
    if (FORBIDDEN_XML_PATTERN.test(body)) {
      return res.status(400).send('Invalid XML');
    }
    const nodeCount = (body.match(/</g) || []).length;
    if (nodeCount > MAX_XML_NODES) {
      return res.status(400).send('Invalid XML');
    }

    const result: { xml: WechatMessage } = await xml2js.parseStringPromise(body, {
      explicitArray: true,
      strict: true
    });
    let message = result.xml;
    const msgType = message?.MsgType?.[0];

    if (msgType === 'event') {
      const eventHandler = new WeChatEventHandler();
      const response = await eventHandler.handleEvent(message);
      setPlainTextHeaders(res);
      return res.status(200).send(response);
    }
    if (msgType === 'text') {
      const response = textMsg(message, `欢迎来到公众号,收到消息=> ${message.Content?.[0] ?? ''}`);
      setPlainTextHeaders(res, 'text/xml; charset=utf-8');
      return res.status(200).send(response);
    }

    setPlainTextHeaders(res);
    return res.status(200).send('success');
  } catch (error) {
    console.log(error);
    setPlainTextHeaders(res);
    return res.status(200).send('success');
  }
}
