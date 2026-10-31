import { Config } from '@/config';
import type { AxiosInstance } from 'axios';
import { createHmac, randomBytes } from 'crypto';

export const invoiceSignedRequest = (body: unknown) => {
  const secret = Config().costCenter.invoice.serviceToken;
  if (!secret) {
    throw new Error('invoice service token is not configured');
  }
  // The signature covers the exact serialized body, so keep this string and
  // send it as-is instead of letting axios re-serialize an object.
  const raw = JSON.stringify(body);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString('hex');
  const signature = createHmac('sha256', secret)
    .update(`${timestamp}\n${nonce}\n`)
    .update(raw)
    .digest('hex');
  return {
    raw,
    headers: {
      'Content-Type': 'application/json',
      'X-Invoice-Timestamp': timestamp,
      'X-Invoice-Nonce': nonce,
      'X-Invoice-Signature': signature
    }
  };
};

export const postSignedInvoice = (
  client: AxiosInstance,
  path: string,
  body: unknown
) => {
  const { raw, headers } = invoiceSignedRequest(body);
  return client.post(path, raw, { headers });
};
