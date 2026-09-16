/**
 * Structured request logging — never log Authorization, tokens, wrap secrets, or JWKs.
 */

export interface RequestLogFields {
  ts: string;
  level: 'info' | 'warn' | 'error';
  msg: string;
  method?: string;
  path?: string;
  status?: number;
  durationMs?: number;
  client?: string;
  errorCode?: string;
}

export function logRequest(fields: RequestLogFields): void {
  const line = JSON.stringify({ ...fields, service: 'tdcp-authority' });
  if (fields.level === 'error') console.error(line);
  else if (fields.level === 'warn') console.warn(line);
  else console.log(line);
}
