import { createHash } from 'node:crypto';

const MASK_PLACEHOLDER = '***';

export const hasValue = (value: unknown): boolean =>
  value !== undefined && value !== null && value !== '';

export const maskString = (
  value?: string | null,
  keepStart = 2,
  keepEnd = 2,
): string | undefined => {
  if (!value) {
    return undefined;
  }

  const normalized = value.trim();
  if (!normalized) {
    return undefined;
  }

  if (normalized.length <= keepStart + keepEnd) {
    return `${normalized[0] ?? ''}${MASK_PLACEHOLDER}`;
  }

  return `${normalized.slice(0, keepStart)}…${normalized.slice(-keepEnd)}`;
};

export const maskEmail = (email?: string | null): string | undefined => {
  if (!email) {
    return undefined;
  }

  const [localPart, domainPart] = email.split('@');
  if (!domainPart) {
    return maskString(email, 2, 2);
  }

  const maskedLocal = maskString(localPart, 1, 1) ?? MASK_PLACEHOLDER;
  const domainSections = domainPart.split('.');
  const domainHead = domainSections[0] ?? '';
  const maskedDomainHead = domainHead
    ? `${domainHead.slice(0, 1)}${MASK_PLACEHOLDER}`
    : MASK_PLACEHOLDER;
  const domainTail =
    domainSections.length > 1 ? `.${domainSections.slice(1).join('.')}` : '';

  return `${maskedLocal}@${maskedDomainHead}${domainTail}`;
};

export const maskIdentifier = (identifier?: string | null): string | undefined => {
  if (!identifier) {
    return undefined;
  }
  return identifier.includes('@')
    ? maskEmail(identifier)
    : maskString(identifier, 1, 1);
};

export const maskToken = (token?: string | null, label = 'token'): string | undefined => {
  if (!token) {
    return undefined;
  }

  const digest = createHash('sha256').update(token).digest('hex').slice(0, 8);
  return `${label}[len=${token.length},sha=${digest}]`;
};

export const maskId = (value?: string | null): string | undefined =>
  maskString(value, 4, 4);

const sanitizeContext = (context: Record<string, unknown>): Record<string, unknown> => {
  return Object.fromEntries(
    Object.entries(context).filter(([, value]) => value !== undefined),
  );
};

export const buildLogContext = (context: Record<string, unknown>): string => {
  const sanitized = sanitizeContext(context);
  return Object.keys(sanitized).length ? JSON.stringify(sanitized) : '';
};

export const formatLogContext = (context: Record<string, unknown>): string => {
  const payload = buildLogContext(context);
  return payload ? ` ${payload}` : '';
};
