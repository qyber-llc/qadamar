export class PepError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export class PdpHttpError extends PepError {
  readonly status: number;
  readonly retryAfter: string | undefined;

  constructor(status: number, code: string, retryAfter?: string) {
    super(code, `PDP request failed with HTTP ${status} (${code})`);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

export class PdpResponseError extends PepError {
  constructor(message = 'PDP returned a malformed response') {
    super('invalid_response', message);
  }
}

export class PdpNetworkError extends PepError {}

export class AccessDeniedError extends PepError {
  constructor() {
    super('access_denied', 'The PDP denied access; the record was not released');
  }
}

export class ObligationError extends PepError {
  constructor(message = 'The record obligations could not be enforced safely') {
    super('obligation_failed', message);
  }
}
