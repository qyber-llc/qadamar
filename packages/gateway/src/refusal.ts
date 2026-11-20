/** A request the gateway refuses: nothing from the upstream is released. */
export class Refusal extends Error {
  readonly status: number;
  readonly code: string;
  /** The upstream certainly never received the request (its connection was never made). */
  readonly undelivered: boolean;
  constructor(status: number, code: string, undelivered = false) {
    super(code);
    this.status = status;
    this.code = code;
    this.undelivered = undelivered;
  }
}
