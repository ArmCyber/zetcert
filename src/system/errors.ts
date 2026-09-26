/** An error whose message is meant for the user: printed without a stack trace. */
export class UserError extends Error {
  constructor(
    message: string,
    readonly exitCode = 1,
  ) {
    super(message);
    this.name = 'UserError';
  }
}

export const EXIT_OK = 0;
export const EXIT_ERROR = 1;
/** Partly done: some certificates failed or names were skipped. */
export const EXIT_PARTIAL = 2;
