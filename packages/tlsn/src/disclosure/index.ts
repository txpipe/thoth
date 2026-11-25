// The zkFetch disclosure mechanism as tlsn@1 runs it: what a prover reveals, and what
// the attestor reads from the revealed bytes. For custom provers and parity checks.

import { type ByteRange, type RevealedBytes, redactedResponseText } from '../http.js';
import { disclosedValuesOf } from '../match.js';
import { RedactionError, requestReveals, responseReveals } from '../redact.js';

export type { ByteRange, RevealedBytes };
export { disclosedValuesOf, RedactionError, redactedResponseText, requestReveals, responseReveals };
