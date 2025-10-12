import type { ActionCode, DelegatedActionCode, Chain } from "../types";

export interface ChainAdapter {
  verifyWithWallet(actionCode: ActionCode): boolean;
  verifyWithDelegation(actionCode: DelegatedActionCode): boolean;
  verifyRevokeWithWallet(
    actionCode: ActionCode,
    revokeSignature: string
  ): boolean;
  verifyRevokeWithDelegation(
    actionCode: DelegatedActionCode,
    revokeSignature: string
  ): boolean;
}

export type SignFn = (message: Uint8Array, chain: Chain) => Promise<string>;

export abstract class BaseChainAdapter implements ChainAdapter {
  abstract verifyWithWallet(actionCode: ActionCode): boolean;
  abstract verifyWithDelegation(actionCode: DelegatedActionCode): boolean;
  abstract verifyRevokeWithWallet(
    actionCode: ActionCode,
    revokeSignature: string
  ): boolean;
  abstract verifyRevokeWithDelegation(
    actionCode: DelegatedActionCode,
    revokeSignature: string
  ): boolean;
}
