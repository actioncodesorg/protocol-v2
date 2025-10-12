import { WalletStrategy } from "./WalletStrategy";
import { serializeCanonical } from "../utils/canonical";
import { ProtocolError } from "../errors";
import { PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import bs58 from "bs58";

import type {
  DelegationProof,
  DelegatedActionCode,
  CodeGenerationConfig,
  Chain,
} from "../types";

export class DelegationStrategy {
  private walletStrategy: WalletStrategy;
  private config: CodeGenerationConfig;

  constructor(config: CodeGenerationConfig) {
    this.config = config;
    this.walletStrategy = new WalletStrategy(config);
  }

  /**
   * Generate a delegated action code using a delegation proof and signature over message to generate code via delegated keypair
   */
  generateDelegatedCode(
    delegationProof: DelegationProof,
    canonicalMessage: Uint8Array,
    chain: Chain,
    signature: string // this is the signature over message to generate code via delegated keypair
  ): DelegatedActionCode {
    // Validate delegation proof format and expiration
    this.validateDelegationProof(delegationProof);

    // Generate code using existing WalletStrategy with the original canonical message
    // The signature was created over this message by the delegated keypair
    const result = this.walletStrategy.generateCode(
      canonicalMessage,
      chain,
      signature // Use signature from delegated keypair
    );

    // Create delegated action code
    const delegatedActionCode: DelegatedActionCode = {
      ...result,
      delegationProof: delegationProof,
    };

    return delegatedActionCode;
  }

  /**
   * Validate a delegated action code
   */
  validateDelegatedCode(
    actionCode: DelegatedActionCode,
  ): void {
    // Basic validation checks (similar to WalletStrategy.validateCode)
    const currentTime = Date.now();
    if (currentTime > actionCode.expiresAt + (this.config.clockSkewMs ?? 0)) {
      throw ProtocolError.expiredCode(
        actionCode.code,
        actionCode.expiresAt,
        currentTime
      );
    }

    // Verify delegation proof is still valid
    this.validateDelegationProof(actionCode.delegationProof);

    // Verify the delegation proof matches the action code
    // The action code pubkey should be the delegated signer (who signed the message)
    if (actionCode.pubkey !== actionCode.delegationProof.delegatedPubkey) {
      throw ProtocolError.invalidInput(
        "delegatedPubkey",
        actionCode.delegationProof.delegatedPubkey,
        "Action code pubkey does not match delegated signer"
      );
    }

    // Verify that the generated code doesn't expire after the delegation proof
    // This prevents codes from outliving their authorization
    if (actionCode.expiresAt > actionCode.delegationProof.expiresAt) {
      throw ProtocolError.invalidInput(
        "expiresAt",
        actionCode.expiresAt,
        "Action code cannot expire after delegation proof expiration"
      );
    }

    // Verify delegated signature is present
    if (!actionCode.delegationProof.signature) {
      throw ProtocolError.missingRequiredField("delegationProof.signature");
    }

    // Finally, verify the delegated signature against the canonical message
    // The signature was created by signing a message with the DELEGATED pubkey
    // even though the ActionCode.pubkey is the wallet owner
    const canonicalMessage = serializeCanonical({
      pubkey: actionCode.delegationProof.delegatedPubkey,
      windowStart: actionCode.timestamp,
    });

    // Decode and verify the delegated signature
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = bs58.decode(actionCode.signature ?? "");
    } catch {
      throw ProtocolError.invalidSignature(
        "Invalid Base58 delegated signature format"
      );
    }

    // Verify the signature using the delegated keypair's public key
    const delegatedPubkeyBytes = bs58.decode(actionCode.delegationProof.delegatedPubkey);
    const isValidSignature = nacl.sign.detached.verify(
      canonicalMessage,
      signatureBytes,
      delegatedPubkeyBytes
    );

    if (!isValidSignature) {
      throw ProtocolError.invalidSignature(
        "Delegated signature verification failed"
      );
    }
  }

  /**
   * Validate a delegation proof with comprehensive input validation
   */
  private validateDelegationProof(delegationProof: DelegationProof): void {
    // Validate walletPubkey using Solana's PublicKey constructor
    if (
      !delegationProof.walletPubkey ||
      typeof delegationProof.walletPubkey !== "string"
    ) {
      throw ProtocolError.invalidInput(
        "walletPubkey",
        delegationProof.walletPubkey,
        "Wallet pubkey is required and must be a string"
      );
    }
    try {
      new PublicKey(delegationProof.walletPubkey);
    } catch {
      throw ProtocolError.invalidInput(
        "walletPubkey",
        delegationProof.walletPubkey,
        "Invalid wallet pubkey format"
      );
    }

    // Validate delegatedPubkey using Solana's PublicKey constructor
    if (
      !delegationProof.delegatedPubkey ||
      typeof delegationProof.delegatedPubkey !== "string"
    ) {
      throw ProtocolError.invalidInput(
        "delegatedPubkey",
        delegationProof.delegatedPubkey,
        "Delegated pubkey is required and must be a string"
      );
    }
    try {
      new PublicKey(delegationProof.delegatedPubkey);
    } catch {
      throw ProtocolError.invalidInput(
        "delegatedPubkey",
        delegationProof.delegatedPubkey,
        "Invalid delegated pubkey format"
      );
    }

    // Validate chain
    if (!delegationProof.chain || typeof delegationProof.chain !== "string") {
      throw ProtocolError.invalidInput(
        "chain",
        delegationProof.chain,
        "Chain is required and must be a string"
      );
    }
    if (
      delegationProof.chain.length === 0 ||
      delegationProof.chain.length > 50
    ) {
      throw ProtocolError.invalidInput(
        "chain",
        delegationProof.chain,
        "Chain must be between 1 and 50 characters"
      );
    }
    if (!/^[a-z0-9-]+$/.test(delegationProof.chain)) {
      throw ProtocolError.invalidInput(
        "chain",
        delegationProof.chain,
        "Chain contains invalid characters (only lowercase letters, numbers, and hyphens allowed)"
      );
    }

    // Validate expiresAt
    if (
      typeof delegationProof.expiresAt !== "number" ||
      !Number.isInteger(delegationProof.expiresAt)
    ) {
      throw ProtocolError.invalidInput(
        "expiresAt",
        delegationProof.expiresAt,
        "Expiration time must be a valid integer timestamp"
      );
    }
    if (delegationProof.expiresAt <= 0) {
      throw ProtocolError.invalidInput(
        "expiresAt",
        delegationProof.expiresAt,
        "Expiration time must be positive"
      );
    }

    // Check for reasonable expiration bounds (not too far in the future)
    const now = Date.now();
    const maxFuture = 365 * 24 * 60 * 60 * 1000; // 1 year from now

    if (delegationProof.expiresAt > now + maxFuture) {
      throw ProtocolError.invalidInput(
        "expiresAt",
        delegationProof.expiresAt,
        "Expiration time is too far in the future"
      );
    }

    // Check if delegation has expired
    if (delegationProof.expiresAt < now) {
      throw ProtocolError.expiredCode(
        "Delegation proof has expired",
        delegationProof.expiresAt,
        now
      );
    }

    // Validate signature
    if (
      !delegationProof.signature ||
      typeof delegationProof.signature !== "string"
    ) {
      throw ProtocolError.invalidInput(
        "signature",
        delegationProof.signature,
        "Delegation signature is required and must be a string"
      );
    }
    if (
      delegationProof.signature.length === 0 ||
      delegationProof.signature.length > 200
    ) {
      throw ProtocolError.invalidInput(
        "signature",
        delegationProof.signature,
        "Delegation signature must be between 1 and 200 characters"
      );
    }
    // Note: Signature format validation will be done during actual verification
  }
}
