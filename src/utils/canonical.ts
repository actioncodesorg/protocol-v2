import type {
  CanonicalMessageParts,
  CanonicalRevokeMessageParts,
  DelegationProof,
} from "../types";
import { ProtocolError } from "../errors";

export const CANONICAL_MESSAGE_VERSION = 1;
export const CANONICAL_MESSAGE_PREFIX = "actioncodes";
export const CANONICAL_REVOKE_MESSAGE_PREFIX = "actioncodes-revoke";

export function serializeCanonical(parts: CanonicalMessageParts): Uint8Array {
  // Comprehensive validation for public key and JSON safety
  if (typeof parts.pubkey !== "string") {
    throw ProtocolError.invalidInput(
      "pubkey",
      parts.pubkey,
      "must be a string"
    );
  }

  // Check for empty or too long pubkey
  if (parts.pubkey.length === 0) {
    throw ProtocolError.invalidInput("pubkey", parts.pubkey, "cannot be empty");
  }
  if (parts.pubkey.length > 100) {
    throw ProtocolError.invalidInput("pubkey", parts.pubkey, "too long (max 100 characters)");
  }

  // Check for characters that can't be in a valid public key or would break JSON
  // Valid public keys are typically base58/base64 encoded (alphanumeric + some special chars)
  // But we need to prevent JSON injection, so check for dangerous characters
  if (/["\\\x00-\x1f\x7f-\x9f]/.test(parts.pubkey)) {
    throw ProtocolError.invalidInput(
      "pubkey",
      parts.pubkey,
      "contains invalid characters for public key or JSON"
    );
  }

  const json = JSON.stringify({
    id: CANONICAL_MESSAGE_PREFIX,
    ver: CANONICAL_MESSAGE_VERSION,
    pubkey: parts.pubkey,
    windowStart: parts.windowStart,
  });
  return new TextEncoder().encode(json);
}

export function serializeCanonicalRevoke(
  parts: CanonicalRevokeMessageParts
): Uint8Array {
  // Minimal validation to prevent JSON injection attacks
  if (typeof parts.pubkey !== "string") {
    throw ProtocolError.invalidInput(
      "pubkey",
      parts.pubkey,
      "must be a string"
    );
  }

  if (typeof parts.codeHash !== "string") {
    throw ProtocolError.invalidInput(
      "codeHash",
      parts.codeHash,
      "must be a string"
    );
  }

  // Check for empty or too long values
  if (parts.pubkey.length === 0) {
    throw ProtocolError.invalidInput("pubkey", parts.pubkey, "cannot be empty");
  }
  if (parts.pubkey.length > 100) {
    throw ProtocolError.invalidInput("pubkey", parts.pubkey, "too long (max 100 characters)");
  }
  
  if (parts.codeHash.length === 0) {
    throw ProtocolError.invalidInput("codeHash", parts.codeHash, "cannot be empty");
  }
  if (parts.codeHash.length > 100) {
    throw ProtocolError.invalidInput("codeHash", parts.codeHash, "too long (max 100 characters)");
  }
  
  // Check for characters that can't be in valid identifiers or would break JSON
  if (/["\\\x00-\x1f\x7f-\x9f]/.test(parts.pubkey) || /["\\\x00-\x1f\x7f-\x9f]/.test(parts.codeHash)) {
    throw ProtocolError.invalidInput("input", "contains invalid characters for identifiers or JSON", "contains invalid characters");
  }

  const json = JSON.stringify({
    id: CANONICAL_REVOKE_MESSAGE_PREFIX,
    ver: CANONICAL_MESSAGE_VERSION,
    pubkey: parts.pubkey,
    codeHash: parts.codeHash,
    windowStart: parts.windowStart,
  });
  return new TextEncoder().encode(json);
}

export function getCanonicalMessageParts(pubkey: string): Uint8Array {
  return serializeCanonical({ pubkey, windowStart: Date.now() });
}

export function serializeDelegationProof(
  proof: Omit<DelegationProof, "signature">
): Uint8Array {
  // Comprehensive validation for delegation proof fields and JSON safety
  const fields = ["walletPubkey", "delegatedPubkey", "chain"] as const;
  for (const field of fields) {
    const value = proof[field];
    if (typeof value !== "string") {
      throw ProtocolError.invalidInput(field, value, "must be a string");
    }
    
    // Check for empty or too long values
    if (value.length === 0) {
      throw ProtocolError.invalidInput(field, value, "cannot be empty");
    }
    if (value.length > 100) {
      throw ProtocolError.invalidInput(field, value, "too long (max 100 characters)");
    }
    
    // Check for characters that can't be in valid identifiers or would break JSON
    if (/["\\\x00-\x1f\x7f-\x9f]/.test(value)) {
      throw ProtocolError.invalidInput(field, value, "contains invalid characters for identifiers or JSON");
    }
  }

  const json = JSON.stringify({
    walletPubkey: proof.walletPubkey,
    delegatedPubkey: proof.delegatedPubkey,
    expiresAt: proof.expiresAt,
    chain: proof.chain,
  });
  return new TextEncoder().encode(json);
}
