import nacl from "tweetnacl";
import bs58 from "bs58";
import {
  PublicKey,
  Transaction,
  VersionedTransaction,
  TransactionInstruction,
  MessageV0,
  Connection,
  TransactionMessage,
  AddressLookupTableAccount,
} from "@solana/web3.js";
import { createMemoInstruction, MEMO_PROGRAM_ID } from "@solana/spl-memo";
import { BaseChainAdapter } from "./BaseChainAdapter";
import {
  buildProtocolMeta,
  parseProtocolMeta,
  type ProtocolMetaFields,
} from "../utils/protocolMeta";
import { codeHash } from "../utils/crypto";
import type { ActionCode, DelegatedActionCode } from "../types";
import { ProtocolError } from "../errors";
import {
  serializeCanonical,
  serializeCanonicalRevoke,
  serializeDelegationProof,
} from "../utils/canonical";

/** Union of supported Solana txn types */
export type SolanaTransaction = Transaction | VersionedTransaction;

export const ADAPTER_CHAIN_NAME = "solana" as const;

export class SolanaAdapter extends BaseChainAdapter {
  /** Normalize pubkey input to PublicKey */
  private normalizePubkey(input: string | PublicKey): PublicKey {
    if (typeof input === "string") {
      return new PublicKey(input);
    }
    return input;
  }

  /** Verify the signature over canonical message (protocol-level) */
  verifyWithWallet(actionCode: ActionCode): boolean {
    // Early validation checks - these are fast and don't leak timing info
    if (actionCode.chain !== ADAPTER_CHAIN_NAME) return false;
    if (!actionCode.pubkey || !actionCode.timestamp || !actionCode.signature)
      return false;

    // Perform all operations in a single try-catch to ensure consistent timing
    try {
      const message = serializeCanonical({
        pubkey: actionCode.pubkey,
        windowStart: actionCode.timestamp,
      });
      const pub = this.normalizePubkey(actionCode.pubkey);
      const sigBytes = bs58.decode(actionCode.signature);
      const pubBytes = pub.toBytes();

      // Validate lengths
      if (sigBytes.length !== 64 || pubBytes.length !== 32) {
        return false;
      }

      // Perform signature verification
      return nacl.sign.detached.verify(message, sigBytes, pubBytes);
    } catch {
      // All errors result in false with consistent timing
      return false;
    }
  }

  /** Verify delegation proof signature */
  verifyWithDelegation(delegatedActionCode: DelegatedActionCode): boolean {
    // Early validation checks - these are fast and don't leak timing info
    if (delegatedActionCode.chain !== ADAPTER_CHAIN_NAME) return false;
    if (
      !delegatedActionCode.pubkey ||
      !delegatedActionCode.timestamp ||
      !delegatedActionCode.signature
    )
      return false;

    const proof = delegatedActionCode.delegationProof;

    // Basic validation
    if (
      !proof.walletPubkey ||
      !proof.delegatedPubkey ||
      !proof.chain ||
      !proof.expiresAt ||
      !proof.signature
    ) {
      return false;
    }

    // Validate chain matches adapter
    if (proof.chain !== ADAPTER_CHAIN_NAME) {
      return false;
    }

    // The revoke/message pubkey for delegated flow must be the delegated pubkey
    if (delegatedActionCode.pubkey !== proof.delegatedPubkey) return false;

    // Check if delegation has expired
    if (proof.expiresAt < Date.now()) return false;

    // Perform all operations in a single try-catch to ensure consistent timing
    try {
      // this check if delegation correct
      const delegationMessage = serializeDelegationProof(proof);
      const walletPub = this.normalizePubkey(proof.walletPubkey);
      const walletSigBytes = bs58.decode(proof.signature);
      const walletPubBytes = walletPub.toBytes();

      // this check if generated code correct by delegated keypair
      // The signature was created by signing a message with the DELEGATED pubkey
      const canonicalMessage = serializeCanonical({
        pubkey: proof.delegatedPubkey,
        windowStart: delegatedActionCode.timestamp,
      });
      const delegatedPub = this.normalizePubkey(proof.delegatedPubkey);
      const delegatedSigBytes = bs58.decode(delegatedActionCode.signature);
      const delegatedPubBytes = delegatedPub.toBytes();

      // Validate lengths first to prevent timing attacks
      if (walletSigBytes.length !== 64 || walletPubBytes.length !== 32) {
        return false;
      }
      if (delegatedSigBytes.length !== 64 || delegatedPubBytes.length !== 32) {
        return false;
      }

      // Perform both signature verifications regardless of first result
      // This prevents timing attacks that could leak information about which signature failed
      const delegationProofOk = nacl.sign.detached.verify(
        delegationMessage,
        walletSigBytes,
        walletPubBytes
      );

      const canonicalMessageOk = nacl.sign.detached.verify(
        canonicalMessage,
        delegatedSigBytes,
        delegatedPubBytes
      );

      // Return result only after both operations complete
      return delegationProofOk && canonicalMessageOk;
    } catch {
      // All errors result in false with consistent timing
      return false;
    }
  }

  /** Verify the signature over canonical revoke message (protocol-level) */
  verifyRevokeWithWallet(
    actionCode: ActionCode,
    revokeSignature: string
  ): boolean {
    // Early validation checks - these are fast and don't leak timing info
    if (actionCode.chain !== ADAPTER_CHAIN_NAME) return false;
    if (!actionCode.pubkey || !actionCode.timestamp || !revokeSignature)
      return false;

    // Perform all operations in a single try-catch to ensure consistent timing
    try {
      const message = serializeCanonicalRevoke({
        pubkey: actionCode.pubkey,
        codeHash: codeHash(actionCode.code),
        windowStart: actionCode.timestamp,
      });
      const pub = this.normalizePubkey(actionCode.pubkey);
      const sigBytes = bs58.decode(revokeSignature);
      const pubBytes = pub.toBytes();

      // Validate lengths
      if (sigBytes.length !== 64 || pubBytes.length !== 32) {
        return false;
      }

      // Perform signature verification
      return nacl.sign.detached.verify(message, sigBytes, pubBytes);
    } catch {
      // All errors result in false with consistent timing
      return false;
    }
  }

  verifyRevokeWithDelegation(
    delegatedActionCode: DelegatedActionCode,
    revokeSignature: string
  ): boolean {
    // Early validation checks - these are fast and don't leak timing info
    if (delegatedActionCode.chain !== ADAPTER_CHAIN_NAME) return false;
    if (
      !delegatedActionCode.pubkey ||
      !delegatedActionCode.timestamp ||
      !delegatedActionCode.signature ||
      !delegatedActionCode.delegationProof
    )
      return false;

    const proof = delegatedActionCode.delegationProof;

    // Basic validation
    if (
      !proof.walletPubkey ||
      !proof.delegatedPubkey ||
      !proof.chain ||
      !proof.expiresAt ||
      !proof.signature
    ) {
      return false;
    }

    // Validate chain matches adapter
    if (proof.chain !== ADAPTER_CHAIN_NAME) {
      return false;
    }

    // The revoke/message pubkey for delegated flow must be the delegated pubkey
    if (delegatedActionCode.pubkey !== proof.delegatedPubkey) return false;

    // Check if delegation has expired
    if (proof.expiresAt < Date.now()) return false;

    // Perform all operations in a single try-catch to ensure consistent timing
    try {
      const delegationMessage = serializeDelegationProof(proof);
      const walletPub = this.normalizePubkey(proof.walletPubkey);
      const walletSigBytes = bs58.decode(proof.signature);
      const walletPubBytes = walletPub.toBytes();

      const revokeMessage = serializeCanonicalRevoke({
        pubkey: proof.delegatedPubkey, // Revoke signature is from delegated keypair
        codeHash: codeHash(delegatedActionCode.code),
        windowStart: delegatedActionCode.timestamp,
      });
      const delegatedPub = this.normalizePubkey(proof.delegatedPubkey);
      const delegatedSigBytes = bs58.decode(revokeSignature);
      const delegatedPubBytes = delegatedPub.toBytes();

      // Validate lengths first to prevent timing attacks
      if (walletSigBytes.length !== 64 || walletPubBytes.length !== 32) {
        return false;
      }
      if (delegatedSigBytes.length !== 64 || delegatedPubBytes.length !== 32) {
        return false;
      }

      // Perform both signature verifications regardless of first result
      // This prevents timing attacks that could leak information about which signature failed
      const delegationProofOk = nacl.sign.detached.verify(
        delegationMessage,
        walletSigBytes,
        walletPubBytes
      );

      const revokeMessageOk = nacl.sign.detached.verify(
        revokeMessage,
        delegatedSigBytes,
        delegatedPubBytes
      );

      // Return result only after both operations complete
      return delegationProofOk && revokeMessageOk;
    } catch {
      // All errors result in false with consistent timing
      return false;
    }
  }

  /** Create a Solana memo instruction carrying protocol meta (for SDK/clients) */
  static createProtocolMetaIx(
    meta: ProtocolMetaFields
  ): TransactionInstruction {
    const metaString = buildProtocolMeta(meta);
    return createMemoInstruction(metaString);
  }

  /** Extract protocol metadata string (memo) from a base64-encoded transaction, or null */
  getProtocolMeta(txString: string): string | null {
    try {
      const tx = this.deserializeTransaction(txString);
      for (const ix of this.getMemoInstructions(tx)) {
        const data = ix.data;
        try {
          const s = new TextDecoder().decode(data);
          // Optionally: test parse
          const parsed = parseProtocolMeta(s);
          if (parsed) return s;
        } catch {
          // ignore
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  /** Deserialize a base64-encoded transaction string to SolanaTransaction */
  private deserializeTransaction(txString: string): SolanaTransaction {
    try {
      // Try versioned first (most common now)
      const versionedTx = VersionedTransaction.deserialize(
        Buffer.from(txString, "base64")
      );

      // Check if this is actually a versioned transaction by checking if it has a MessageV0
      if (versionedTx.message instanceof MessageV0) {
        return versionedTx;
      } else {
        // This is likely a legacy transaction that was incorrectly deserialized as versioned
        // Fall back to legacy deserialization
        return Transaction.from(Buffer.from(txString, "base64"));
      }
    } catch {
      try {
        // Fallback to legacy
        return Transaction.from(Buffer.from(txString, "base64"));
      } catch {
        throw ProtocolError.invalidTransactionFormat(
          "Invalid base64 transaction format"
        );
      }
    }
  }

  /** Get parsed ProtocolMeta object from base64-encoded transaction, or null if none or invalid */
  parseMeta(txString: string): ProtocolMetaFields | null {
    const s = this.getProtocolMeta(txString);
    if (!s) return null;
    return parseProtocolMeta(s);
  }

  /** List memo instructions from the transaction (legacy & versioned) */
  private getMemoInstructions(tx: SolanaTransaction): TransactionInstruction[] {
    if (tx instanceof Transaction) {
      return tx.instructions.filter((ix) =>
        ix.programId.equals(MEMO_PROGRAM_ID)
      );
    } else {
      // VersionedTransaction: inspect `message.compiledInstructions` / static keys
      const vtx = tx as VersionedTransaction;
      const msg = vtx.message;
      if (msg instanceof MessageV0) {
        const memos: TransactionInstruction[] = [];
        for (const ix of msg.compiledInstructions) {
          const pid = msg.staticAccountKeys[ix.programIdIndex];
          if (pid && pid.equals(MEMO_PROGRAM_ID)) {
            // reconstruct a TransactionInstruction for inspection
            const keys = ix.accountKeyIndexes.map((i) => ({
              pubkey: msg.staticAccountKeys[i]!,
              isSigner: false,
              isWritable: false,
            }));
            memos.push(
              new TransactionInstruction({
                keys,
                programId: pid,
                data: ix.data as Buffer,
              })
            );
          }
        }
        return memos;
      }
      return [];
    }
  }

  /**
   * Validate that a base64-encoded transaction's memo meta aligns with the bound `actionCode`.
   * Throws ProtocolError if validation fails.
   */
  verifyTransactionMatchesCode(actionCode: ActionCode, txString: string): void {
    // Check expiration first
    const currentTime = Date.now();
    if (currentTime > actionCode.expiresAt) {
      throw ProtocolError.expiredCode(
        actionCode.code,
        actionCode.expiresAt,
        currentTime
      );
    }

    const meta = this.parseMeta(txString);
    if (!meta) {
      throw ProtocolError.missingMeta();
    }

    // Check version
    if (meta.ver !== 2) {
      throw ProtocolError.metaMismatch("2", String(meta.ver), "ver");
    }

    // Check code ID - should be codeHash of the code, not the code itself
    const expectedCodeHash = codeHash(actionCode.code);
    if (meta.id !== expectedCodeHash) {
      throw ProtocolError.metaMismatch(expectedCodeHash, meta.id, "id");
    }

    // Check intended pubkey
    if (meta.int !== actionCode.pubkey) {
      throw ProtocolError.metaMismatch(actionCode.pubkey, meta.int, "int");
    }
  }

  /**
   * Verify that the base64-encoded transaction is signed by the "intendedFor" pubkey
   * as declared in the protocol meta of the transaction.
   * Throws ProtocolError if validation fails.
   */
  verifyTransactionSignedByIntentOwner(txString: string): void {
    const meta = this.parseMeta(txString);
    if (!meta) {
      throw ProtocolError.missingMeta();
    }

    const intended = meta.int;
    const issuer = meta.iss;
    if (!intended) {
      throw ProtocolError.invalidMetaFormat(
        "Missing 'int' (intendedFor) field"
      );
    }

    let intendedPubkey: PublicKey;
    let issuerPubkey: PublicKey;
    try {
      intendedPubkey = new PublicKey(intended);
    } catch {
      throw ProtocolError.invalidPubkeyFormat(
        intended,
        "Invalid public key format"
      );
    }

    try {
      if (issuer) {
        issuerPubkey = new PublicKey(issuer);
      }
    } catch {
      throw ProtocolError.invalidPubkeyFormat(
        issuer || "",
        "Invalid public key format"
      );
    }

    const tx = this.deserializeTransaction(txString);
    const actualSigners: string[] = [];

    // For legacy Transaction
    if (tx instanceof Transaction) {
      let isSignedByIntended = false;
      let isSignedByIssuer = false;

      tx.signatures.forEach((sig) => {
        if (!sig.signature) return;
        actualSigners.push(sig.publicKey.toString());

        if (sig.publicKey.equals(intendedPubkey)) {
          isSignedByIntended = true;
        }
        if (issuer && sig.publicKey.equals(issuerPubkey!)) {
          isSignedByIssuer = true;
        }
      });

      if (!isSignedByIntended) {
        throw ProtocolError.transactionNotSignedByIntendedOwner(
          intended,
          actualSigners
        );
      }

      if (issuer && !isSignedByIssuer) {
        throw ProtocolError.transactionNotSignedByIssuer(
          issuer,
          actualSigners
        );
      }
      return;
    }

    // For VersionedTransaction (MessageV0)
    if (tx instanceof VersionedTransaction) {
      const msg = tx.message;
      if (msg instanceof MessageV0) {
        let isSignedByIntended = false;
        let isSignedByIssuer = false;
        const signerCount = msg.header.numRequiredSignatures;
        for (let i = 0; i < signerCount; i++) {
          const key = msg.staticAccountKeys[i];
          if (key) {
            actualSigners.push(key.toString());
            if (key.equals(intendedPubkey)) {
              isSignedByIntended = true;
            }
            if (issuer && key.equals(issuerPubkey!)) {
              isSignedByIssuer = true;
            }
          }
        }
        if (!isSignedByIntended) {
          throw ProtocolError.transactionNotSignedByIntendedOwner(
            intended,
            actualSigners
          );
        }
        if (issuer && !isSignedByIssuer) {
          throw ProtocolError.transactionNotSignedByIssuer(
            issuer,
            actualSigners
          );
        }
        return;
      }
    }

    throw ProtocolError.invalidTransactionFormat(
      "Unsupported transaction format"
    );
  }

  verifyMessageSignedByIntentOwner(
    message: string,
    signature: string,
    pubkey: string
  ): void {
    try {
      const messageBytes = new TextEncoder().encode(message);
      const signatureBytes = bs58.decode(signature);
      const pubkeyObj = this.normalizePubkey(pubkey);
      const pubBytes = pubkeyObj.toBytes();

      const isValid = nacl.sign.detached.verify(
        messageBytes,
        signatureBytes,
        pubBytes
      );

      if (!isValid) {
        throw ProtocolError.invalidSignature("Signature verification failed");
      }
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes("Signature verification failed")
      ) {
        throw error;
      }
      throw ProtocolError.invalidSignature("Invalid signature format");
    }
  }

  /**
   * Attach protocol meta into a base64-encoded transaction and return the modified transaction as base64.
   * Throws ProtocolError if the transaction already contains protocol meta.
   * 
   * @param txString - Base64-encoded transaction string
   * @param meta - Protocol metadata to attach
   * @param connection - Optional Solana connection. Required if transaction has address lookup tables
   *                    and instructions reference accounts from those tables.
   * @returns Base64-encoded transaction with protocol meta attached
   */
  static async attachProtocolMeta(
    txString: string,
    meta: ProtocolMetaFields,
    connection?: Connection
  ): Promise<string> {
    // Check if transaction already has protocol meta
    const adapter = new SolanaAdapter();
    const existingMeta = adapter.getProtocolMeta(txString);
    if (existingMeta) {
      throw ProtocolError.invalidTransactionFormat(
        "Transaction already contains protocol meta. Cannot attach additional protocol meta."
      );
    }

    const metaIx = SolanaAdapter.createProtocolMetaIx(meta);

    try {
      // Try to deserialize as versioned first
      const versionedTx = VersionedTransaction.deserialize(
        Buffer.from(txString, "base64")
      );

      // Check if this is actually a versioned transaction by checking if it has a MessageV0
      if (versionedTx.message instanceof MessageV0) {
        const msg = versionedTx.message;

        // Check if we need to handle address lookup tables
        const hasAddressTableLookups =
          msg.addressTableLookups && msg.addressTableLookups.length > 0;

        // Check if any instruction references accounts beyond static account keys
        // (which would indicate they reference lookup table accounts)
        const numStaticAccounts = msg.staticAccountKeys.length;
        const referencesLookupAccounts = msg.compiledInstructions.some((ix) =>
          ix.accountKeyIndexes.some((idx) => idx >= numStaticAccounts)
        );

        // If we have lookup tables and instructions reference them, we need a connection
        if (hasAddressTableLookups && referencesLookupAccounts) {
          if (!connection) {
            throw ProtocolError.invalidTransactionFormat(
              "Connection required: Transaction uses address lookup tables and instructions reference accounts from those tables. A Solana connection is needed to resolve lookup tables and correctly recalculate account indices."
            );
          }

          // Resolve address lookup tables
          const addressLookupTableAccounts: AddressLookupTableAccount[] = [];
          for (const lookup of msg.addressTableLookups) {
            try {
              const lookupTableAccount = await connection.getAddressLookupTable(
                lookup.accountKey
              );
              if (lookupTableAccount.value) {
                addressLookupTableAccounts.push(lookupTableAccount.value);
              }
            } catch (error) {
              throw ProtocolError.invalidTransactionFormat(
                `Failed to resolve address lookup table ${lookup.accountKey.toString()}: ${error}`
              );
            }
          }

          // Decompile the message with resolved lookup tables
          const decompiledMessage = TransactionMessage.decompile(msg, {
            addressLookupTableAccounts,
          });

          // Add memo instruction (programId will be added automatically during compilation)
          decompiledMessage.instructions.push(metaIx);

          // Recompile - this will correctly recalculate all account indices
          const recompiledMessage =
            decompiledMessage.compileToV0Message(addressLookupTableAccounts);

          // Re-wrap in VersionedTransaction
          const newTx = new VersionedTransaction(recompiledMessage);
          // Preserve existing signatures if any
          newTx.signatures = versionedTx.signatures;

          return Buffer.from(newTx.serialize()).toString("base64");
        } else {
          // Simple case: no lookup tables or no instructions reference them
          // Use the original simple approach
          const newStaticKeys = [...msg.staticAccountKeys];
          if (!newStaticKeys.some((k) => k.equals(MEMO_PROGRAM_ID))) {
            newStaticKeys.push(MEMO_PROGRAM_ID);
          }

          // Program ID index
          const programIdIndex = newStaticKeys.findIndex((k) =>
            k.equals(MEMO_PROGRAM_ID)
          );

          // Memo instruction as compiled instruction
          const compiledIx = {
            programIdIndex,
            accountKeyIndexes: [],
            data: metaIx.data,
          };

          const newMsg = new MessageV0({
            header: msg.header,
            staticAccountKeys: newStaticKeys,
            recentBlockhash: msg.recentBlockhash,
            compiledInstructions: [...msg.compiledInstructions, compiledIx],
            addressTableLookups: msg.addressTableLookups,
          });

          // Re-wrap in VersionedTransaction
          const newTx = new VersionedTransaction(newMsg);
          // Preserve existing signatures if any
          newTx.signatures = versionedTx.signatures;

          return Buffer.from(newTx.serialize()).toString("base64");
        }
      } else {
        // This is likely a legacy transaction that was incorrectly deserialized as versioned
        // Fall back to legacy deserialization
        const legacyTx = Transaction.from(Buffer.from(txString, "base64"));

        // Legacy tx: just push memo instruction
        legacyTx.add(metaIx);

        return Buffer.from(
          legacyTx.serialize({ requireAllSignatures: false })
        ).toString("base64");
      }
    } catch (error) {
      // If it's already a ProtocolError, re-throw it
      if (error instanceof ProtocolError) {
        throw error;
      }

      try {
        // Fallback to legacy transaction
        const legacyTx = Transaction.from(Buffer.from(txString, "base64"));

        // Legacy tx: just push memo instruction
        legacyTx.add(metaIx);

        return Buffer.from(
          legacyTx.serialize({ requireAllSignatures: false })
        ).toString("base64");
      } catch {
        throw ProtocolError.invalidTransactionFormat(
          `Invalid base64 transaction format: ${error}`
        );
      }
    }
  }
}
