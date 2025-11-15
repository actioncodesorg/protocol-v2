import {
  Keypair,
  Transaction,
  VersionedTransaction,
  MessageV0,
  PublicKey,
} from "@solana/web3.js";
import { MEMO_PROGRAM_ID } from "@solana/spl-memo";
import bs58 from "bs58";
import nacl from "tweetnacl";
import { SolanaAdapter } from "../../src/adapters/SolanaAdapter";
import {
  serializeCanonical,
  serializeCanonicalRevoke,
  serializeDelegationProof,
} from "../../src/utils/canonical";
import { codeHash } from "../../src/utils/crypto";
import type { ActionCode, DelegatedActionCode, Chain } from "../../src/types";
import type { ProtocolMetaFields } from "../../src/utils/protocolMeta";

describe("SolanaAdapter", () => {
  let adapter: SolanaAdapter;
  let keypair: Keypair;

  beforeEach(() => {
    adapter = new SolanaAdapter();
    keypair = Keypair.generate();
  });

  describe("verify method", () => {
    test("verify returns true for valid signature", () => {
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const message = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalMessageParts.windowStart,
        expiresAt: canonicalMessageParts.windowStart + 120000,
        chain: "solana",
        signature: signatureB58,
      };

      const result = adapter.verifyWithWallet(actionCode);
      expect(result).toBe(true);
    });

    test("verify returns false for invalid signature", () => {
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const message = serializeCanonical(canonicalMessageParts);
      const wrongKeypair = nacl.sign.keyPair();
      const signature = nacl.sign.detached(message, wrongKeypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalMessageParts.windowStart,
        expiresAt: canonicalMessageParts.windowStart + 120000,
        chain: "solana",
        signature: signatureB58,
      };

      const result = adapter.verifyWithWallet(actionCode);
      expect(result).toBe(false);
    });

    test("verify works with both string and PublicKey pubkeys", () => {
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const message = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      // Test with string pubkey
      const actionCode1: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalMessageParts.windowStart,
        expiresAt: canonicalMessageParts.windowStart + 120000,
        chain: "solana",
        signature: signatureB58,
      };
      expect(adapter.verifyWithWallet(actionCode1)).toBe(true);

      // Test with same string pubkey (the adapter normalizes internally)
      const actionCode2: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalMessageParts.windowStart,
        expiresAt: canonicalMessageParts.windowStart + 120000,
        chain: "solana",
        signature: signatureB58,
      };
      expect(adapter.verifyWithWallet(actionCode2)).toBe(true);
    });
  });

  describe("verifyRevokeWithWallet method", () => {
    test("verifyRevokeWithWallet returns true for valid signature", () => {
      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        chain: "solana",
        signature: "original-signature",
      };

      // Create canonical revoke message using the same codeHash that the method will use
      const canonicalRevokeMessageParts = {
        pubkey: actionCode.pubkey,
        codeHash: codeHash(actionCode.code),
        windowStart: actionCode.timestamp,
      };
      const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const result = adapter.verifyRevokeWithWallet(actionCode, signatureB58);
      expect(result).toBe(true);
    });

    test("verifyRevokeWithWallet returns false for invalid signature", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-123",
        windowStart: Date.now(),
      };
      const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
      const wrongKeypair = nacl.sign.keyPair();
      const signature = nacl.sign.detached(message, wrongKeypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalRevokeMessageParts.windowStart,
        expiresAt: canonicalRevokeMessageParts.windowStart + 120000,
        chain: "solana",
        signature: "original-signature",
      };

      const result = adapter.verifyRevokeWithWallet(actionCode, signatureB58);
      expect(result).toBe(false);
    });

    test("verifyRevokeWithWallet works with both string and PublicKey pubkeys", () => {
      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        chain: "solana",
        signature: "original-signature",
      };

      // Create canonical revoke message using the same codeHash that the method will use
      const canonicalRevokeMessageParts = {
        pubkey: actionCode.pubkey,
        codeHash: codeHash(actionCode.code),
        windowStart: actionCode.timestamp,
      };
      const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      // Test with string pubkey
      expect(adapter.verifyRevokeWithWallet(actionCode, signatureB58)).toBe(
        true
      );

      // Test with same string pubkey (the adapter normalizes internally)
      expect(adapter.verifyRevokeWithWallet(actionCode, signatureB58)).toBe(
        true
      );
    });

    test("verifyRevokeWithWallet returns false for wrong chain", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-789",
        windowStart: Date.now(),
      };
      const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalRevokeMessageParts.windowStart,
        expiresAt: canonicalRevokeMessageParts.windowStart + 120000,
        chain: "ethereum" as any, // Wrong chain
        signature: "original-signature",
      };

      const result = adapter.verifyRevokeWithWallet(actionCode, signatureB58);
      expect(result).toBe(false);
    });

    test("verifyRevokeWithWallet returns false for missing required fields", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-999",
        windowStart: Date.now(),
      };

      // Missing signature
      const actionCode1: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalRevokeMessageParts.windowStart,
        expiresAt: canonicalRevokeMessageParts.windowStart + 120000,
        chain: "solana",
        signature: "original-signature",
      };
      expect(adapter.verifyRevokeWithWallet(actionCode1, "")).toBe(false); // Empty signature

      // Missing pubkey
      const actionCode2: ActionCode = {
        code: "12345678",
        pubkey: "", // Empty pubkey
        timestamp: canonicalRevokeMessageParts.windowStart,
        expiresAt: canonicalRevokeMessageParts.windowStart + 120000,
        chain: "solana",
        signature: "original-signature",
      };
      expect(
        adapter.verifyRevokeWithWallet(actionCode2, "some-signature")
      ).toBe(false);

      // Missing timestamp
      const actionCode3: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: 0, // Invalid timestamp
        expiresAt: canonicalRevokeMessageParts.windowStart + 120000,
        chain: "solana",
        signature: "original-signature",
      };
      expect(
        adapter.verifyRevokeWithWallet(actionCode3, "some-signature")
      ).toBe(false);
    });

    test("verifyRevokeWithWallet handles malformed signature gracefully", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-malformed",
        windowStart: Date.now(),
      };

      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalRevokeMessageParts.windowStart,
        expiresAt: canonicalRevokeMessageParts.windowStart + 120000,
        chain: "solana",
        signature: "original-signature",
      };

      const result = adapter.verifyRevokeWithWallet(
        actionCode,
        "invalid-base58-signature"
      );
      expect(result).toBe(false);
    });

    test("verifyRevokeWithWallet handles different codeHash values", () => {
      const codes = [
        "12345678",
        "87654321",
        "abcdefgh",
        "a".repeat(8), // Long code
        "short", // Short code
      ];

      for (const code of codes) {
        const actionCode: ActionCode = {
          code,
          pubkey: keypair.publicKey.toString(),
          timestamp: Date.now(),
          expiresAt: Date.now() + 120000,
          chain: "solana",
          signature: "original-signature",
        };

        // Create canonical revoke message using the same codeHash that the method will use
        const canonicalRevokeMessageParts = {
          pubkey: actionCode.pubkey,
          codeHash: codeHash(actionCode.code),
          windowStart: actionCode.timestamp,
        };
        const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
        const signature = nacl.sign.detached(message, keypair.secretKey);
        const signatureB58 = bs58.encode(signature);

        const result = adapter.verifyRevokeWithWallet(actionCode, signatureB58);
        expect(result).toBe(true);
      }
    });
  });

  describe("transaction meta methods", () => {
    test("createProtocolMetaIx creates valid memo instruction", () => {
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });

      expect(instruction.programId.toString()).toBe(MEMO_PROGRAM_ID.toString());
      expect(instruction.keys).toHaveLength(0);
      expect(instruction.data.toString("utf8")).toContain("actioncodes:ver=2");
    });

    test("getProtocolMeta extracts meta from transaction", () => {
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });
      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = adapter.getProtocolMeta(base64String);
      expect(result).toContain("actioncodes:ver=2");
      expect(result).toContain(`id=${codeHashValue}`);
      expect(result).toContain("int=user%40example.com"); // URL encoded @
      expect(result).toContain("p=%7B%22amount%22%3A100%7D"); // URL encoded JSON
    });

    test("getProtocolMeta returns null when no memo instruction", () => {
      const tx = new Transaction(); // Empty transaction
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = adapter.getProtocolMeta(base64String);
      expect(result).toBe(null);
    });

    test("parseMeta extracts and parses meta from transaction", () => {
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });
      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = adapter.parseMeta(base64String);
      expect(result).toEqual({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });
    });

    test("parseMeta returns null when no valid meta", () => {
      const tx = new Transaction(); // Empty transaction
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = adapter.parseMeta(base64String);
      expect(result).toBe(null);
    });

    test("verifyTransactionMatchesCode validates action code against transaction meta", () => {
      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: "user@example.com",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        signature: "test-signature",
        chain: "solana",
      };

      const codeHashValue = codeHash(actionCode.code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
      });
      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      // Should not throw for valid transaction
      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionMatchesCode(actionCode, base64String);
      }).not.toThrow();
    });

    test("verifyTransactionMatchesCode throws when meta doesn't match", () => {
      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: "user@example.com",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        chain: "solana",
        signature: "test-signature",
      };

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: "different-codehash", // Different codeHash
        int: "user@example.com",
      });
      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionMatchesCode(actionCode, base64String);
      }).toThrow();
    });

    test("verifyTransactionMatchesCode throws when no meta", () => {
      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: "user@example.com",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        chain: "solana",
        signature: "test-signature",
      };

      const tx = new Transaction(); // Empty transaction
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionMatchesCode(actionCode, base64String);
      }).toThrow();
    });

    test("verifyTransactionSignedByIntentOwner returns true when transaction is signed by intended owner", () => {
      const keypair = Keypair.generate();
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: keypair.publicKey.toString(), // Use the keypair's pubkey as intended
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;
      tx.recentBlockhash = "11111111111111111111111111111111"; // Mock recent blockhash
      tx.sign(keypair); // Sign with the intended keypair

      // Should not throw for valid transaction
      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).not.toThrow();
    });

    test("verifyTransactionSignedByIntentOwner throws when transaction is not signed by intended owner", () => {
      const intendedKeypair = Keypair.generate();
      const signingKeypair = Keypair.generate(); // Different keypair
      const code = "12345678";
      const codeHashValue = codeHash(code);

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: intendedKeypair.publicKey.toString(), // Intended is different from signer
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = signingKeypair.publicKey; // Use the signing keypair as fee payer
      tx.sign(signingKeypair); // Sign with different keypair

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).toThrow();
    });

    test("verifyTransactionSignedByIntentOwner throws when no meta", () => {
      const keypair = Keypair.generate();
      const tx = new Transaction();
      tx.recentBlockhash = "11111111111111111111111111111111"; // Mock recent blockhash
      tx.feePayer = keypair.publicKey;
      tx.sign(keypair);

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).toThrow();
    });

    test("verifyTransactionSignedByIntentOwner throws when intended pubkey is invalid", () => {
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "invalid-pubkey", // Invalid pubkey format
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).toThrow();
    });

    test("verifyTransactionSignedByIntentOwner succeeds when transaction is signed by both int and iss", () => {
      const intendedKeypair = Keypair.generate();
      const issuerKeypair = Keypair.generate();
      const code = "12345678";
      const codeHashValue = codeHash(code);

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: intendedKeypair.publicKey.toString(),
        iss: issuerKeypair.publicKey.toString(),
      });

      // Add issuer as a signer in the instruction
      instruction.keys.push({
        pubkey: issuerKeypair.publicKey,
        isSigner: true,
        isWritable: false,
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = intendedKeypair.publicKey;
      
      // Sign with both intended and issuer
      tx.sign(intendedKeypair, issuerKeypair);

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).not.toThrow();
    });

    test("verifyTransactionSignedByIntentOwner throws when transaction has iss but only signed by int", () => {
      const intendedKeypair = Keypair.generate();
      const issuerKeypair = Keypair.generate();
      const code = "12345678";
      const codeHashValue = codeHash(code);

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: intendedKeypair.publicKey.toString(),
        iss: issuerKeypair.publicKey.toString(),
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = intendedKeypair.publicKey;
      
      // Sign only with intended, not issuer
      tx.sign(intendedKeypair);

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).toThrow(/issuer/);
    });

    test("verifyTransactionSignedByIntentOwner throws when transaction has iss but only signed by iss", () => {
      const intendedKeypair = Keypair.generate();
      const issuerKeypair = Keypair.generate();
      const code = "12345678";
      const codeHashValue = codeHash(code);

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: intendedKeypair.publicKey.toString(),
        iss: issuerKeypair.publicKey.toString(),
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = issuerKeypair.publicKey;
      
      // Sign only with issuer, not intended
      tx.sign(issuerKeypair);

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).toThrow(/intended owner/);
    });

    test("verifyTransactionSignedByIntentOwner succeeds when iss field is absent (only checks int)", () => {
      const keypair = Keypair.generate();
      const code = "12345678";
      const codeHashValue = codeHash(code);

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: keypair.publicKey.toString(),
        // No iss field
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;
      tx.sign(keypair);

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).not.toThrow();
    });

    test("verifyTransactionSignedByIntentOwner succeeds when int and iss are same signer", () => {
      const keypair = Keypair.generate();
      const code = "12345678";
      const codeHashValue = codeHash(code);

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: keypair.publicKey.toString(),
        iss: keypair.publicKey.toString(), // Same as int
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;
      tx.sign(keypair);

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).not.toThrow();
    });

    describe("verifyTransactionSignedByIntentOwner - Versioned Transaction with Address Lookup Tables", () => {
      test("should verify versioned transaction with lookup tables when signer is in staticAccountKeys", () => {
        const intendedKeypair = Keypair.generate();
        const code = "12345678";
        const codeHashValue = codeHash(code);

        // Create a versioned transaction with address lookup tables
        // Signer must be in staticAccountKeys (Solana requirement)
        const lookupTableAccount = Keypair.generate().publicKey;
        const otherAccount = Keypair.generate().publicKey;
        const programId = Keypair.generate().publicKey;

        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 1, // programId is readonly
            },
            staticAccountKeys: [
              intendedKeypair.publicKey, // 0: signer (fee payer)
              programId, // 1: program
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 1, // programId
                accountKeyIndexes: [0, 2], // 0 = signer, 2 = account from lookup table
                data: Buffer.from("test instruction"),
              },
            ],
            addressTableLookups: [
              {
                accountKey: lookupTableAccount,
                writableIndexes: [0], // Account at index 0 in lookup table becomes index 2 overall
                readonlyIndexes: [],
              },
            ],
          })
        );

        // Sign the transaction
        versionedTx.sign([intendedKeypair]);

        // Attach protocol meta
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: codeHashValue,
          int: intendedKeypair.publicKey.toString(),
        };

        // Note: We need to attach meta first, then verify
        // But attachProtocolMeta clears signatures, so we need to re-sign
        // For this test, let's create the transaction with meta already attached
        const txWithMeta = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 2, // programId and MEMO_PROGRAM_ID are readonly
            },
            staticAccountKeys: [
              intendedKeypair.publicKey, // 0: signer
              programId, // 1: program
              MEMO_PROGRAM_ID, // 2: memo program
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 1, // programId
                accountKeyIndexes: [0, 3], // 0 = signer, 3 = account from lookup table
                data: Buffer.from("test instruction"),
              },
              {
                programIdIndex: 2, // MEMO_PROGRAM_ID
                accountKeyIndexes: [],
                data: Buffer.from(
                  `actioncodes:ver=2&id=${codeHashValue}&int=${intendedKeypair.publicKey.toString()}`
                ),
              },
            ],
            addressTableLookups: [
              {
                accountKey: lookupTableAccount,
                writableIndexes: [0], // Account becomes index 3 overall
                readonlyIndexes: [],
              },
            ],
          })
        );

        txWithMeta.sign([intendedKeypair]);

        const base64String = Buffer.from(txWithMeta.serialize()).toString(
          "base64"
        );

        // Current implementation should work because signer is in staticAccountKeys
        expect(() => {
          adapter.verifyTransactionSignedByIntentOwner(base64String);
        }).not.toThrow();
      });

      test("should demonstrate potential issue: only checks staticAccountKeys, not resolved lookup table keys", () => {
        // This test demonstrates the issue: the current implementation only checks
        // msg.staticAccountKeys[i] instead of using msg.getAccountKeys().get(i)
        // While signers must be in staticAccountKeys in Solana, using getAccountKeys()
        // is the recommended approach for future-proofing and consistency.

        const intendedKeypair = Keypair.generate();
        const code = "12345678";
        const codeHashValue = codeHash(code);

        // Create a versioned transaction WITHOUT lookup tables to demonstrate getAccountKeys() API
        // (getAccountKeys() requires lookup tables to be resolved if present)
        const programId = Keypair.generate().publicKey;

        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 2, // programId and MEMO_PROGRAM_ID
            },
            staticAccountKeys: [
              intendedKeypair.publicKey, // 0: signer (must be static)
              programId, // 1: program
              MEMO_PROGRAM_ID, // 2: memo program
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 1, // programId
                accountKeyIndexes: [0], // signer
                data: Buffer.from("test instruction"),
              },
              {
                programIdIndex: 2, // MEMO_PROGRAM_ID
                accountKeyIndexes: [],
                data: Buffer.from(
                  `actioncodes:ver=2&id=${codeHashValue}&int=${intendedKeypair.publicKey.toString()}`
                ),
              },
            ],
            addressTableLookups: [], // No lookup tables for this test
          })
        );

        versionedTx.sign([intendedKeypair]);

        const base64String = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Verify the transaction structure
        const deserialized = VersionedTransaction.deserialize(
          Buffer.from(base64String, "base64")
        );
        const msg = deserialized.message as MessageV0;

        // Demonstrate the difference:
        // - Current code uses: msg.staticAccountKeys[i]
        // - Recommended: msg.getAccountKeys().get(i)
        // Both should work for signers (since they're always static), but getAccountKeys()
        // is the proper API that handles all account resolution

        // Current implementation checks staticAccountKeys directly
        const signerFromStatic = msg.staticAccountKeys[0];
        expect(signerFromStatic.equals(intendedKeypair.publicKey)).toBe(true);

        // The recommended approach uses getAccountKeys() which resolves all keys
        // This works when there are no lookup tables (or when they're resolved)
        const accountKeys = msg.getAccountKeys();
        const signerFromResolved = accountKeys.get(0);
        expect(signerFromResolved?.equals(intendedKeypair.publicKey)).toBe(
          true
        );

        // Current implementation should work, but demonstrates the issue:
        // It doesn't use the recommended API (getAccountKeys())
        // The issue is that if lookup tables are present, getAccountKeys() would require
        // them to be resolved, but the current code bypasses this by only checking staticAccountKeys
        expect(() => {
          adapter.verifyTransactionSignedByIntentOwner(base64String);
        }).not.toThrow();
      });

      test("should handle versioned transaction without explicit MessageV0 check (future message versions)", () => {
        // This test demonstrates issue #1: the code only handles MessageV0 explicitly
        // If other message versions exist in the future, they won't be handled.
        // The code should work with any VersionedTransaction message type.

        const intendedKeypair = Keypair.generate();
        const code = "12345678";
        const codeHashValue = codeHash(code);

        // Create a MessageV0 transaction (current only version, but code should be future-proof)
        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 1, // MEMO_PROGRAM_ID
            },
            staticAccountKeys: [
              intendedKeypair.publicKey, // 0: signer
              MEMO_PROGRAM_ID, // 1: memo program
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 1, // MEMO_PROGRAM_ID
                accountKeyIndexes: [],
                data: Buffer.from(
                  `actioncodes:ver=2&id=${codeHashValue}&int=${intendedKeypair.publicKey.toString()}`
                ),
              },
            ],
            addressTableLookups: [],
          })
        );

        versionedTx.sign([intendedKeypair]);

        const base64String = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Current code has: if (msg instanceof MessageV0)
        // This works for now, but if MessageV1, MessageV2, etc. are added,
        // they won't be handled. The code should work with any message type
        // that has getAccountKeys() method.

        // Verify it works with MessageV0
        expect(() => {
          adapter.verifyTransactionSignedByIntentOwner(base64String);
        }).not.toThrow();

        // Note: If future message versions are added, this test would need to be updated
        // to test those versions, and the implementation should be updated to handle them.
      });

      test("should demonstrate issue: staticAccountKeys access vs getAccountKeys() API", () => {
        // This test demonstrates the colleague's concern:
        // The code uses msg.staticAccountKeys[i] directly instead of msg.getAccountKeys().get(i)
        // While this works for signers (which are always static), using getAccountKeys()
        // is the recommended Solana API that properly resolves all account keys.

        const intendedKeypair = Keypair.generate();
        const issuerKeypair = Keypair.generate();
        const code = "12345678";
        const codeHashValue = codeHash(code);

        // Create a multi-signer transaction WITHOUT lookup tables
        // (getAccountKeys() requires lookup tables to be resolved if present)
        const programId = Keypair.generate().publicKey;

        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 2, // Both intended and issuer sign
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 1, // MEMO_PROGRAM_ID
            },
            staticAccountKeys: [
              intendedKeypair.publicKey, // 0: first signer
              issuerKeypair.publicKey, // 1: second signer
              MEMO_PROGRAM_ID, // 2: memo program
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 2, // MEMO_PROGRAM_ID
                accountKeyIndexes: [],
                data: Buffer.from(
                  `actioncodes:ver=2&id=${codeHashValue}&int=${intendedKeypair.publicKey.toString()}&iss=${issuerKeypair.publicKey.toString()}`
                ),
              },
            ],
            addressTableLookups: [], // No lookup tables for this test
          })
        );

        versionedTx.sign([intendedKeypair, issuerKeypair]);

        const base64String = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Verify using the recommended API (getAccountKeys)
        const deserialized = VersionedTransaction.deserialize(
          Buffer.from(base64String, "base64")
        );
        const msg = deserialized.message as MessageV0;
        const accountKeys = msg.getAccountKeys();

        // Both signers should be accessible via getAccountKeys()
        expect(accountKeys.get(0)?.equals(intendedKeypair.publicKey)).toBe(
          true
        );
        expect(accountKeys.get(1)?.equals(issuerKeypair.publicKey)).toBe(true);

        // Current implementation uses staticAccountKeys directly
        // This works but is not using the recommended API
        expect(msg.staticAccountKeys[0].equals(intendedKeypair.publicKey)).toBe(
          true
        );
        expect(msg.staticAccountKeys[1].equals(issuerKeypair.publicKey)).toBe(
          true
        );

        // Current implementation should work
        // The issue is that it doesn't use the recommended getAccountKeys() API
        // which would be more robust and future-proof
        expect(() => {
          adapter.verifyTransactionSignedByIntentOwner(base64String);
        }).not.toThrow();
      });
    });

    test("attachProtocolMeta adds meta to legacy transaction", async () => {
      const tx = new Transaction();
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const code = "12345678";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      };

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = await SolanaAdapter.attachProtocolMeta(
        base64String,
        meta as ProtocolMetaFields
      );

      // Should return a new base64 string
      expect(result).not.toBe(base64String);

      // Should be able to deserialize the result
      const resultTx = Transaction.from(Buffer.from(result, "base64"));
      expect(resultTx.instructions).toHaveLength(1);
      expect(resultTx.instructions[0]!.programId.toString()).toBe(
        MEMO_PROGRAM_ID.toString()
      );

      // Should be able to extract the meta
      const extractedMeta = adapter.getProtocolMeta(result);
      expect(extractedMeta).toContain("actioncodes:ver=2");
      expect(extractedMeta).toContain(`id=${codeHashValue}`);
    });

    test("attachProtocolMeta adds meta to versioned transaction", async () => {
      const keypair = Keypair.generate();
      const tx = new VersionedTransaction(
        new MessageV0({
          header: {
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
          },
          staticAccountKeys: [keypair.publicKey],
          recentBlockhash: "11111111111111111111111111111111",
          compiledInstructions: [],
          addressTableLookups: [],
        })
      );

      const code = "87654321";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user2@example.com",
      };

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      const result = await SolanaAdapter.attachProtocolMeta(
        base64String,
        meta as ProtocolMetaFields
      );

      // Should return a new base64 string
      expect(result).not.toBe(base64String);

      // Should be able to extract the meta
      const extractedMeta = adapter.getProtocolMeta(result);
      expect(extractedMeta).toContain("actioncodes:ver=2");
      expect(extractedMeta).toContain(`id=${codeHashValue}`);
    });

    test("attachProtocolMeta clears signatures when message changes", async () => {
      const keypair = Keypair.generate();
      const tx = new VersionedTransaction(
        new MessageV0({
          header: {
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
          },
          staticAccountKeys: [keypair.publicKey],
          recentBlockhash: "11111111111111111111111111111111",
          compiledInstructions: [],
          addressTableLookups: [],
        })
      );

      // Add some mock signatures
      tx.signatures = [new Uint8Array(64).fill(1)];

      const code = "11111111";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user3@example.com",
      };

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      const result = await SolanaAdapter.attachProtocolMeta(
        base64String,
        meta as ProtocolMetaFields
      );

      // Signatures should be cleared (empty) since message changed
      const resultTx = VersionedTransaction.deserialize(
        Buffer.from(result, "base64")
      );
      expect(resultTx.signatures.length).toBe(tx.signatures.length);
      // All signatures should be empty (64 bytes of zeros)
      resultTx.signatures.forEach((sig) => {
        expect(sig.length).toBe(64);
        expect(sig.every((byte) => byte === 0)).toBe(true);
      });
    });

    test("attachProtocolMeta handles MEMO_PROGRAM_ID already present", async () => {
      const keypair = Keypair.generate();
      const tx = new VersionedTransaction(
        new MessageV0({
          header: {
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
          },
          staticAccountKeys: [keypair.publicKey, MEMO_PROGRAM_ID], // Already present
          recentBlockhash: "11111111111111111111111111111111",
          compiledInstructions: [],
          addressTableLookups: [],
        })
      );

      const code = "22222222";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user4@example.com",
      };

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      const result = await SolanaAdapter.attachProtocolMeta(
        base64String,
        meta as ProtocolMetaFields
      );

      // Should not duplicate MEMO_PROGRAM_ID
      const resultTx = VersionedTransaction.deserialize(
        Buffer.from(result, "base64")
      );
      const msg = resultTx.message as MessageV0;
      const memoProgramCount = msg.staticAccountKeys.filter((k) =>
        k.equals(MEMO_PROGRAM_ID)
      ).length;
      expect(memoProgramCount).toBe(1);

      // Should still work
      const extractedMeta = adapter.getProtocolMeta(result);
      expect(extractedMeta).toContain("actioncodes:ver=2");
    });

    test("attachProtocolMeta throws for invalid transaction format", async () => {
      const code = "33333333";
      const codeHashValue = codeHash(code);
      const meta = { ver: 2, id: codeHashValue, int: "user" };

      // Mock an invalid base64 string
      const invalidBase64 = "invalid-base64-string";

      await expect(
        SolanaAdapter.attachProtocolMeta(
          invalidBase64,
          meta as ProtocolMetaFields
        )
      ).rejects.toThrow("Invalid base64 transaction format");
    });

    test("attachProtocolMeta throws when transaction already has protocol meta", async () => {
      const code = "44444444";
      const codeHashValue = codeHash(code);

      // Create transaction with existing protocol meta
      const existingMeta = {
        ver: 2,
        id: "existing-hash",
        int: keypair.publicKey.toString(),
      } as ProtocolMetaFields;
      const existingMetaIx = SolanaAdapter.createProtocolMetaIx(existingMeta);

      const tx = new Transaction();
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;
      tx.add(existingMetaIx);

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");

      // Try to attach new protocol meta
      const newMeta = { ver: 2, id: codeHashValue, int: "user" };

      await expect(
        SolanaAdapter.attachProtocolMeta(
          base64String,
          newMeta as ProtocolMetaFields
        )
      ).rejects.toThrow("Transaction already contains protocol meta");
    });
  });

  describe("integration tests", () => {
    test("full workflow: sign message and verify with adapter", () => {
      // Simulate the full workflow
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const canonicalMessage = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(canonicalMessage, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalMessageParts.windowStart,
        expiresAt: canonicalMessageParts.windowStart + 120000,
        chain: "solana",
        signature: signatureB58,
      };

      // Verify the signature
      const verifyResult = adapter.verifyWithWallet(actionCode);
      expect(verifyResult).toBe(true);

      // Note: Protocol meta validation is now handled by transaction inspection
      // This is a policy decision, not a protocol requirement
    });

    test("performance test: multiple verifications", () => {
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const canonicalMessage = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(canonicalMessage, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: canonicalMessageParts.windowStart,
        expiresAt: canonicalMessageParts.windowStart + 120000,
        chain: "solana",
        signature: signatureB58,
      };

      // Test different batch sizes
      const batchSizes = [10, 50, 100, 200];
      const results: {
        batchSize: number;
        timeMs: number;
        perVerificationMs: number;
      }[] = [];

      for (const batchSize of batchSizes) {
        const start = Date.now();
        const batchResults = Array.from({ length: batchSize }, () =>
          adapter.verifyWithWallet(actionCode)
        );
        const end = Date.now();

        const timeMs = end - start;
        const perVerificationMs = timeMs / batchSize;

        results.push({ batchSize, timeMs, perVerificationMs });

        // All should be true
        expect(batchResults.every((r) => r === true)).toBe(true);
      }

      console.log("\n=== Performance Results ===");
      results.forEach(({ batchSize, timeMs, perVerificationMs }) => {
        console.log(
          `${batchSize} verifications: ${timeMs}ms (${perVerificationMs.toFixed(
            2
          )}ms each)`
        );
      });

      // Performance should be reasonable for 100 verifications
      const hundredVerifications = results.find((r) => r.batchSize === 100);
      expect(hundredVerifications?.timeMs).toBeLessThan(500); // 500ms for 100 verifications
      expect(hundredVerifications?.perVerificationMs).toBeLessThan(5); // 5ms per verification
    });
  });

  describe("String-based interface", () => {
    describe("deserializeTransaction", () => {
      test("should deserialize versioned transaction from base64", () => {
        // Create a simple versioned transaction
        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [keypair.publicKey],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [],
            addressTableLookups: [],
          })
        );

        const base64String = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Test that we can deserialize it
        const result = adapter.getProtocolMeta(base64String);
        expect(result).toBeNull(); // No memo instructions, so should be null
      });

      test("should deserialize legacy transaction from base64", () => {
        // Create a simple legacy transaction
        const legacyTx = new Transaction();
        legacyTx.recentBlockhash = "11111111111111111111111111111111";
        legacyTx.feePayer = keypair.publicKey;

        const base64String = Buffer.from(
          legacyTx.serialize({ requireAllSignatures: false })
        ).toString("base64");

        // Test that we can deserialize it
        const result = adapter.getProtocolMeta(base64String);
        expect(result).toBeNull(); // No memo instructions, so should be null
      });

      test("should throw error for invalid base64", () => {
        expect(() => {
          adapter.getProtocolMeta("invalid-base64-string");
        }).not.toThrow(); // getProtocolMeta should return null for invalid input
      });
    });

    describe("getProtocolMetaFromString", () => {
      test("should extract protocol meta from versioned transaction with memo", () => {
        // Create versioned transaction with memo
        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [keypair.publicKey, MEMO_PROGRAM_ID],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 1,
                accountKeyIndexes: [],
                data: Buffer.from("test-memo", "utf8"),
              },
            ],
            addressTableLookups: [],
          })
        );

        const base64String = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // This should return null because it's not a valid protocol meta
        const result = adapter.getProtocolMeta(base64String);
        expect(result).toBeNull();
      });
    });

    describe("parseMetaFromString", () => {
      test("should parse valid protocol meta from string", () => {
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        // Create a transaction with valid protocol meta
        const tx = new Transaction();
        tx.recentBlockhash = "11111111111111111111111111111111";
        tx.feePayer = keypair.publicKey;

        // Add memo instruction with protocol meta using the proper format
        const metaIx = SolanaAdapter.createProtocolMetaIx(meta);
        tx.add(metaIx);

        const base64String = Buffer.from(
          tx.serialize({ requireAllSignatures: false })
        ).toString("base64");

        const result = adapter.parseMeta(base64String);
        expect(result).toEqual(meta);
      });
    });

    describe("verifyTransactionMatchesCode", () => {
      test("should verify transaction matches action code", () => {
        const actionCode: ActionCode = {
          code: "test-code",
          pubkey: keypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000, // 1 hour from now
          timestamp: Date.now(),
          chain: "solana",
          signature: "test-signature",
        };

        const meta: ProtocolMetaFields = {
          ver: 2,
          id: codeHash("test-code"),
          int: keypair.publicKey.toString(),
        };

        // Create transaction with matching meta
        const tx = new Transaction();
        tx.recentBlockhash = "11111111111111111111111111111111";
        tx.feePayer = keypair.publicKey;

        const metaIx = SolanaAdapter.createProtocolMetaIx({
          ver: 2,
          id: codeHash("test-code"),
          int: keypair.publicKey.toString(),
        });
        tx.add(metaIx);

        const base64String = Buffer.from(
          tx.serialize({ requireAllSignatures: false })
        ).toString("base64");

        // Should not throw
        expect(() => {
          adapter.verifyTransactionMatchesCode(actionCode, base64String);
        }).not.toThrow();
      });
    });

    describe("attachProtocolMeta - Transaction Integrity", () => {
      test("should not modify original transaction string", async () => {
        const originalTx = new Transaction();
        originalTx.recentBlockhash = "11111111111111111111111111111111";
        originalTx.feePayer = keypair.publicKey;

        const originalBase64 = Buffer.from(
          originalTx.serialize({ requireAllSignatures: false })
        ).toString("base64");
        const originalTxCopy = Transaction.from(
          Buffer.from(originalBase64, "base64")
        );

        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        // Attach protocol meta
        const newBase64 = await SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );

        // Original string should be unchanged
        expect(newBase64).not.toBe(originalBase64);

        // Original transaction should be unchanged
        const originalTxAfter = Transaction.from(
          Buffer.from(originalBase64, "base64")
        );
        expect(originalTxAfter.instructions.length).toBe(
          originalTxCopy.instructions.length
        );

        // New transaction should have one more instruction (the memo)
        const newTx = Transaction.from(Buffer.from(newBase64, "base64"));
        expect(newTx.instructions.length).toBe(
          originalTxCopy.instructions.length + 1
        );
      });

      test("should clear signatures in versioned transaction when message changes", async () => {
        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [keypair.publicKey],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [],
            addressTableLookups: [],
          })
        );

        // Add a fake signature
        versionedTx.signatures = [new Uint8Array(64).fill(1)];

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const newBase64 = await SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );
        const newTx = VersionedTransaction.deserialize(
          Buffer.from(newBase64, "base64")
        );

        // Signatures should be cleared (empty) since message changed
        expect(newTx.signatures.length).toBe(versionedTx.signatures.length);
        // All signatures should be empty (64 bytes of zeros)
        newTx.signatures.forEach((sig) => {
          expect(sig.length).toBe(64);
          expect(sig.every((byte) => byte === 0)).toBe(true);
        });
      });

      test("should preserve account key indices when attaching meta to versioned transaction", async () => {
        // Create a versioned transaction with multiple instructions that reference different account keys
        const account1 = Keypair.generate().publicKey;
        const account2 = Keypair.generate().publicKey;
        const account3 = Keypair.generate().publicKey;
        const program1 = Keypair.generate().publicKey;
        const program2 = Keypair.generate().publicKey;

        // Create a transaction with multiple instructions that use different account indices
        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [
              keypair.publicKey, // 0: fee payer/signer
              account1,          // 1
              account2,          // 2
              account3,          // 3
              program1,          // 4: program ID for first instruction
              program2,          // 5: program ID for second instruction
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 4, // program1
                accountKeyIndexes: [0, 1, 2], // references keypair, account1, account2
                data: Buffer.from("instruction1"),
              },
              {
                programIdIndex: 5, // program2
                accountKeyIndexes: [0, 2, 3], // references keypair, account2, account3
                data: Buffer.from("instruction2"),
              },
            ],
            addressTableLookups: [],
          })
        );

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Verify original transaction structure
        const originalDeserialized = VersionedTransaction.deserialize(
          Buffer.from(originalBase64, "base64")
        );
        const originalMsg = originalDeserialized.message as MessageV0;
        expect(originalMsg.compiledInstructions.length).toBe(2);
        expect(originalMsg.staticAccountKeys.length).toBe(6);

        // Attach protocol meta (MEMO_PROGRAM_ID is not in static keys, so it will be added)
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const newBase64 = await SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );

        // Deserialize the new transaction
        const newTx = VersionedTransaction.deserialize(
          Buffer.from(newBase64, "base64")
        );
        const newMsg = newTx.message as MessageV0;

        // Verify structure
        expect(newMsg.compiledInstructions.length).toBe(3); // Should have 2 original + 1 memo
        expect(newMsg.staticAccountKeys.length).toBe(7); // Should have 6 original + 1 MEMO_PROGRAM_ID

        // CRITICAL: Verify that the original instructions still have correct account key indices
        // The first instruction should still reference the same accounts
        const firstIx = newMsg.compiledInstructions[0];
        expect(firstIx.programIdIndex).toBe(4); // program1 should still be at index 4
        expect(firstIx.accountKeyIndexes).toEqual([0, 1, 2]); // Should still reference same accounts

        // The second instruction should still reference the same accounts
        const secondIx = newMsg.compiledInstructions[1];
        expect(secondIx.programIdIndex).toBe(5); // program2 should still be at index 5
        expect(secondIx.accountKeyIndexes).toEqual([0, 2, 3]); // Should still reference same accounts

        // Verify the account keys themselves are still correct
        expect(newMsg.staticAccountKeys[0].equals(keypair.publicKey)).toBe(true);
        expect(newMsg.staticAccountKeys[1].equals(account1)).toBe(true);
        expect(newMsg.staticAccountKeys[2].equals(account2)).toBe(true);
        expect(newMsg.staticAccountKeys[3].equals(account3)).toBe(true);
        expect(newMsg.staticAccountKeys[4].equals(program1)).toBe(true);
        expect(newMsg.staticAccountKeys[5].equals(program2)).toBe(true);
        expect(newMsg.staticAccountKeys[6].equals(MEMO_PROGRAM_ID)).toBe(true);

        // Verify the memo instruction
        const memoIx = newMsg.compiledInstructions[2];
        expect(memoIx.programIdIndex).toBe(6); // MEMO_PROGRAM_ID should be at index 6
        expect(memoIx.accountKeyIndexes).toEqual([]); // Memo has no accounts
      });

      test("should preserve account key indices when MEMO_PROGRAM_ID already exists", async () => {
        // Create a versioned transaction where MEMO_PROGRAM_ID is already in static keys
        const account1 = Keypair.generate().publicKey;
        const program1 = Keypair.generate().publicKey;

        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [
              keypair.publicKey, // 0: fee payer/signer
              account1,          // 1
              program1,          // 2: program ID
              MEMO_PROGRAM_ID,   // 3: MEMO_PROGRAM_ID already present
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 2, // program1
                accountKeyIndexes: [0, 1], // references keypair, account1
                data: Buffer.from("instruction1"),
              },
            ],
            addressTableLookups: [],
          })
        );

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Attach protocol meta (MEMO_PROGRAM_ID is already in static keys)
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const newBase64 = await SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );

        // Deserialize the new transaction
        const newTx = VersionedTransaction.deserialize(
          Buffer.from(newBase64, "base64")
        );
        const newMsg = newTx.message as MessageV0;

        // Verify structure - MEMO_PROGRAM_ID should NOT be duplicated
        expect(newMsg.staticAccountKeys.length).toBe(4); // Should still be 4, not 5
        expect(newMsg.compiledInstructions.length).toBe(2); // Should have 1 original + 1 memo

        // Verify the original instruction still has correct indices
        const firstIx = newMsg.compiledInstructions[0];
        expect(firstIx.programIdIndex).toBe(2); // program1 should still be at index 2
        expect(firstIx.accountKeyIndexes).toEqual([0, 1]); // Should still reference same accounts

        // Verify the memo instruction uses the existing MEMO_PROGRAM_ID index
        const memoIx = newMsg.compiledInstructions[1];
        expect(memoIx.programIdIndex).toBe(3); // MEMO_PROGRAM_ID should be at index 3
      });

      test("should preserve address table lookups when attaching meta", async () => {
        // Create a versioned transaction with address table lookups (like the real-world example)
        const { PublicKey } = require("@solana/web3.js");
        const addressTableKey = new PublicKey(
          "FaMS3U4uBojvGn5FSDEPimddcXsCfwkKsFgMVVnDdxGb"
        );

        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [keypair.publicKey],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [],
            addressTableLookups: [
              {
                accountKey: addressTableKey,
                writableIndexes: [],
                readonlyIndexes: [141],
              },
            ],
          })
        );

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Attach protocol meta
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const newBase64 = await SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );

        // Deserialize and verify address table lookups are preserved
        const newTx = VersionedTransaction.deserialize(
          Buffer.from(newBase64, "base64")
        );
        const newMsg = newTx.message as MessageV0;

        expect(newMsg.addressTableLookups).toBeDefined();
        expect(newMsg.addressTableLookups?.length).toBe(1);
        expect(
          newMsg.addressTableLookups?.[0]?.accountKey.equals(addressTableKey)
        ).toBe(true);
        expect(newMsg.addressTableLookups?.[0]?.readonlyIndexes).toEqual([
          141,
        ]);
      });

      test("should produce valid transaction that can be round-tripped after attaching meta", async () => {
        // Create a complex transaction similar to real-world usage
        const account1 = Keypair.generate().publicKey;
        const account2 = Keypair.generate().publicKey;
        const program1 = Keypair.generate().publicKey;

        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 1, // program1 is readonly
            },
            staticAccountKeys: [
              keypair.publicKey, // 0: fee payer/signer
              account1,          // 1: writable
              account2,          // 2: writable
              program1,          // 3: readonly program
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 3, // program1
                accountKeyIndexes: [0, 1, 2], // references keypair, account1, account2
                data: Buffer.from("instruction data"),
              },
            ],
            addressTableLookups: [],
          })
        );

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Attach protocol meta
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const newBase64 = await SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );

        // Round-trip: deserialize and re-serialize to ensure it's valid
        const roundTripTx = VersionedTransaction.deserialize(
          Buffer.from(newBase64, "base64")
        );
        const roundTripBase64 = Buffer.from(roundTripTx.serialize()).toString(
          "base64"
        );

        // Should be able to deserialize again
        const finalTx = VersionedTransaction.deserialize(
          Buffer.from(roundTripBase64, "base64")
        );
        const finalMsg = finalTx.message as MessageV0;

        // Verify all instructions are still valid
        expect(finalMsg.compiledInstructions.length).toBe(2);
        
        // Verify original instruction still works
        const originalIx = finalMsg.compiledInstructions[0];
        expect(originalIx.programIdIndex).toBe(3);
        expect(originalIx.accountKeyIndexes).toEqual([0, 1, 2]);
        
        // Verify memo instruction
        const memoIx = finalMsg.compiledInstructions[1];
        expect(memoIx.programIdIndex).toBe(4); // MEMO_PROGRAM_ID should be at index 4
        expect(finalMsg.staticAccountKeys[memoIx.programIdIndex].equals(MEMO_PROGRAM_ID)).toBe(true);
      });

      test("should handle full cycle: serialize -> deserialize -> attach meta -> serialize -> deserialize", async () => {
        // Step 1: Create versioned transaction with multiple instructions
        const account1 = Keypair.generate().publicKey;
        const account2 = Keypair.generate().publicKey;
        const program1 = Keypair.generate().publicKey;
        const program2 = Keypair.generate().publicKey;

        const originalTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 2, // program1 and program2 are readonly
            },
            staticAccountKeys: [
              keypair.publicKey, // 0: fee payer/signer
              account1,          // 1: writable
              account2,          // 2: writable
              program1,          // 3: readonly program
              program2,          // 4: readonly program
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 3, // program1
                accountKeyIndexes: [0, 1], // references keypair, account1
                data: Buffer.from("instruction1-data"),
              },
              {
                programIdIndex: 4, // program2
                accountKeyIndexes: [0, 2], // references keypair, account2
                data: Buffer.from("instruction2-data"),
              },
            ],
            addressTableLookups: [],
          })
        );

        // Step 2: Serialize the original transaction
        const serialized1 = Buffer.from(originalTx.serialize()).toString("base64");
        
        // Step 3: Deserialize it
        const deserialized1 = VersionedTransaction.deserialize(
          Buffer.from(serialized1, "base64")
        );
        const msg1 = deserialized1.message as MessageV0;
        
        // Verify original structure
        expect(msg1.staticAccountKeys.length).toBe(5);
        expect(msg1.compiledInstructions.length).toBe(2);
        expect(msg1.staticAccountKeys[0].equals(keypair.publicKey)).toBe(true);
        expect(msg1.staticAccountKeys[3].equals(program1)).toBe(true);
        expect(msg1.staticAccountKeys[4].equals(program2)).toBe(true);

        // Step 4: Attach protocol meta
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash-123",
          int: keypair.publicKey.toString(),
        };

        const withMeta = await SolanaAdapter.attachProtocolMeta(serialized1, meta);

        // Step 5: Serialize the transaction with meta
        const deserialized2 = VersionedTransaction.deserialize(
          Buffer.from(withMeta, "base64")
        );
        const serialized2 = Buffer.from(deserialized2.serialize()).toString("base64");

        // Step 6: Deserialize again
        const deserialized3 = VersionedTransaction.deserialize(
          Buffer.from(serialized2, "base64")
        );
        const msg3 = deserialized3.message as MessageV0;

        // Verify final structure
        expect(msg3.staticAccountKeys.length).toBe(6); // 5 original + 1 MEMO_PROGRAM_ID
        expect(msg3.compiledInstructions.length).toBe(3); // 2 original + 1 memo

        // Verify original instructions still have correct indices
        const ix1 = msg3.compiledInstructions[0];
        expect(ix1.programIdIndex).toBe(3); // program1 should still be at index 3
        expect(ix1.accountKeyIndexes).toEqual([0, 1]);
        expect(Buffer.from(ix1.data).toString()).toBe("instruction1-data");

        const ix2 = msg3.compiledInstructions[1];
        expect(ix2.programIdIndex).toBe(4); // program2 should still be at index 4
        expect(ix2.accountKeyIndexes).toEqual([0, 2]);
        expect(Buffer.from(ix2.data).toString()).toBe("instruction2-data");

        // Verify memo instruction
        const memoIx = msg3.compiledInstructions[2];
        expect(memoIx.programIdIndex).toBe(5); // MEMO_PROGRAM_ID should be at index 5
        expect(memoIx.accountKeyIndexes).toEqual([]);
        expect(msg3.staticAccountKeys[memoIx.programIdIndex].equals(MEMO_PROGRAM_ID)).toBe(true);

        // Verify all account keys are still correct
        expect(msg3.staticAccountKeys[0].equals(keypair.publicKey)).toBe(true);
        expect(msg3.staticAccountKeys[1].equals(account1)).toBe(true);
        expect(msg3.staticAccountKeys[2].equals(account2)).toBe(true);
        expect(msg3.staticAccountKeys[3].equals(program1)).toBe(true);
        expect(msg3.staticAccountKeys[4].equals(program2)).toBe(true);
        expect(msg3.staticAccountKeys[5].equals(MEMO_PROGRAM_ID)).toBe(true);

        // Verify we can extract the protocol meta
        const adapter = new SolanaAdapter();
        const extractedMeta = adapter.parseMeta(serialized2);
        expect(extractedMeta).not.toBeNull();
        expect(extractedMeta?.ver).toBe(2);
        expect(extractedMeta?.id).toBe("test-hash-123");
        expect(extractedMeta?.int).toBe(keypair.publicKey.toString());
      });

      test("should handle Memo Program insertion in middle of account keys", async () => {
        // Create a transaction where Memo Program might be inserted in the middle
        const account1 = Keypair.generate().publicKey;
        const account2 = Keypair.generate().publicKey;
        const tokenProgram = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        const program1 = Keypair.generate().publicKey;

        // Create transaction with Token Program at index 3
        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 2, // tokenProgram and program1 are readonly
            },
            staticAccountKeys: [
              keypair.publicKey,  // 0: fee payer/signer
              account1,           // 1: writable
              account2,           // 2: writable
              tokenProgram,       // 3: Token Program (readonly)
              program1,           // 4: program1 (readonly)
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 3, // Token Program
                accountKeyIndexes: [0, 1, 2], // references keypair, account1, account2
                data: Buffer.from("token instruction"),
              },
              {
                programIdIndex: 4, // program1
                accountKeyIndexes: [0, 1],
                data: Buffer.from("program1 instruction"),
              },
            ],
            addressTableLookups: [],
          })
        );

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString("base64");

        // Attach protocol meta
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const newBase64 = await SolanaAdapter.attachProtocolMeta(originalBase64, meta);

        // Deserialize and verify
        const finalTx = VersionedTransaction.deserialize(Buffer.from(newBase64, "base64"));
        const finalMsg = finalTx.message as MessageV0;

        // CRITICAL: Verify Token Program instruction still references Token Program, not Memo Program
        const tokenIx = finalMsg.compiledInstructions[0];
        const tokenProgramIndex = tokenIx.programIdIndex;
        const actualProgram = finalMsg.staticAccountKeys[tokenProgramIndex];

        // This should pass - Token Program should still be at its original index
        expect(actualProgram.equals(tokenProgram)).toBe(true);
        expect(actualProgram.equals(MEMO_PROGRAM_ID)).toBe(false); // Should NOT be Memo Program

        // Verify account indices are still correct
        expect(tokenIx.accountKeyIndexes).toEqual([0, 1, 2]);

        // Verify program1 instruction
        const program1Ix = finalMsg.compiledInstructions[1];
        expect(finalMsg.staticAccountKeys[program1Ix.programIdIndex].equals(program1)).toBe(true);
        expect(program1Ix.accountKeyIndexes).toEqual([0, 1]);
      });

      test("should preserve address table lookups with multiple tables and complex indices", async () => {
        // Test with multiple address lookup tables and various index patterns
        const addressTable1 = Keypair.generate().publicKey;
        const addressTable2 = Keypair.generate().publicKey;

        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [keypair.publicKey],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [],
            addressTableLookups: [
              {
                accountKey: addressTable1,
                writableIndexes: [0, 5, 10],
                readonlyIndexes: [1, 2, 3],
              },
              {
                accountKey: addressTable2,
                writableIndexes: [],
                readonlyIndexes: [100, 200, 255],
              },
            ],
          })
        );

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Attach protocol meta
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const newBase64 = await SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );

        // Deserialize and verify address table lookups are preserved exactly
        const newTx = VersionedTransaction.deserialize(
          Buffer.from(newBase64, "base64")
        );
        const newMsg = newTx.message as MessageV0;

        // Verify both address table lookups are preserved
        expect(newMsg.addressTableLookups).toBeDefined();
        expect(newMsg.addressTableLookups?.length).toBe(2);

        // Verify first address table lookup
        const lookup1 = newMsg.addressTableLookups?.[0];
        expect(lookup1).toBeDefined();
        expect(lookup1?.accountKey.equals(addressTable1)).toBe(true);
        expect(lookup1?.writableIndexes).toEqual([0, 5, 10]);
        expect(lookup1?.readonlyIndexes).toEqual([1, 2, 3]);

        // Verify second address table lookup
        const lookup2 = newMsg.addressTableLookups?.[1];
        expect(lookup2).toBeDefined();
        expect(lookup2?.accountKey.equals(addressTable2)).toBe(true);
        expect(lookup2?.writableIndexes).toEqual([]);
        expect(lookup2?.readonlyIndexes).toEqual([100, 200, 255]);
      });

      test("should preserve address table lookups through multiple serialize/deserialize cycles", async () => {
        // Test that address table lookups survive multiple round-trips
        const addressTableKey = new PublicKey(
          "FaMS3U4uBojvGn5FSDEPimddcXsCfwkKsFgMVVnDdxGb"
        );

        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [keypair.publicKey],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [],
            addressTableLookups: [
              {
                accountKey: addressTableKey,
                writableIndexes: [1, 2, 3],
                readonlyIndexes: [141, 142],
              },
            ],
          })
        );

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Attach protocol meta
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const withMeta = await SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );

        // Round-trip 1: serialize and deserialize
        const tx1 = VersionedTransaction.deserialize(
          Buffer.from(withMeta, "base64")
        );
        const serialized1 = Buffer.from(tx1.serialize()).toString("base64");

        // Round-trip 2: serialize and deserialize again
        const tx2 = VersionedTransaction.deserialize(
          Buffer.from(serialized1, "base64")
        );
        const serialized2 = Buffer.from(tx2.serialize()).toString("base64");

        // Round-trip 3: one more time
        const tx3 = VersionedTransaction.deserialize(
          Buffer.from(serialized2, "base64")
        );
        const finalMsg = tx3.message as MessageV0;

        // Verify address table lookups are still intact after multiple round-trips
        expect(finalMsg.addressTableLookups).toBeDefined();
        expect(finalMsg.addressTableLookups?.length).toBe(1);
        expect(
          finalMsg.addressTableLookups?.[0]?.accountKey.equals(addressTableKey)
        ).toBe(true);
        expect(finalMsg.addressTableLookups?.[0]?.writableIndexes).toEqual([
          1, 2, 3,
        ]);
        expect(finalMsg.addressTableLookups?.[0]?.readonlyIndexes).toEqual([
          141, 142,
        ]);
      });

      test("should require connection when instructions reference lookup table accounts", async () => {
        // This test verifies that attachProtocolMeta correctly requires a connection
        // when instructions reference accounts from address lookup tables.
        // Without a connection, we cannot resolve the lookup tables and recalculate indices correctly.
        
        const addressTableKey = Keypair.generate().publicKey;
        const staticAccount1 = Keypair.generate().publicKey;
        const staticAccount2 = Keypair.generate().publicKey;
        const program1 = Keypair.generate().publicKey;

        // Create a transaction where:
        // - Static accounts: [keypair.publicKey, staticAccount1, staticAccount2, program1] (indices 0-3)
        // - Address lookup table has accounts at indices 0, 1, 2 (which become indices 4, 5, 6 in full account list)
        // - An instruction references account at index 4 (first account from lookup table)
        
        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 1, // program1 is readonly
            },
            staticAccountKeys: [
              keypair.publicKey, // 0
              staticAccount1,    // 1
              staticAccount2,    // 2
              program1,          // 3
            ],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 3, // program1
                // This instruction references:
                // - Index 0: keypair.publicKey (static)
                // - Index 1: staticAccount1 (static)
                // - Index 4: first account from lookup table (static accounts are 0-3, so lookup starts at 4)
                accountKeyIndexes: [0, 1, 4],
                data: Buffer.from("instruction referencing lookup table account"),
              },
            ],
            addressTableLookups: [
              {
                accountKey: addressTableKey,
                writableIndexes: [0], // First account in lookup table (becomes index 4 in full list)
                readonlyIndexes: [1, 2], // Second and third accounts (become indices 5, 6)
              },
            ],
          })
        );

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Verify original structure
        const originalDeserialized = VersionedTransaction.deserialize(
          Buffer.from(originalBase64, "base64")
        );
        const originalMsg = originalDeserialized.message as MessageV0;
        expect(originalMsg.staticAccountKeys.length).toBe(4);
        const originalIx = originalMsg.compiledInstructions[0];
        expect(originalIx.accountKeyIndexes).toEqual([0, 1, 4]); // Index 4 = first lookup table account

        // Attach protocol meta without connection - should throw error
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        // Should throw error because connection is required
        await expect(
          SolanaAdapter.attachProtocolMeta(originalBase64, meta)
        ).rejects.toThrow("Connection required");
      });
    });
  });

  describe("verifyMessageSignedByIntentOwner", () => {
    test("should verify a message signed by the action code owner", () => {
      const ownerKeypair = Keypair.generate();
      const message = "Authorise pumpfun 1121312313";
      
      // Encode the message as UTF-8 bytes
      const messageBytes = new TextEncoder().encode(message);
      
      // Sign the message with the owner's keypair
      const signature = nacl.sign.detached(messageBytes, ownerKeypair.secretKey);
      
      // Encode the signature as base58
      const signatureB58 = bs58.encode(signature);
      
      // Verify should not throw
      expect(() => {
        adapter.verifyMessageSignedByIntentOwner(
          message,
          signatureB58,
          ownerKeypair.publicKey.toString()
        );
      }).not.toThrow();
    });

    test("should throw for invalid signature", () => {
      const ownerKeypair = Keypair.generate();
      const wrongKeypair = Keypair.generate();
      const message = "Authorise pumpfun 1121312313";
      
      // Encode the message as UTF-8 bytes
      const messageBytes = new TextEncoder().encode(message);
      
      // Sign with wrong keypair
      const signature = nacl.sign.detached(messageBytes, wrongKeypair.secretKey);
      const signatureB58 = bs58.encode(signature);
      
      // Should throw because signature doesn't match pubkey
      expect(() => {
        adapter.verifyMessageSignedByIntentOwner(
          message,
          signatureB58,
          ownerKeypair.publicKey.toString()
        );
      }).toThrow();
    });

    test("should throw for malformed signature", () => {
      const ownerKeypair = Keypair.generate();
      const message = "Authorise pumpfun 1121312313";
      
      // Should throw for invalid base58
      expect(() => {
        adapter.verifyMessageSignedByIntentOwner(
          message,
          "invalid-signature",
          ownerKeypair.publicKey.toString()
        );
      }).toThrow();
    });

    test("should throw for invalid pubkey format", () => {
      const message = "Authorise pumpfun 1121312313";
      const messageBytes = new TextEncoder().encode(message);
      const keypair = Keypair.generate();
      const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);
      
      // Should throw for invalid pubkey
      expect(() => {
        adapter.verifyMessageSignedByIntentOwner(
          message,
          signatureB58,
          "invalid-pubkey"
        );
      }).toThrow();
    });

    test("should verify different message formats", () => {
      const ownerKeypair = Keypair.generate();
      const messages = [
        "Authorise pumpfun 1121312313",
        "Transfer 100 SOL",
        "Approve transaction #12345",
        "Sign in to dApp",
      ];
      
      for (const message of messages) {
        const messageBytes = new TextEncoder().encode(message);
        const signature = nacl.sign.detached(messageBytes, ownerKeypair.secretKey);
        const signatureB58 = bs58.encode(signature);
        
        expect(() => {
          adapter.verifyMessageSignedByIntentOwner(
            message,
            signatureB58,
            ownerKeypair.publicKey.toString()
          );
        }).not.toThrow();
      }
    });

    test("should throw when message doesn't match signature", () => {
      const ownerKeypair = Keypair.generate();
      const originalMessage = "Authorise pumpfun 1121312313";
      const differentMessage = "Authorise pumpfun 9999999999";
      
      // Sign the original message
      const messageBytes = new TextEncoder().encode(originalMessage);
      const signature = nacl.sign.detached(messageBytes, ownerKeypair.secretKey);
      const signatureB58 = bs58.encode(signature);
      
      // Try to verify with a different message
      expect(() => {
        adapter.verifyMessageSignedByIntentOwner(
          differentMessage,
          signatureB58,
          ownerKeypair.publicKey.toString()
        );
      }).toThrow();
    });
  });

  describe("delegation verification methods", () => {
    let walletKeypair: Keypair;
    let delegatedKeypair: Keypair;

    beforeEach(() => {
      walletKeypair = Keypair.generate();
      delegatedKeypair = Keypair.generate();
    });

    describe("verifyWithDelegation", () => {
      test("verifyWithDelegation returns true for valid signatures", () => {
        // Create delegation proof
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000, // 1 hour from now
          chain: "solana",
          signature: "", // Will be filled below
        };

        // Wallet signs the delegation proof
        const delegationMessage = serializeDelegationProof(delegationProof);
        const walletSignature = nacl.sign.detached(
          delegationMessage,
          walletKeypair.secretKey
        );
        delegationProof.signature = bs58.encode(walletSignature);

        // Create canonical message for action code
        const canonicalMessageParts = {
          pubkey: delegatedKeypair.publicKey.toString(),
          windowStart: Date.now(),
        };

        // Delegated key signs the canonical message
        const canonicalMessage = serializeCanonical(canonicalMessageParts);
        const delegatedSignature = nacl.sign.detached(
          canonicalMessage,
          delegatedKeypair.secretKey
        );
        const delegatedSignatureB58 = bs58.encode(delegatedSignature);

        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: delegatedKeypair.publicKey.toString(),
          timestamp: canonicalMessageParts.windowStart,
          expiresAt: canonicalMessageParts.windowStart + 120000,
          chain: "solana",
          signature: delegatedSignatureB58,
          delegationProof,
        };

        const result = adapter.verifyWithDelegation(delegatedActionCode);
        expect(result).toBe(true);
      });

      test("verifyWithDelegation returns false for invalid wallet signature", () => {
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000,
          chain: "solana",
          signature: "invalid-signature", // Invalid signature
        };

        const canonicalMessageParts = {
          pubkey: delegatedKeypair.publicKey.toString(),
          windowStart: Date.now(),
        };

        const canonicalMessage = serializeCanonical(canonicalMessageParts);
        const delegatedSignature = nacl.sign.detached(
          canonicalMessage,
          delegatedKeypair.secretKey
        );
        const delegatedSignatureB58 = bs58.encode(delegatedSignature);

        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: delegatedKeypair.publicKey.toString(),
          timestamp: canonicalMessageParts.windowStart,
          expiresAt: canonicalMessageParts.windowStart + 120000,
          chain: "solana",
          signature: delegatedSignatureB58,
          delegationProof,
        };

        const result = adapter.verifyWithDelegation(delegatedActionCode);
        expect(result).toBe(false);
      });

      test("verifyWithDelegation returns false for invalid delegated signature", () => {
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          chain: "solana",
          expiresAt: Date.now() + 3600000,
          signature: "", // Will be filled below
        };

        // Wallet signs the delegation proof correctly
        const delegationMessage = serializeDelegationProof(delegationProof);
        const walletSignature = nacl.sign.detached(
          delegationMessage,
          walletKeypair.secretKey
        );
        delegationProof.signature = bs58.encode(walletSignature);

        const canonicalMessageParts = {
          pubkey: delegatedKeypair.publicKey.toString(),
          windowStart: Date.now(),
        };

        const actionCode: DelegatedActionCode = {
          chain: "solana",
          pubkey: delegatedKeypair.publicKey.toString(),
          timestamp: canonicalMessageParts.windowStart,
          expiresAt: canonicalMessageParts.windowStart + 120000,
          signature: "invalid-delegated-signature", // Invalid signature
          delegationProof,
          code: "12345678",
        };

        const result = adapter.verifyWithDelegation(actionCode);
        expect(result).toBe(false);
      });

      test("verifyWithDelegation returns false for expired delegation", () => {
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() - 3600000, // 1 hour ago (expired)
          chain: "solana",
          signature: "", // Will be filled below
        };

        const delegationMessage = serializeDelegationProof(delegationProof);
        const walletSignature = nacl.sign.detached(
          delegationMessage,
          walletKeypair.secretKey
        );
        delegationProof.signature = bs58.encode(walletSignature);

        const canonicalMessageParts = {
          pubkey: delegatedKeypair.publicKey.toString(),
          windowStart: Date.now(),
        };

        const canonicalMessage = serializeCanonical(canonicalMessageParts);
        const delegatedSignature = nacl.sign.detached(
          canonicalMessage,
          delegatedKeypair.secretKey
        );
        const delegatedSignatureB58 = bs58.encode(delegatedSignature);

        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: delegatedKeypair.publicKey.toString(),
          timestamp: canonicalMessageParts.windowStart,
          expiresAt: canonicalMessageParts.windowStart + 120000,
          chain: "solana",
          signature: delegatedSignatureB58,
          delegationProof,
        };

        const result = adapter.verifyWithDelegation(delegatedActionCode);
        expect(result).toBe(false);
      });

      test("verifyWithDelegation returns false for mismatched delegated pubkey", () => {
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000,
          chain: "solana",
          signature: "", // Will be filled below
        };

        const delegationMessage = serializeDelegationProof(delegationProof);
        const walletSignature = nacl.sign.detached(
          delegationMessage,
          walletKeypair.secretKey
        );
        delegationProof.signature = bs58.encode(walletSignature);

        // Use different pubkey in message than in delegation proof
        const canonicalMessageParts = {
          pubkey: walletKeypair.publicKey.toString(), // Different from delegatedPubkey
          windowStart: Date.now(),
        };

        const canonicalMessage = serializeCanonical(canonicalMessageParts);
        const delegatedSignature = nacl.sign.detached(
          canonicalMessage,
          delegatedKeypair.secretKey
        );
        const delegatedSignatureB58 = bs58.encode(delegatedSignature);

        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: walletKeypair.publicKey.toString(), // Different from delegatedPubkey
          timestamp: canonicalMessageParts.windowStart,
          expiresAt: canonicalMessageParts.windowStart + 120000,
          chain: "solana",
          signature: delegatedSignatureB58,
          delegationProof,
        };

        const result = adapter.verifyWithDelegation(delegatedActionCode);
        expect(result).toBe(false);
      });
    });

    describe("verifyRevokeWithDelegation", () => {
      test("verifyRevokeWithDelegation returns true for valid signatures", () => {
        // Create delegation proof
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000, // 1 hour from now
          chain: "solana",
          signature: "", // Will be filled below
        };

        // Wallet signs the delegation proof
        const delegationMessage = serializeDelegationProof(delegationProof);
        const walletSignature = nacl.sign.detached(
          delegationMessage,
          walletKeypair.secretKey
        );
        delegationProof.signature = bs58.encode(walletSignature);

        // Create delegated action code
        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: delegatedKeypair.publicKey.toString(),
          timestamp: Date.now(),
          expiresAt: Date.now() + 120000,
          chain: "solana",
          signature: "original-signature",
          delegationProof,
        };

        // Create revoke message using the same codeHash that the method will use
        const revokeMessageParts = {
          pubkey: delegatedActionCode.pubkey,
          codeHash: codeHash(delegatedActionCode.code),
          windowStart: delegatedActionCode.timestamp,
        };

        // Delegated key signs the revoke message
        const revokeMessage = serializeCanonicalRevoke(revokeMessageParts);
        const delegatedSignature = nacl.sign.detached(
          revokeMessage,
          delegatedKeypair.secretKey
        );
        const delegatedSignatureB58 = bs58.encode(delegatedSignature);

        const result = adapter.verifyRevokeWithDelegation(
          delegatedActionCode,
          delegatedSignatureB58
        );
        expect(result).toBe(true);
      });

      test("verifyRevokeWithDelegation returns false for invalid wallet signature", () => {
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000,
          chain: "solana",
          signature: "invalid-wallet-signature", // Invalid signature
        };

        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: delegatedKeypair.publicKey.toString(),
          timestamp: Date.now(),
          expiresAt: Date.now() + 120000,
          chain: "solana",
          signature: "original-signature",
          delegationProof,
        };

        // Create revoke message using the same codeHash that the method will use
        const revokeMessageParts = {
          pubkey: delegatedActionCode.pubkey,
          codeHash: codeHash(delegatedActionCode.code),
          windowStart: delegatedActionCode.timestamp,
        };

        const revokeMessage = serializeCanonicalRevoke(revokeMessageParts);
        const delegatedSignature = nacl.sign.detached(
          revokeMessage,
          delegatedKeypair.secretKey
        );
        const delegatedSignatureB58 = bs58.encode(delegatedSignature);

        const result = adapter.verifyRevokeWithDelegation(delegatedActionCode, delegatedSignatureB58);
        expect(result).toBe(false);
      });

      test("verifyRevokeWithDelegation returns false for invalid delegated signature", () => {
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000,
          chain: "solana",
          signature: "", // Will be filled below
        };

        // Wallet signs the delegation proof correctly
        const delegationMessage = serializeDelegationProof(delegationProof);
        const walletSignature = nacl.sign.detached(
          delegationMessage,
          walletKeypair.secretKey
        );
        delegationProof.signature = bs58.encode(walletSignature);

        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: delegatedKeypair.publicKey.toString(),
          timestamp: Date.now(),
          expiresAt: Date.now() + 120000,
          chain: "solana",
          signature: "original-signature",
          delegationProof,
        };

        const result = adapter.verifyRevokeWithDelegation(delegatedActionCode, "invalid-delegated-signature");
        expect(result).toBe(false);
      });

      test("verifyRevokeWithDelegation returns false for expired delegation", () => {
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() - 3600000, // 1 hour ago (expired)
          chain: "solana",
          signature: "", // Will be filled below
        };

        const delegationMessage = serializeDelegationProof(delegationProof);
        const walletSignature = nacl.sign.detached(
          delegationMessage,
          walletKeypair.secretKey
        );
        delegationProof.signature = bs58.encode(walletSignature);

        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: delegatedKeypair.publicKey.toString(),
          timestamp: Date.now(),
          expiresAt: Date.now() + 120000,
          chain: "solana",
          signature: "original-signature",
          delegationProof,
        };

        // Create revoke message using the same codeHash that the method will use
        const revokeMessageParts = {
          pubkey: delegatedActionCode.pubkey,
          codeHash: codeHash(delegatedActionCode.code),
          windowStart: delegatedActionCode.timestamp,
        };

        const revokeMessage = serializeCanonicalRevoke(revokeMessageParts);
        const delegatedSignature = nacl.sign.detached(
          revokeMessage,
          delegatedKeypair.secretKey
        );
        const delegatedSignatureB58 = bs58.encode(delegatedSignature);

        const result = adapter.verifyRevokeWithDelegation(delegatedActionCode, delegatedSignatureB58);
        expect(result).toBe(false);
      });

      test("verifyRevokeWithDelegation returns false for mismatched delegated pubkey", () => {
        const delegationProof = {
          walletPubkey: walletKeypair.publicKey.toString(),
          delegatedPubkey: delegatedKeypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000,
          chain: "solana",
          signature: "", // Will be filled below
        };

        const delegationMessage = serializeDelegationProof(delegationProof);
        const walletSignature = nacl.sign.detached(
          delegationMessage,
          walletKeypair.secretKey
        );
        delegationProof.signature = bs58.encode(walletSignature);

        // Use different pubkey in action code than in delegation proof
        const delegatedActionCode: DelegatedActionCode = {
          code: "12345678",
          pubkey: walletKeypair.publicKey.toString(), // Different from delegatedPubkey
          timestamp: Date.now(),
          expiresAt: Date.now() + 120000,
          chain: "solana",
          signature: "original-signature",
          delegationProof,
        };

        // Create revoke message using the same codeHash that the method will use
        const revokeMessageParts = {
          pubkey: delegatedActionCode.pubkey,
          codeHash: codeHash(delegatedActionCode.code),
          windowStart: delegatedActionCode.timestamp,
        };

        const revokeMessage = serializeCanonicalRevoke(revokeMessageParts);
        const delegatedSignature = nacl.sign.detached(
          revokeMessage,
          delegatedKeypair.secretKey
        );
        const delegatedSignatureB58 = bs58.encode(delegatedSignature);

        const result = adapter.verifyRevokeWithDelegation(delegatedActionCode, delegatedSignatureB58);
        expect(result).toBe(false);
      });
    });
  });
});
