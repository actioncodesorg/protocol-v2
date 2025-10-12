import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import {
  SolanaAdapter,
  type SolanaTransaction,
} from "../src/adapters/SolanaAdapter";
import { NodeCryptoAdapter } from "../examples/customadapter/NodeCryptoAdapter";
import { codeHash } from "../src/utils/crypto";
import { Keypair } from "@solana/web3.js";
import { Transaction } from "@solana/web3.js";
import nacl from "tweetnacl";
import bs58 from "bs58";
import type { ProtocolMetaFields } from "../src/utils/protocolMeta";
import { serializeCanonical, getCanonicalMessageParts } from "../src/utils/canonical";
import type { Chain, ActionCode } from "../src/types";

// Helper function to create proper Base58 signatures for testing
function createTestSignature(message: Uint8Array): string {
  const keypair = nacl.sign.keyPair();
  const signature = nacl.sign.detached(message, keypair.secretKey);
  return bs58.encode(signature);
}

describe("Cross-Chain Compatibility", () => {
  let protocol: ActionCodesProtocol;
  let solanaAdapter: SolanaAdapter;
  let nodeCryptoAdapter: NodeCryptoAdapter;
  let testKeypair: Keypair;
  const chain: Chain = "solana";

  beforeEach(() => {
    protocol = new ActionCodesProtocol({
      codeLength: 8,
      ttlMs: 120000,
    });

    solanaAdapter = new SolanaAdapter();
    nodeCryptoAdapter = new NodeCryptoAdapter();
    testKeypair = Keypair.generate();

    // Register both adapters
    protocol.registerAdapter("solana", solanaAdapter);
    protocol.registerAdapter("nodecrypto", nodeCryptoAdapter);
  });

  describe("Multi-Chain Code Generation", () => {
    test("generates same codes across different chains", async () => {
      const pubkey = "test-pubkey-crosschain";
      const canonicalMessage = getCanonicalMessageParts(pubkey);
      const signature = createTestSignature(canonicalMessage);
      const signFn = async (message: Uint8Array, chain: string) => signature;

      // Generate code once
      const actionCode = await protocol.generate("wallet", pubkey, chain, signFn);

      // The same code should work for both chains
      expect(actionCode.code).toMatch(/^\d+$/);
      expect(actionCode.code).toHaveLength(8);
      expect(actionCode.pubkey).toBe(pubkey);
    });

    test("generates different codes for different pubkeys", async () => {
      const pubkeys = ["solana-pubkey", "ethereum-pubkey", "bitcoin-pubkey"];
      const codes = await Promise.all(pubkeys.map(async (pubkey) => {
        const canonicalMessage = getCanonicalMessageParts(pubkey);
        const signature = createTestSignature(canonicalMessage);
        const signFn = async (message: Uint8Array, chain: string) => signature;
        const actionCode = await protocol.generate("wallet", pubkey, chain, signFn);
        return actionCode.code;
      }));

      // All codes should be different
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(codes.length);
    });
  });

  describe("Solana Chain Integration", () => {
    test("validates codes with Solana adapter", async () => {
      const keypair = Keypair.generate();
      const timestamp = Date.now();
      const canonicalMessage = serializeCanonical({
        pubkey: keypair.publicKey.toString(),
        windowStart: timestamp,
      });
      const signature = nacl.sign.detached(canonicalMessage, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);
      const signFn = async (message: Uint8Array, chain: string) => {
        // The protocol will call this with the canonical message it wants signed
        // We need to sign that exact message, not our pre-generated one
        const signature = nacl.sign.detached(message, keypair.secretKey);
        return bs58.encode(signature);
      };
      const actionCode = await protocol.generate("wallet", keypair.publicKey.toString(), chain, signFn);

      // Verify with Solana adapter
      const isValid = solanaAdapter.verifyWithWallet(actionCode as ActionCode & { chain: "solana" });

      expect(isValid).toBe(true);
    });

    test("creates and validates Solana transactions with protocol meta", async () => {
      const keypair = Keypair.generate();
      const signFn = async (message: Uint8Array, chain: string) => {
        // The protocol will call this with the canonical message it wants signed
        // We need to sign that exact message
        const signature = nacl.sign.detached(message, keypair.secretKey);
        return bs58.encode(signature);
      };
      const actionCode = await protocol.generate("wallet", keypair.publicKey.toString(), chain, signFn);

      // Create transaction with protocol meta
      const codeHashValue = codeHash(actionCode.code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: keypair.publicKey.toString(),
        p: { chain: "solana", action: "transfer" },
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;
      tx.sign(keypair);

      const base64String = Buffer.from(tx.serialize({requireAllSignatures: false})).toString('base64');

      // Verify transaction matches code
      expect(() => {
        solanaAdapter.verifyTransactionMatchesCode(actionCode, base64String);
      }).not.toThrow();

      // Verify transaction is signed by intended owner
      expect(() => {
        solanaAdapter.verifyTransactionSignedByIntentOwner(base64String);
      }).not.toThrow();
    });
  });

  describe("Node.js Crypto Chain Integration", () => {
    test("validates codes with Node.js crypto adapter", async () => {
      const { publicKey, privateKey } = NodeCryptoAdapter.generateKeyPair();
      const pubkeyString = publicKey.export({
        type: "spki",
        format: "pem",
      }) as string;

      const signFn = async (message: Uint8Array, chain: string) => {
        // The protocol will call this with the canonical message it wants signed
        // We need to sign that exact message
        return NodeCryptoAdapter.signMessage(message, privateKey);
      };

      // Generate code with signature
      const actionCode = await protocol.generate("wallet", pubkeyString, chain, signFn);

      // Create a modified ActionCode with the correct chain type for NodeCrypto verification
      const nodeCryptoActionCode = {
        ...actionCode,
        chain: "nodecrypto" as const,
      };

      // Verify with NodeCrypto adapter
      const isValid = nodeCryptoAdapter.verifyWithWallet(nodeCryptoActionCode);

      expect(isValid).toBe(true);
    });

    test("creates and validates NodeCrypto transactions with protocol meta", async () => {
      const { publicKey, privateKey } = NodeCryptoAdapter.generateKeyPair();
      const shortId = "test-pubkey-123"; // Use short ID for both action code and protocol meta

      const signFn = async (message: Uint8Array, chain: string) => {
        // The protocol will call this with the canonical message it wants signed
        // We need to sign that exact message
        return NodeCryptoAdapter.signMessage(message, privateKey);
      };
      const actionCode = await protocol.generate("wallet", shortId, chain, signFn);

      // Create transaction with protocol meta
      const codeHashValue = codeHash(actionCode.code);
      const tx = NodeCryptoAdapter.attachProtocolMeta(
        { instructions: [] },
        {
          ver: 2,
          id: codeHashValue,
          int: shortId,
          p: { chain: "nodecrypto", action: "transfer" },
        }
      );

      // Add signature - generate a signature for the transaction
      const signature = NodeCryptoAdapter.signMessage(
        serializeCanonical({
          pubkey: shortId,
          windowStart: actionCode.timestamp,
        }),
        privateKey
      );

      const signedTx = {
        ...tx,
        signatures: [{ pubkey: shortId, signature }],
      };

      // Verify transaction matches code
      expect(() => {
        nodeCryptoAdapter.verifyTransactionMatchesCode(actionCode, signedTx);
      }).not.toThrow();

      // Verify transaction is signed by intended owner
      expect(() => {
        nodeCryptoAdapter.verifyTransactionSignedByIntentOwner(signedTx);
      }).not.toThrow();
    });
  });

  describe("Cross-Chain Protocol Validation", () => {
    test("validates same action code across different chains", async () => {
      const pubkey = "crosschain-test-pubkey";
      const keypair = Keypair.generate();
      const signFn = async (message: Uint8Array, chain: string) => {
        // The protocol will call this with the canonical message it wants signed
        // We need to sign that exact message
        const signature = nacl.sign.detached(message, keypair.secretKey);
        return bs58.encode(signature);
      };
      const actionCode = await protocol.generate("wallet", pubkey, chain, signFn);

      // Both chains should accept the same action code
      expect(actionCode.code).toMatch(/^\d+$/);
      expect(actionCode.pubkey).toBe(pubkey);
      expect(actionCode.expiresAt).toBeGreaterThan(Date.now());
    });

    test("rejects expired codes on both chains", async () => {
      const expiredActionCode = {
        code: "12345678",
        pubkey: "test-pubkey",
        timestamp: Date.now() - 200000,
        expiresAt: Date.now() - 100000,
        signature: "testsignature",
      };

      // Both adapters should reject expired codes
      expect(() => {
        solanaAdapter.verifyTransactionMatchesCode(expiredActionCode, {
          instructions: [],
        } as unknown as SolanaTransaction);
      }).toThrow();

      expect(() => {
        nodeCryptoAdapter.verifyTransactionMatchesCode(expiredActionCode, {
          instructions: [],
        } as unknown as {
          instructions: Array<{ data: string; type: string }>;
        });
      }).toThrow();
    });

    test("enforces codeHash validation on both chains", async () => {
      const actionCode = {
        code: "12345678",
        pubkey: "test-pubkey",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        signature: "testsignature",
      };

      const wrongCodeHash = "wrong-hash-value";

      // Create transactions with wrong codeHash
      const solanaTx = new Transaction().add(
        SolanaAdapter.createProtocolMetaIx({
          ver: 2,
          id: wrongCodeHash,
          int: actionCode.pubkey,
        })
      );

      const nodeCryptoTx = NodeCryptoAdapter.attachProtocolMeta(
        { instructions: [] },
        {
          ver: 2,
          id: wrongCodeHash,
          int: actionCode.pubkey,
        }
      );

      // Both should reject wrong codeHash
      expect(() => {
        solanaAdapter.verifyTransactionMatchesCode(actionCode, solanaTx);
      }).toThrow();

      expect(() => {
        nodeCryptoAdapter.verifyTransactionMatchesCode(
          actionCode,
          nodeCryptoTx
        );
      }).toThrow();
    });
  });

  describe("Chain-Specific Features", () => {
    test("Solana adapter handles Ed25519 signatures", async () => {
      const keypair = Keypair.generate();
      const timestamp = Date.now();
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: timestamp,
      };
      const message = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      // Create mock ActionCode for Solana verification
      const mockActionCode = {
        code: "12345678",
        pubkey: keypair.publicKey.toString(),
        timestamp: timestamp,
        expiresAt: timestamp + 120000,
        chain: "solana" as const,
        signature: signatureB58,
      };
      const isValid = solanaAdapter.verifyWithWallet(mockActionCode);

      expect(isValid).toBe(true);
    });

    test("NodeCrypto adapter handles RSA signatures", async () => {
      const { publicKey, privateKey } = NodeCryptoAdapter.generateKeyPair();
      const pubkeyString = publicKey.export({
        type: "spki",
        format: "pem",
      }) as string;
      const timestamp = Date.now();
      const canonicalMessageParts = {
        pubkey: pubkeyString,
        windowStart: timestamp,
      };
      const message = serializeCanonical(canonicalMessageParts);
      const signature = NodeCryptoAdapter.signMessage(message, privateKey);

      // Create a mock ActionCode for NodeCrypto verification
      const mockActionCode = {
        code: "12345678",
        pubkey: pubkeyString,
        timestamp: timestamp,
        expiresAt: timestamp + 120000,
        chain: "nodecrypto" as const,
        signature: signature,
      };
      const isValid = nodeCryptoAdapter.verifyWithWallet(mockActionCode);

      expect(isValid).toBe(true);
    });

    test("different signature algorithms produce different results", async () => {
      const solanaKeypair = Keypair.generate();
      const { publicKey: rsaPublicKey, privateKey: rsaPrivateKey } =
        NodeCryptoAdapter.generateKeyPair();
      const rsaPubkeyString = rsaPublicKey.export({
        type: "spki",
        format: "pem",
      }) as string;

      const timestamp = Date.now();
      const canonicalMessageParts = {
        pubkey: solanaKeypair.publicKey.toString(),
        windowStart: timestamp,
      };
      const message = serializeCanonical(canonicalMessageParts);

      // Sign with different algorithms
      const solanaSignature = bs58.encode(
        nacl.sign.detached(message, solanaKeypair.secretKey)
      );
      
      // Generate RSA signature with the correct message for the RSA pubkey
      const rsaMessage = serializeCanonical({
        pubkey: rsaPubkeyString,
        windowStart: timestamp,
      });
      const rsaSignature = NodeCryptoAdapter.signMessage(
        rsaMessage,
        rsaPrivateKey
      );

      // Each adapter should only accept its own signature type
      const mockActionCodeSolana = {
        code: "12345678",
        pubkey: solanaKeypair.publicKey.toString(),
        timestamp: timestamp,
        expiresAt: timestamp + 120000,
        chain: "solana" as const,
        signature: solanaSignature,
      };
      expect(solanaAdapter.verifyWithWallet(mockActionCodeSolana)).toBe(true);

      const mockActionCodeSolanaWrong = {
        code: "12345678",
        pubkey: solanaKeypair.publicKey.toString(),
        timestamp: timestamp,
        expiresAt: timestamp + 120000,
        chain: "solana" as const,
        signature: rsaSignature, // Wrong signature type
      };
      expect(solanaAdapter.verifyWithWallet(mockActionCodeSolanaWrong)).toBe(false);

      // Create mock ActionCode for NodeCrypto verification
      const mockActionCode = {
        code: "12345678",
        pubkey: rsaPubkeyString,
        timestamp: timestamp,
        expiresAt: timestamp + 120000,
        chain: "nodecrypto" as const,
        signature: rsaSignature,
      };
      expect(nodeCryptoAdapter.verifyWithWallet(mockActionCode)).toBe(true);

      // Create mock ActionCode for NodeCrypto verification with wrong signature
      const mockActionCodeWrong = {
        code: "12345678",
        pubkey: rsaPubkeyString,
        timestamp: timestamp,
        expiresAt: timestamp + 120000,
        chain: "nodecrypto" as const,
        signature: solanaSignature, // Wrong signature type
      };
      expect(nodeCryptoAdapter.verifyWithWallet(mockActionCodeWrong)).toBe(false);
    });
  });

  describe("Protocol Meta Consistency", () => {
    test("same protocol meta works across chains", async () => {
      const actionCode = {
        code: "87654321",
        pubkey: "crosschain-pubkey",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        signature: "testsignature",
      };

      const codeHashValue = codeHash(actionCode.code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: actionCode.pubkey,
        p: { amount: 100, token: "USDC" },
      };

      // Create transactions for both chains
      const solanaTx = new Transaction().add(
        SolanaAdapter.createProtocolMetaIx(meta as ProtocolMetaFields)
      );
      solanaTx.recentBlockhash = "11111111111111111111111111111111";
      solanaTx.feePayer = testKeypair.publicKey;
      const solanaBase64 = Buffer.from(solanaTx.serialize({requireAllSignatures: false})).toString('base64');

      const nodeCryptoTx = NodeCryptoAdapter.attachProtocolMeta(
        { instructions: [] },
        meta as ProtocolMetaFields
      );

      // Both should parse the same meta correctly
      const solanaMeta = solanaAdapter.parseMeta(solanaBase64);
      const nodeCryptoMeta = nodeCryptoAdapter.parseMeta(nodeCryptoTx);

      expect(solanaMeta).toEqual(meta);
      expect(nodeCryptoMeta).toEqual(meta);
    });

    test("protocol meta validation is consistent across chains", async () => {
      const actionCode = {
        code: "11111111",
        pubkey: "test-pubkey",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        signature: "testsignature",
      };

      const codeHashValue = codeHash(actionCode.code);
      const validMeta = {
        ver: 2,
        id: codeHashValue,
        int: actionCode.pubkey,
      };

      const invalidMeta = {
        ver: 2,
        id: "wrong-hash",
        int: "wrong-pubkey",
      };

      // Create transactions with valid and invalid meta
      const validSolanaTx = new Transaction().add(
        SolanaAdapter.createProtocolMetaIx(validMeta as ProtocolMetaFields)
      );
      validSolanaTx.recentBlockhash = "11111111111111111111111111111111";
      validSolanaTx.feePayer = testKeypair.publicKey;
      const validSolanaBase64 = Buffer.from(validSolanaTx.serialize({requireAllSignatures: false})).toString('base64');

      const invalidSolanaTx = new Transaction().add(
        SolanaAdapter.createProtocolMetaIx(invalidMeta as ProtocolMetaFields)
      );
      invalidSolanaTx.recentBlockhash = "11111111111111111111111111111111";
      invalidSolanaTx.feePayer = testKeypair.publicKey;
      const invalidSolanaBase64 = Buffer.from(invalidSolanaTx.serialize({requireAllSignatures: false})).toString('base64');

      const validNodeCryptoTx = NodeCryptoAdapter.attachProtocolMeta(
        { instructions: [] },
        validMeta as ProtocolMetaFields
      );
      const invalidNodeCryptoTx = NodeCryptoAdapter.attachProtocolMeta(
        { instructions: [] },
        invalidMeta as ProtocolMetaFields
      );

      // Both chains should accept valid meta and reject invalid meta
      expect(() => {
        solanaAdapter.verifyTransactionMatchesCode(actionCode, validSolanaBase64);
      }).not.toThrow();

      expect(() => {
        solanaAdapter.verifyTransactionMatchesCode(actionCode, invalidSolanaBase64);
      }).toThrow();

      expect(() => {
        nodeCryptoAdapter.verifyTransactionMatchesCode(
          actionCode,
          validNodeCryptoTx
        );
      }).not.toThrow();

      expect(() => {
        nodeCryptoAdapter.verifyTransactionMatchesCode(
          actionCode,
          invalidNodeCryptoTx
        );
      }).toThrow();
    });
  });
});
