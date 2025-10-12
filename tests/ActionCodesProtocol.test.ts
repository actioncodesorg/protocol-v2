import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import { serializeDelegationProof } from "../src/utils/canonical";
import type { Chain, DelegationProof } from "../src/types";
import type { SignFn } from "../src/adapters/BaseChainAdapter";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import bs58 from "bs58";

const CHAIN: Chain = "solana" as const;

function createSignFnWithCapture(keypair: Keypair) {
  let lastBytes: Uint8Array | null = null;
  const signFn: SignFn = async (message, chain) => {
    if (chain !== CHAIN) throw new Error(`Unexpected chain ${chain}`);
    lastBytes = message;
    const sig = nacl.sign.detached(message, keypair.secretKey);
    return bs58.encode(sig);
  };
  return {
    signFn,
    getLastBytes: () => lastBytes,
  };
}

function createSignFn(keypair: Keypair): SignFn {
  return async (message, chain) => {
    if (chain !== CHAIN) throw new Error(`Unexpected chain ${chain}`);
    const sig = nacl.sign.detached(message, keypair.secretKey);
    return bs58.encode(sig);
  };
}

describe("ActionCodesProtocol - real Solana signatures", () => {
  test("wallet flow: generate and validate with real signature; timestamp aligned", async () => {
    const protocol = new ActionCodesProtocol({ codeLength: 8, ttlMs: 2 * 60_000 });
    const wallet = Keypair.generate();

    const { signFn, getLastBytes } = createSignFnWithCapture(wallet);

    const actionCode = await protocol.generate(
      "wallet",
      wallet.publicKey.toBase58(),
      CHAIN,
      signFn
    );

    // Validate via protocol (pure)
    protocol.validate("wallet", actionCode);

    // Validate via adapter (chain-level)
    const ok = protocol.adapter.solana.verifyWithWallet(actionCode);
    expect(ok).toBe(true);

    // Timestamp alignment: canonical that was signed matches actionCode fields
    const bytes = getLastBytes();
    expect(bytes).not.toBeNull();
    const canonical = JSON.parse(new TextDecoder().decode(bytes!));
    expect(canonical.pubkey).toBe(actionCode.pubkey);
    expect(canonical.windowStart).toBe(actionCode.timestamp);
  });

  test("delegation flow: generate and validate with owner+delegated real signatures", async () => {
    const protocol = new ActionCodesProtocol({ codeLength: 8, ttlMs: 2 * 60_000 });
    const owner = Keypair.generate();
    const delegated = Keypair.generate();

    // Build signed delegation proof by owner
    const proofFields = {
      walletPubkey: owner.publicKey.toBase58(),
      delegatedPubkey: delegated.publicKey.toBase58(),
      expiresAt: Date.now() + 60 * 60 * 1000,
      chain: CHAIN,
    };
    const proofBytes = serializeDelegationProof(proofFields);
    const ownerSig = nacl.sign.detached(proofBytes, owner.secretKey);
    const delegationProof: DelegationProof = {
      ...proofFields,
      signature: bs58.encode(ownerSig),
    };

    // Generate delegated code signed by delegated wallet
    const { signFn, getLastBytes } = createSignFnWithCapture(delegated);
    const delegatedCode = await protocol.generate(
      "delegation",
      delegationProof,
      CHAIN,
      signFn
    );

    // Debug: Check the canonical message that was signed
    const bytes = getLastBytes();
    expect(bytes).not.toBeNull();
    const canonical = JSON.parse(new TextDecoder().decode(bytes!));
    console.log("Signed canonical:", canonical);
    console.log("Delegated code timestamp:", delegatedCode.timestamp);
    console.log("Delegated code pubkey:", delegatedCode.pubkey);
    console.log("Delegation proof delegated pubkey:", delegationProof.delegatedPubkey);

    // Validate protocol-level and adapter-level
    protocol.validate("delegation", delegatedCode);
    const ok = protocol.adapter.solana.verifyWithDelegation(delegatedCode);
    expect(ok).toBe(true);

    // CRITICAL: DelegatedActionCode.pubkey should be the DELEGATED SIGNER (who signed the message)
    expect(delegatedCode.pubkey).toBe(delegationProof.delegatedPubkey);
    expect(delegatedCode.pubkey).not.toBe(delegationProof.walletPubkey);

    // Timestamp alignment
    expect(canonical.pubkey).toBe(delegationProof.delegatedPubkey);
    expect(canonical.windowStart).toBe(delegatedCode.timestamp);
  });

  test("wallet revoke: produces verifiable revoke signature", async () => {
    const protocol = new ActionCodesProtocol({ codeLength: 8, ttlMs: 2 * 60_000 });
    const wallet = Keypair.generate();
    const signWallet = createSignFn(wallet);

    const actionCode = await protocol.generate(
      "wallet",
      wallet.publicKey.toBase58(),
      CHAIN,
      signWallet
    );
    const revokeRecord = await protocol.revoke("wallet", actionCode, CHAIN, signWallet);

    // Verify revoke with adapter
    const ok = protocol.adapter.solana.verifyRevokeWithWallet(
      actionCode,
      revokeRecord.revokeSignature
    );
    expect(ok).toBe(true);
  });

  test("delegation revoke: delegated signer can revoke with proof", async () => {
    const protocol = new ActionCodesProtocol({ codeLength: 8, ttlMs: 2 * 60_000 });
    const owner = Keypair.generate();
    const delegated = Keypair.generate();

    const proofFields = {
      walletPubkey: owner.publicKey.toBase58(),
      delegatedPubkey: delegated.publicKey.toBase58(),
      expiresAt: Date.now() + 60 * 60 * 1000,
      chain: CHAIN,
    };
    const proofBytes = serializeDelegationProof(proofFields);
    const ownerSig = nacl.sign.detached(proofBytes, owner.secretKey);
    const delegationProof: DelegationProof = {
      ...proofFields,
      signature: bs58.encode(ownerSig),
    };

    const delegatedCode = await protocol.generate(
      "delegation",
      delegationProof,
      CHAIN,
      createSignFn(delegated)
    );

    // CRITICAL: DelegatedActionCode.pubkey should be the DELEGATED SIGNER (who signed the message)
    expect(delegatedCode.pubkey).toBe(delegationProof.delegatedPubkey);
    expect(delegatedCode.pubkey).not.toBe(delegationProof.walletPubkey);

    const revokeRecord = await protocol.revoke(
      "delegation",
      delegatedCode,
      CHAIN,
      createSignFn(delegated)
    );

    const ok = protocol.adapter.solana.verifyRevokeWithDelegation(
      delegatedCode,
      revokeRecord.revokeSignature
    );
    expect(ok).toBe(true);
  });

  test("wallet complete flow: generate → validate → revoke", async () => {
    const protocol = new ActionCodesProtocol({ codeLength: 8, ttlMs: 2 * 60_000 });
    const wallet = Keypair.generate();
    const signWallet = createSignFn(wallet);

    // 1. Generate
    const actionCode = await protocol.generate(
      "wallet",
      wallet.publicKey.toBase58(),
      CHAIN,
      signWallet
    );

    // 2. Validate (protocol + adapter)
    protocol.validate("wallet", actionCode);
    const validateOk = protocol.adapter.solana.verifyWithWallet(actionCode);
    expect(validateOk).toBe(true);

    // 3. Revoke
    const revokeRecord = await protocol.revoke("wallet", actionCode, CHAIN, signWallet);

    // 4. Verify revoke
    const revokeOk = protocol.adapter.solana.verifyRevokeWithWallet(
      actionCode,
      revokeRecord.revokeSignature
    );
    expect(revokeOk).toBe(true);
  });

  test("delegation complete flow: generate → validate → revoke", async () => {
    const protocol = new ActionCodesProtocol({ codeLength: 8, ttlMs: 2 * 60_000 });
    const owner = Keypair.generate();
    const delegated = Keypair.generate();

    // Build delegation proof
    const proofFields = {
      walletPubkey: owner.publicKey.toBase58(),
      delegatedPubkey: delegated.publicKey.toBase58(),
      expiresAt: Date.now() + 60 * 60 * 1000,
      chain: CHAIN,
    };
    const proofBytes = serializeDelegationProof(proofFields);
    const ownerSig = nacl.sign.detached(proofBytes, owner.secretKey);
    const delegationProof: DelegationProof = {
      ...proofFields,
      signature: bs58.encode(ownerSig),
    };

    // 1. Generate
    const delegatedCode = await protocol.generate(
      "delegation",
      delegationProof,
      CHAIN,
      createSignFn(delegated)
    );

    // 2. Validate (protocol + adapter)
    protocol.validate("delegation", delegatedCode);
    const validateOk = protocol.adapter.solana.verifyWithDelegation(delegatedCode);
    expect(validateOk).toBe(true);

    // 3. Revoke
    const revokeRecord = await protocol.revoke(
      "delegation",
      delegatedCode,
      CHAIN,
      createSignFn(delegated)
    );

    // 4. Verify revoke
    const revokeOk = protocol.adapter.solana.verifyRevokeWithDelegation(
      delegatedCode,
      revokeRecord.revokeSignature
    );
    expect(revokeOk).toBe(true);
  });
});


