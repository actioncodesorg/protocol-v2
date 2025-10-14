import type {
  ActionCode,
  CodeGenerationConfig,
  DelegationProof,
  DelegatedActionCode,
  Chain,
  ActionCodeRevoke,
  DelegatedActionCodeRevoke,
} from "./types";
import type { ChainAdapter, SignFn } from "./adapters/BaseChainAdapter";
import { WalletStrategy } from "./strategy/WalletStrategy";
import { DelegationStrategy } from "./strategy/DelegationStrategy";
import { SolanaAdapter } from "./adapters/SolanaAdapter";
import { ProtocolError } from "./errors";
import { SUPPORTED_CHAINS } from "./constants";
import {
  getCanonicalMessageParts,
  serializeCanonicalRevoke,
} from "./utils/canonical";
import { codeHash } from "./utils/crypto";

export class ActionCodesProtocol {
  private adapters: Record<string, ChainAdapter> = {};
  private _walletStrategy: WalletStrategy;
  private _delegationStrategy: DelegationStrategy;

  constructor(private readonly config: CodeGenerationConfig) {
    // Register default adapters
    this.adapters.solana = new SolanaAdapter();

    // Initialize strategies
    this._walletStrategy = new WalletStrategy(config);
    this._delegationStrategy = new DelegationStrategy(config);
  }

  public getConfig(): CodeGenerationConfig {
    return this.config;
  }

  /** Register a chain adapter */
  registerAdapter(chain: string, adapter: ChainAdapter): void {
    this.adapters[chain] = adapter;
  }

  /** Get a registered adapter */
  getAdapter(chain: string): ChainAdapter | undefined {
    return this.adapters[chain];
  }

  /** Typed access to specific adapters */
  get adapter() {
    return {
      solana: this.adapters.solana as unknown as SolanaAdapter,
    };
  }

  /** Access to strategies */
  get walletStrategy() {
    return this._walletStrategy;
  }

  get delegationStrategy() {
    return this._delegationStrategy;
  }

  // Generate code
  async generate(
    strategy: "wallet",
    pubkey: string,
    chain: Chain,
    signFn: SignFn
  ): Promise<ActionCode>;
  async generate(
    strategy: "delegation",
    delegationProof: DelegationProof,
    chain: Chain,
    signFn: SignFn
  ): Promise<DelegatedActionCode>;
  async generate(
    strategy: "wallet" | "delegation",
    pubkeyOrProof: string | DelegationProof,
    chain: Chain,
    signFn: SignFn
  ): Promise<ActionCode | DelegatedActionCode> {
    if (!chain || !SUPPORTED_CHAINS[chain]) {
      throw ProtocolError.invalidAdapter(chain);
    }

    if (!signFn || typeof signFn !== "function") {
      throw ProtocolError.invalidSignature("Missing signature function");
    }

    if (strategy === "wallet") {
      const canonical = getCanonicalMessageParts(pubkeyOrProof as string);
      // For now we have to pass Solana as only chain
      // later we will allow to pass the chain dynamically
      const signature = await signFn(canonical, chain);

      // Here param1 must be Uint8Array (canonical message)
      if (!signature) {
        throw ProtocolError.invalidSignature(
          "Missing signature over canonical message"
        );
      }
      return this.walletStrategy.generateCode(canonical, chain, signature);
    } else {
      const proof = pubkeyOrProof as DelegationProof;
      const canonical = getCanonicalMessageParts(proof.delegatedPubkey); // Use delegated pubkey for signing
      const signature = await signFn(canonical, chain);

      // Here param1 must be DelegationProof
      if (!signature) {
        throw ProtocolError.invalidSignature("Missing delegated signature");
      }
      return this.delegationStrategy.generateDelegatedCode(
        proof as DelegationProof,
        canonical,
        chain,
        signature
      );
    }
  }

  async revoke(
    strategy: "wallet",
    actionCode: ActionCode,
    chain: Chain,
    signFn: SignFn
  ): Promise<ActionCodeRevoke>;
  async revoke(
    strategy: "delegation",
    actionCode: DelegatedActionCode,
    chain: Chain,
    signFn: SignFn
  ): Promise<DelegatedActionCodeRevoke>;
  async revoke(
    strategy: "wallet" | "delegation",
    actionCode: ActionCode | DelegatedActionCode,
    chain: Chain,
    signFn: SignFn
  ): Promise<ActionCodeRevoke | DelegatedActionCodeRevoke> {
    if (!chain || !SUPPORTED_CHAINS[chain]) {
      throw ProtocolError.invalidAdapter(chain);
    }

    if (!signFn || typeof signFn !== "function") {
      throw ProtocolError.invalidSignature("Missing signature function");
    }

    if (strategy === "wallet") {
      const canonical = serializeCanonicalRevoke({
        codeHash: codeHash(actionCode.code),
        pubkey: actionCode.pubkey,
        windowStart: actionCode.timestamp,
      });
      // For now we have to pass Solana as only chain
      // later we will allow to pass the chain dynamically
      const signature = await signFn(canonical, chain);

      // Here param1 must be Uint8Array (canonical message)
      if (!signature) {
        throw ProtocolError.invalidSignature(
          "Missing signature over canonical message"
        );
      }

      return {
        ...actionCode,
        revokeSignature: signature,
      };
    } else {
      const delegatedActionCode = actionCode as DelegatedActionCode;
      const canonical = serializeCanonicalRevoke({
        codeHash: codeHash(actionCode.code),
        pubkey: delegatedActionCode.delegationProof.delegatedPubkey, // Use delegated pubkey for signature
        windowStart: actionCode.timestamp,
      });
      const signature = await signFn(canonical, chain);

      // Here param1 must be DelegationProof
      if (!signature) {
        throw ProtocolError.invalidSignature("Missing delegated signature");
      }

      return {
        ...actionCode,
        revokeSignature: signature,
      };
    }
  }

  // Overloaded validateCode methods with strategy parameter
  validate(strategy: "wallet", actionCode: ActionCode): void;
  validate(strategy: "delegation", actionCode: DelegatedActionCode): void;
  validate(
    strategy: "wallet" | "delegation",
    actionCode: ActionCode | DelegatedActionCode
  ): void {
    if (strategy === "wallet") {
      // This will throw if validation fails
      this.walletStrategy.validateCode(actionCode as ActionCode);

      const adapter = this.getAdapter(actionCode.chain);
      if (!adapter) throw ProtocolError.invalidAdapter(actionCode.chain);

      const ok = adapter.verifyWithWallet(actionCode);

      if (!ok) {
        throw ProtocolError.invalidSignature(
          "Wallet signature verification failed"
        );
      }
    } else {
      this.delegationStrategy.validateDelegatedCode(
        actionCode as DelegatedActionCode
      );

      // Then verify the delegation proof signature
      const adapter = this.getAdapter(actionCode.chain);
      if (!adapter) throw ProtocolError.invalidAdapter(actionCode.chain);

      const ok = adapter.verifyWithDelegation(
        actionCode as DelegatedActionCode
      );

      if (!ok) {
        throw ProtocolError.invalidSignature(
          "Delegation signature verification failed"
        );
      }
    }
  }
}
