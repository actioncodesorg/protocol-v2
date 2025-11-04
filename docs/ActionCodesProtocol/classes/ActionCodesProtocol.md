[**@actioncodes/protocol**](../../README.md)

***

[@actioncodes/protocol](../../modules.md) / [ActionCodesProtocol](../README.md) / ActionCodesProtocol

# Class: ActionCodesProtocol

Defined in: src/ActionCodesProtocol.ts:22

## Constructors

### Constructor

> **new ActionCodesProtocol**(`config`): `ActionCodesProtocol`

Defined in: src/ActionCodesProtocol.ts:27

#### Parameters

##### config

[`CodeGenerationConfig`](../../types/interfaces/CodeGenerationConfig.md)

#### Returns

`ActionCodesProtocol`

## Accessors

### adapter

#### Get Signature

> **get** **adapter**(): `object`

Defined in: src/ActionCodesProtocol.ts:51

Typed access to specific adapters

##### Returns

`object`

###### solana

> **solana**: [`SolanaAdapter`](../../adapters/SolanaAdapter/classes/SolanaAdapter.md)

***

### delegationStrategy

#### Get Signature

> **get** **delegationStrategy**(): [`DelegationStrategy`](../../strategy/DelegationStrategy/classes/DelegationStrategy.md)

Defined in: src/ActionCodesProtocol.ts:62

##### Returns

[`DelegationStrategy`](../../strategy/DelegationStrategy/classes/DelegationStrategy.md)

***

### walletStrategy

#### Get Signature

> **get** **walletStrategy**(): [`WalletStrategy`](../../strategy/WalletStrategy/classes/WalletStrategy.md)

Defined in: src/ActionCodesProtocol.ts:58

Access to strategies

##### Returns

[`WalletStrategy`](../../strategy/WalletStrategy/classes/WalletStrategy.md)

## Methods

### generate()

#### Call Signature

> **generate**(`strategy`, `pubkey`, `chain`, `signFn`): `Promise`\<[`ActionCode`](../../types/interfaces/ActionCode.md)\>

Defined in: src/ActionCodesProtocol.ts:67

##### Parameters

###### strategy

`"wallet"`

###### pubkey

`string`

###### chain

`"solana"`

###### signFn

[`SignFn`](../../adapters/BaseChainAdapter/type-aliases/SignFn.md)

##### Returns

`Promise`\<[`ActionCode`](../../types/interfaces/ActionCode.md)\>

#### Call Signature

> **generate**(`strategy`, `delegationProof`, `chain`, `signFn`): `Promise`\<[`DelegatedActionCode`](../../types/interfaces/DelegatedActionCode.md)\>

Defined in: src/ActionCodesProtocol.ts:73

##### Parameters

###### strategy

`"delegation"`

###### delegationProof

[`DelegationProof`](../../types/interfaces/DelegationProof.md)

###### chain

`"solana"`

###### signFn

[`SignFn`](../../adapters/BaseChainAdapter/type-aliases/SignFn.md)

##### Returns

`Promise`\<[`DelegatedActionCode`](../../types/interfaces/DelegatedActionCode.md)\>

***

### getAdapter()

> **getAdapter**(`chain`): `undefined` \| [`ChainAdapter`](../../adapters/BaseChainAdapter/interfaces/ChainAdapter.md)

Defined in: src/ActionCodesProtocol.ts:46

Get a registered adapter

#### Parameters

##### chain

`string`

#### Returns

`undefined` \| [`ChainAdapter`](../../adapters/BaseChainAdapter/interfaces/ChainAdapter.md)

***

### getConfig()

> **getConfig**(): [`CodeGenerationConfig`](../../types/interfaces/CodeGenerationConfig.md)

Defined in: src/ActionCodesProtocol.ts:36

#### Returns

[`CodeGenerationConfig`](../../types/interfaces/CodeGenerationConfig.md)

***

### registerAdapter()

> **registerAdapter**(`chain`, `adapter`): `void`

Defined in: src/ActionCodesProtocol.ts:41

Register a chain adapter

#### Parameters

##### chain

`string`

##### adapter

[`ChainAdapter`](../../adapters/BaseChainAdapter/interfaces/ChainAdapter.md)

#### Returns

`void`

***

### revoke()

#### Call Signature

> **revoke**(`strategy`, `actionCode`, `chain`, `signFn`): `Promise`\<[`ActionCodeRevoke`](../../types/interfaces/ActionCodeRevoke.md)\>

Defined in: src/ActionCodesProtocol.ts:124

##### Parameters

###### strategy

`"wallet"`

###### actionCode

[`ActionCode`](../../types/interfaces/ActionCode.md)

###### chain

`"solana"`

###### signFn

[`SignFn`](../../adapters/BaseChainAdapter/type-aliases/SignFn.md)

##### Returns

`Promise`\<[`ActionCodeRevoke`](../../types/interfaces/ActionCodeRevoke.md)\>

#### Call Signature

> **revoke**(`strategy`, `actionCode`, `chain`, `signFn`): `Promise`\<[`DelegatedActionCodeRevoke`](../../types/interfaces/DelegatedActionCodeRevoke.md)\>

Defined in: src/ActionCodesProtocol.ts:130

##### Parameters

###### strategy

`"delegation"`

###### actionCode

[`DelegatedActionCode`](../../types/interfaces/DelegatedActionCode.md)

###### chain

`"solana"`

###### signFn

[`SignFn`](../../adapters/BaseChainAdapter/type-aliases/SignFn.md)

##### Returns

`Promise`\<[`DelegatedActionCodeRevoke`](../../types/interfaces/DelegatedActionCodeRevoke.md)\>

***

### validate()

#### Call Signature

> **validate**(`strategy`, `actionCode`): `void`

Defined in: src/ActionCodesProtocol.ts:193

##### Parameters

###### strategy

`"wallet"`

###### actionCode

[`ActionCode`](../../types/interfaces/ActionCode.md)

##### Returns

`void`

#### Call Signature

> **validate**(`strategy`, `actionCode`): `void`

Defined in: src/ActionCodesProtocol.ts:194

##### Parameters

###### strategy

`"delegation"`

###### actionCode

[`DelegatedActionCode`](../../types/interfaces/DelegatedActionCode.md)

##### Returns

`void`
