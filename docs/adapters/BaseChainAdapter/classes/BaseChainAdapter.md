[**@actioncodes/protocol**](../../../README.md)

***

[@actioncodes/protocol](../../../modules.md) / [adapters/BaseChainAdapter](../README.md) / BaseChainAdapter

# Abstract Class: BaseChainAdapter

Defined in: src/adapters/BaseChainAdapter.ts:18

## Extended by

- [`SolanaAdapter`](../../SolanaAdapter/classes/SolanaAdapter.md)

## Implements

- [`ChainAdapter`](../interfaces/ChainAdapter.md)

## Constructors

### Constructor

> **new BaseChainAdapter**(): `BaseChainAdapter`

#### Returns

`BaseChainAdapter`

## Methods

### verifyRevokeWithDelegation()

> `abstract` **verifyRevokeWithDelegation**(`actionCode`, `revokeSignature`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:25

#### Parameters

##### actionCode

[`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

##### revokeSignature

`string`

#### Returns

`boolean`

#### Implementation of

[`ChainAdapter`](../interfaces/ChainAdapter.md).[`verifyRevokeWithDelegation`](../interfaces/ChainAdapter.md#verifyrevokewithdelegation)

***

### verifyRevokeWithWallet()

> `abstract` **verifyRevokeWithWallet**(`actionCode`, `revokeSignature`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:21

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

##### revokeSignature

`string`

#### Returns

`boolean`

#### Implementation of

[`ChainAdapter`](../interfaces/ChainAdapter.md).[`verifyRevokeWithWallet`](../interfaces/ChainAdapter.md#verifyrevokewithwallet)

***

### verifyWithDelegation()

> `abstract` **verifyWithDelegation**(`actionCode`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:20

#### Parameters

##### actionCode

[`DelegatedActionCode`](../../../types/interfaces/DelegatedActionCode.md)

#### Returns

`boolean`

#### Implementation of

[`ChainAdapter`](../interfaces/ChainAdapter.md).[`verifyWithDelegation`](../interfaces/ChainAdapter.md#verifywithdelegation)

***

### verifyWithWallet()

> `abstract` **verifyWithWallet**(`actionCode`): `boolean`

Defined in: src/adapters/BaseChainAdapter.ts:19

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

#### Returns

`boolean`

#### Implementation of

[`ChainAdapter`](../interfaces/ChainAdapter.md).[`verifyWithWallet`](../interfaces/ChainAdapter.md#verifywithwallet)
