[**@actioncodes/protocol**](../../../README.md)

***

[@actioncodes/protocol](../../../modules.md) / [strategy/WalletStrategy](../README.md) / WalletStrategy

# Class: WalletStrategy

Defined in: src/strategy/WalletStrategy.ts:8

## Constructors

### Constructor

> **new WalletStrategy**(`config`): `WalletStrategy`

Defined in: src/strategy/WalletStrategy.ts:9

#### Parameters

##### config

[`CodeGenerationConfig`](../../../types/interfaces/CodeGenerationConfig.md)

#### Returns

`WalletStrategy`

## Methods

### generateCode()

> **generateCode**(`canonicalMessage`, `chain`, `signature`): [`ActionCode`](../../../types/interfaces/ActionCode.md)

Defined in: src/strategy/WalletStrategy.ts:11

#### Parameters

##### canonicalMessage

`Uint8Array`

##### chain

`"solana"`

##### signature

`string`

#### Returns

[`ActionCode`](../../../types/interfaces/ActionCode.md)

***

### validateCode()

> **validateCode**(`actionCode`): `void`

Defined in: src/strategy/WalletStrategy.ts:53

#### Parameters

##### actionCode

[`ActionCode`](../../../types/interfaces/ActionCode.md)

#### Returns

`void`
