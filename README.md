# ERC-4337 Modular Smart Wallet with Passkey Support

ModularWallet is a next-gen smart contract wallet built on Ethereum’s ERC-4337 Account Abstraction and the emerging ERC-7579 module standard. It offers counterfactual CREATE2 deployment, a lean immutable core, and a pluggable architecture: signature validation lives in a separate ERC-7780 “signer” module (OwnershipManagement), and execution logic (e.g. DCA) plugs in via ERC-7579 modules.



## Table of Contents

- [ERC-4337 Modular Smart Wallet with Passkey Support](#erc-4337-modular-smart-wallet-with-passkey-support)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Design \& Architecture](#design--architecture)
  - [Core Components](#core-components)
    - [ModularWallet.sol](#modularwalletsol)
    - [WalletFactory.sol](#walletfactorysol)
  - [Module Design](#module-design)
    - [OwnershipManagement.sol (Signer Module)](#ownershipmanagementsol-signer-module)
    - [DCA (Execution Module)](#dca-execution-module)
  - [Standards](#standards)
  - [Design Decisions \& Trade-Offs](#design-decisions--trade-offs)
  - [Security Considerations](#security-considerations)



## Overview

- **Immutable Core**  
  `ModularWallet.sol` is non-upgradeable to minimise attack surface.  

- **Counterfactual Deployment**  
  Wallets deploy via CREATE2 (`WalletFactory`), so addresses exist off-chain ahead of time.  

- **Pluggable Modules**  
  - **Signer Modules (type 6)** handle signature logic (ERC-7780).  
  - **Execution Modules (type 2)** handle on-chain operations (ERC-7579).  

- **Break-Glass Recovery**  
  A time-locked fallback admin path lets you schedule or execute emergency key rotations without redeploying the core.



## Design & Architecture

1. **Minimal, Non-Upgradeable Core** 
All business logic (ownership, DCA, recovery) is isolated in separate modules.


2. **Separation of Concerns** 
Leverage ERC-7579’s `install`/`uninstall` pattern to keep roles isolated and hot-swappable at runtime.


3. **On-Chain Recovery & Rotation** 
OwnershipManagement supports atomic `rotateKey` calls and a 24 h delayed fallback-admin path, keeping a validator live at all times.



## Core Components 

### ModularWallet.sol

- **Based on** `BaseAccount` (ETH-Infinitism ERC-4337) for spec compliance.  
- **Entrypoint Guard** 
  1. The `entryPoint()` override (inherited from `BaseAccount`) declares the trusted ERC-4337 EntryPoint. 
  2. The `onlyEntryPoint` modifier on `installModule`, `uninstallModule`, and `execute` enforces that these critical functions are called exclusively by the trusted `IEntryPoint` instance declared by the `entryPoint()` function. This ensures that all module installs, removals, and user-initiated executions originate from `IEntryPoint.handleOps`. 
- **ERC-1271** support via `isValidSignature` and **ERC-165** via `supportsInterface`, alongside the ERC-4337 account interface.  

### WalletFactory.sol
  
- **CREATE2 Deployment**: deterministic off-chain addresses, no proxies required.  
- **Auto-Install Signer Module**: 
  1. **Constructor** locks in `i_entryPoint` and `i_ownershipModule`.  
  2. **createWallet(salt, ownershipInitData)** ABI-packs the init data into the `ModularWallet` constructor and deploys via CREATE2.



## Module Design

### OwnershipManagement.sol (Signer Module)

- Implements **ERC-7780 ISigner**:  
  - `checkUserOpSignature` for `userOp` flows  
  - `checkSignature` (ERC-1271) for `eth_sign`  
- **Passkey Storage & Rotation**: stores a P-256 public key `(x, y)` and exposes atomic `rotateKey(newX,newY)` via a single UserOp.  
- **Key Rotation**: Signer modules (type 6) cannot be uninstalled from ModularWallet (enforced by contract logic); instead, `rotateKey` must be called to swap keys, ensuring the wallet never risks a “brick” state without a valid signer. 
- **Break-Glass**: fallback admin can request and execute an emergency rotation after a 24 h delay.


### DCA (Execution Module)

- **MVP Scope**: minimal `createPlan(token, destination, amount, interval)` + `run(planId)` to demonstrate ERC-7579 integration. Plans are created when the wallet owner submits a `UserOperation` that calls `wallet.execute(...)`, which then invokes the createPlan function on the DCA module.
- **Asset Support**: works with both native ETH and ERC-20 tokens. 
- **No Custody**: transfers always execute through the wallet via `executeFromExecutor`.  
- **Install/Uninstall**: plug in or remove without touching core wallet code.



## Standards

| Standard | Role                         | Trade-Offs                              |
| -------- | ---------------------------- | --------------------------------------- |
| ERC-4337 | Account Abstraction          | Complex gas model; bundler dependency   |
| ERC-7579 | Modular Smart Account (exec) | Thin specification; minimal boilerplate |
| ERC-7780 | Signer Modules               | Newer standard; narrower adoption       |
| ERC-1271 | Contract Signature Callback  | Ubiquitous; on-chain verifications      |


> **Note:** EIP-6492 (“witness” format) is not included in this MVP. Production-grade bundlers will need it to validate counterfactual signatures.



## Design Decisions & Trade-Offs

- **Passkey (WebAuthn P-256)**  
  - Chose Daimo’s audited `p256-verifier` (~330 k gas) over custom or off-chain solutions.  
  - Future swap to EIP-7212 precompile (≈20 k gas) with a one-line change—already live on some L1s/testnets.

- **Single-Call Execution Mode**  
  Only one `(to, value, data)` per UserOp to keep gas predictable and logic simple for MVP.

- **Immutable Modules vs. Proxies**  
  Avoided proxy pattern for DCA and OwnershipManagement to reduce complexity and attack surface. Future upgrades can introduce proxies once stability and governance controls are properly set.

- **ERC-7579 + ERC-7780 vs. ERC-6900**  
  Preferred the lighter, battle-tested 7579/7780 combo for clear separation of auth (type 6 “signer”) and functionality (type 2 “execution”) with strong ecosystem support.



## Security Considerations

- Emergency recovery paths are time-locked and auditable.  
- Core Wallet logic is immutable; only modules evolve.  
- All module installs/uninstalls require a validated UserOp via EntryPoint.




