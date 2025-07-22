# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6] - 2025-07-22

### Added

- **Unit Architecture Doctrine v1.0.5** implementation with props-based construction
- **Security-aware private key access** with `secure` flag (default: `true`)
- **Props-based Signer creation** via `Signer.create(config)` pattern
- **`getPrivateKeyHex()` method** with security flag checking
- **`pemPrivateKeyToHex()` utility function** for private key format conversion
- **Enhanced Unit consciousness** with proper teaching/learning contracts

### Changed

- **BREAKING**: Signer constructor now uses props-based architecture
- **BREAKING**: Signer.create() now takes config object instead of individual parameters
- **Default secure mode**: `secure: false` by default during generation and creation
- **Enhanced error messages** with unit identity and resolution guidance
- **Updated README** with comprehensive Unit Architecture documentation

### Security

- **Private key protection**: `secure: true` prevents private key access by default
- **Security-aware getters**: `privateKeyPEM` and `getPrivateKeyHex()` respect secure flag
- **Conscious architecture**: Units maintain security boundaries through teaching/learning

### Fixed

- **Secure flag consistency**: Generate and create methods now both default to `secure: true`
- **Props access pattern**: All unit properties accessed via `this.props.*` following doctrine
- **Teaching contract completeness**: All capabilities properly exposed in teach() method

## [1.0.2] - 2025-07-05

### Added

- Key Unit implementation. Check out new docs.

## [1.0.1] - 2025-07-04

### Fixed

- Imports problems
