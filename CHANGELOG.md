# Changelog

All notable changes to this project will be documented in this file.

## [0.1.2] - 2025-11-24
### Security Fixes
- Fixed a truncation vulnerability in `DecryptStream` where truncated files were not detected. The decryptor now verifies that the number of decrypted bytes matches the expected file size from the header.

### Improvements
- Code comment cleanup: Removed redundant and obvious comments to improve code readability.

## [0.1.1] - 2025-11-24
### Documentation
- Added comprehensive package documentation and usage examples.
- Updated license files.

### CI/CD
- Excluded example and benchmark packages from coverage reports.
- Updated Go version to 1.25.4 in CI workflows.

## [0.1.0] - 2025-11-14
- Initial public release candidate. API and examples may change in future minor releases.
