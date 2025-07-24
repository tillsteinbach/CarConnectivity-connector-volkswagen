# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- No unreleased changes so far

## [0.8.2] - 2025-07-22
### Fixed
- Fixes attribute for estimated time reached for charging

## [0.8.1] - 2025-06-27
### Added
- Fix support for adblue range

## [0.8] - 2025-06-26
### Added
- Support for adblue range

## [0.7.3] - 2025-06-20
### Fixed
- Fixes bug that registers hooks several times, causing multiple calls to the servers

### Changed
- Updated dependencies

## [0.7.2] - 2025-04-19
### Fixed
- Fix for problems introduced with PyJWT

## [0.7.1] - 2025-04-19
### Changed
- Use PyJWT instead of jwt

## [0.7] - 2025-04-17
### Changed
- Updated dependencies
- stripping of leading and trailing spaces in commands

### Added
- Precision for all attributes is now used when displaying values

## [0.6] - 2025-04-02
### Fixed
- Made changes to charging settings for older electric vehicles
- Allowes to have multiple instances of this connector running

### Changed
- Updated dependencies

## [0.5] - 2025-03-20
### Added
- Support for window heating attributes
- Support for window heating command
- SUpport for changing charging settings

## [0.4.2] - 2025-03-11
### Fixed
- Fixes bug where no data was shown anymore if the vehicle did not have access capability

## [0.4.1] - 2025-03-04
### Fixed
- Fixed http error when parking position was fetched but due to error not available

## [0.4] - 2025-03-02
### Added
- Added hint to do consent when login is not possible
- Make connection_state public accessible
- Make health state public accessible
- Make interval online changeable
- Threads are now named
- vehcile state is calculated from various states
- Added support for battery temperature
- Check for value range in attributes
- Added support for maintenance attributes
- Added support for plug states
- Added support for connectivity status
- Added position type
- Added better error handling in commands

### Fixed
- Images and capabilities are now only fetched once
- Fix for fetching charging state
- Fix for total range if not a vehicle property
- Fix for older python versions
- Fix for rear seat heating settings

## [0.3] - 2025-02-19
### Added
- Added support for images
- Added tags to attributes
- Added support for webui via carconnectivity-plugin-webui

## [0.2] - 2025-02-02
### Added
- Adds several commands to control the vehicle and charging attributes

## [0.1] - 2025-01-25
Initial release, let's go and give this to the public to try out...
The API is not yet implemented completely! There is no way to control something in the car yet

[unreleased]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/compare/v0.8.2...HEAD
[0.8.2]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.8.2
[0.8.1]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.8.1
[0.8]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.8
[0.7.3]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.7.3
[0.7.2]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.7.2
[0.7.1]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.7.1
[0.7]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.7
[0.6]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.6
[0.5]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.5
[0.4.2]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.4.2
[0.4.1]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.4.1
[0.4]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.4
[0.3]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.3
[0.2]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.2
[0.1]: https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/tag/v0.1
