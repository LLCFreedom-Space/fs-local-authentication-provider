# FSLocalAuthenticationProvider

[![Swift Version][swift-image]][swift-url]
[![License][license-image]][license-url]
![GitHub release (with filter)](https://img.shields.io/github/v/release/LLCFreedom-Space/fs-local-authentication-provider)
[![Read the Docs](https://readthedocs.org/projects/docs/badge/?version=latest)](https://llcfreedom-space.github.io/fs-local-authentication-provider/)
![example workflow](https://github.com/LLCFreedom-Space/fs-local-authentication-provider/actions/workflows/docc.yml/badge.svg?branch=main)
![example workflow](https://github.com/LLCFreedom-Space/fs-local-authentication-provider/actions/workflows/lint.yml/badge.svg?branch=main)
![example workflow](https://github.com/LLCFreedom-Space/fs-local-authentication-provider/actions/workflows/test.yml/badge.svg?branch=main)
[![codecov](https://codecov.io/github/LLCFreedom-Space/fs-local-authentication-provider/graph/badge.svg?token=2EUIA4OGS9)](https://codecov.io/github/LLCFreedom-Space/fs-local-authentication-provider)

Provides methods to manage local authentication on iOS devices, including:

* Checking biometric availability (Face ID, Touch ID, or Optic ID)
* Setting up biometric authentication with a localized reason
* Authenticating users using biometrics
* Retrieving the available biometric type

## Features

* Clear and concise API for easy integration
* Error handling for common authentication issues
* Logging for debugging and troubleshooting
* Support for testing with a mock LAContext
* Compatibility with iOS 10.0 and later

## Installation

Add the package to your Package.swift file:

```swift
dependencies: [
.package(url: "https://github.com/LLCFreedom-Space/fs-local-authentication-provider", from: "1.0.0")
]
```

Import the package in your Swift files:

```swift
import LocalAuthenticationProvider
```

## Usage

Import the library:

```swift
import LocalAuthenticationProvider
```

Create an instance of `LocalAuthenticationProvider`:

```swift
let provider = LocalAuthenticationProvider()
```

Use the provided methods to perform authentication tasks:

```swift
// Check if biometric authentication is available
if try await provider.checkBiometricAvailable() {
    // Set up biometric authentication
    if try await provider.setBiometricAuthentication(localizedReason: "Authenticate to access your data") {
        // Authenticate the user
        if try await provider.authenticate(localizedReason: "Confirm your identity") {
            // Authentication successful!
        } else {
            // Authentication failed
        }
    } else {
        // Biometric authentication could not be set up
    }
} else {
    // Biometric authentication is not available
}
```

## Contributions

We welcome contributions to this project! Please feel free to open issues or pull requests to help improve the package.

## Links

LLC Freedom Space – [@LLCFreedomSpace](https://twitter.com/llcfreedomspace) – [support@freedomspace.company](mailto:support@freedomspace.company)

Distributed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3. See [LICENSE.md][license-url] for more information.

[GitHub](https://github.com/LLCFreedom-Space)

[swift-image]:https://img.shields.io/badge/swift-5.8-orange.svg
[swift-url]: https://swift.org/
[license-image]: https://img.shields.io/badge/License-GPLv3-blue.svg
[license-url]: LICENSE
