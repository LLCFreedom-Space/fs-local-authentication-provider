// FS Local Authentication Provider
// Copyright (C) 2023  FREEDOM SPACE, LLC

//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.

//
//  LocalAuthenticationProvider.swift
//  DealogX
//
//  Created by Mykhailo Bondarenko on 19.07.2022.
//

import Foundation
import LocalAuthentication
import os

/// Provide local authentication functionality, providing methods to check biometric availability, initiate authentication, and retrieve the available biometric type.
public final class LocalAuthenticationProvider: LocalAuthenticationProviderProtocol {
    /// Logger for logging events related to local authentication.
    private let logger = Logger(
        subsystem: "LocalAuthenticationProvider",
        category: String(describing: LocalAuthenticationProvider.self)
    )
    
    /// The context for interacting with the Local Authentication framework.
    private let context: LAContext
    
    /// Creates a new instance of the `LocalAuthenticationProvider`.
    ///
    /// - Parameter context: The LAContext to use for authentication. Defaults to a new LAContext instance.
    public init(context: LAContext = LAContext()) {
        self.context = context
    }
    
    /// Checks if biometric authentication is available on the device.
    /// - Parameter policy: The policy to evaluate.
    /// - Returns: `true` if biometric authentication is available, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during the check.
    public func checkBiometricAvailable(with policy: LocalAuthenticationPolicy) async throws -> Bool {
        var error: NSError?
        if context.canEvaluate(policy: policy, error: &error) {
            return true
        } else {
            if let error {
                throw mapToLocalAuthenticationError(error, context: context)
            } else {
                throw mapToLocalAuthenticationError(
                    NSError(
                        domain: LAError.errorDomain,
                        code: LocalAuthenticationError.unknownError,
                        userInfo: nil
                    ),
                    context: context
                )
            }
        }
    }
    
    /// Sets up biometric authentication with the given localized reason, preparing for authentication but not initiating it immediately.
    /// - Parameter localizedReason: A string explaining why authentication is being requested.
    /// - Returns: `true` if biometric authentication was successfully set up, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during setup.
    public func setBiometricAuthentication(localizedReason: String) async throws -> Bool {
        _ = try await checkBiometricAvailable(with: .biometrics)
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics, localizedReason: localizedReason
            )
        } catch {
            throw mapToLocalAuthenticationError(error, context: context)
        }
    }
    
    /// Authenticates the user using biometric authentication with the given localized reason.
    /// - Parameter localizedReason: A string explaining why authentication is being requested.
    /// - Returns: `true` if authentication was successful, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during authentication.
    public func authenticate(localizedReason: String) async throws -> Bool {
        _ = try await checkBiometricAvailable(with: .biometrics)
        guard context.biometryType != .none else {
            logger.error("\(#function) User face or fingerprint were not recognized")
            throw LocalAuthenticationError.biometricError
        }
        do {
            if try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: localizedReason) {
                return true
            }
        } catch {
            throw mapToLocalAuthenticationError(error, context: context)
        }
        return false
    }
    
    /// Retrieves the type of biometric authentication available on the device.
    /// - Returns: The available biometric type (.none, .touchID, .faceID, or .opticID if available).
    public func getBiometricType() async -> BiometricType {
        let result = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        logger.log("\(#function) evaluated policy with result \(result)")
        if context.biometryType == .none {
            return .none
        }
        if context.biometryType == .faceID {
            return .faceID
        }
        if context.biometryType == .touchID {
            return .touchID
        }
        if #available(iOS 17.0, macOS 14.0, *) {
            if context.biometryType == .opticID {
                return .opticID
            }
        }
        return .none
    }
    
    /// Maps an `Error` to a corresponding `LocalAuthenticationError` for consistent error handling.
    /// - Parameters:
    ///   - error: The original error thrown by the Local Authentication framework.
    ///   - context: The `LAContext` used during authentication.
    /// - Returns: A `LocalAuthenticationError` that represents the mapped error condition.
    func mapToLocalAuthenticationError(
        _ error: Error,
        context: LAContext
    ) -> LocalAuthenticationError {
        if let laError = error as? LAError {
            return handleLAError(laError, context: context)
        }
        /// Converts NSError from the LAError domain into a type-safe LAError and maps it to custom LocalAuthenticationError
        if let nsError = error as NSError?, nsError.domain == LAError.errorDomain {
            let laError = LAError(_nsError: nsError)
            logger.error("\(#function) Caught NSError with LAError domain: \(nsError.localizedDescription)")
            return handleLAError(laError, context: context)
        }
        logger.error("\(#function) Unknown error: \(error.localizedDescription)")
        return .error(error)
    }
    
    /// Maps an `LAError` to a corresponding `LocalAuthenticationError` using a direct switch statement.
    /// - Parameters:
    ///   - laError: The `LAError` received from the Local Authentication framework.
    ///   - context: The `LAContext` used during authentication.
    /// - Returns: `LocalAuthenticationError` that represents the equivalent error condition.
    // swiftlint:disable:next cyclomatic_complexity
    func handleLAError(_ laError: LAError, context: LAContext) -> LocalAuthenticationError {
        let localizedDescription = laError.localizedDescription
        switch laError.code {
        case .authenticationFailed:
            logger.error("User failed to provide valid credentials: \(localizedDescription)")
            return .authenticationFailed
        case .userCancel:
            logger.error("User canceled the authentication process: \(localizedDescription)")
            return .userCanceled
        case .userFallback:
            logger.error("User tapped fallback button: \(localizedDescription)")
            return .userFallback
        case .systemCancel:
            logger.error("System canceled authentication: \(localizedDescription)")
            return .systemCancel
        case .appCancel:
            logger.error("App canceled authentication: \(localizedDescription)")
            return .appCancel
        case .notInteractive:
            logger.error("Displaying UI forbidden: \(localizedDescription)")
            return .notInteractive
        case .biometryLockout:
            logger.error("Biometry locked due to too many failed attempts: \(localizedDescription)")
            return .biometryLockout
        case .passcodeNotSet:
            logger.error("Passcode not set: \(localizedDescription)")
            return .noPasscodeSet
        case .biometryNotAvailable:
            logger.error("Biometry not available: \(localizedDescription)")
            return .biometryNotAvailable
        case .invalidContext:
            logger.error("Authentication context is invalid: \(localizedDescription)")
            return .invalidContext
        case .biometryNotEnrolled:
            return handleBiometryNotEnrolledError(context: context, laError: laError)
#if os(macOS)
        case .biometryDisconnected:
            logger.error("Biometric accessory not connected: \(localizedDescription)")
            return .biometryDisconnected
        case .biometryNotPaired:
            logger.error("No paired biometric accessory: \(localizedDescription)")
            return .biometryNotPaired
        case .invalidDimensions:
            logger.error("Biometric sensor data has invalid dimensions: \(localizedDescription)")
            return .invalidDimensions
#endif
#if compiler(>=6.0)
        case .companionNotAvailable:
            if #available(iOS 18.0, *) {
                logger.error("Companion device not available: \(localizedDescription)")
                return .companionNotAvailable
            } else {
                logger.error("Unknown LAError: \(localizedDescription)")
                return .error(laError)
            }
#endif
        @unknown default:
            logger.error("Unknown LAError: \(localizedDescription)")
            return .error(laError)
            // .touchIDLockout (depricated)
            // .touchIDNotEnrolled (depricated)
            // .touchIDNotAvailable (depricated)
        }
    }
    
    /// Handles `.biometryNotEnrolled` errors by mapping them to specific biometric enrollment issues.
    /// - Parameters:
    ///   - context: The `LAContext` containing information about the current biometry type.
    ///   - laError: The `LAError` instance with the `.biometryNotEnrolled` code.
    /// - Returns: A `LocalAuthenticationError` indicating the missing biometric enrollment type.
    func handleBiometryNotEnrolledError(
        context: LAContext,
        laError: LAError
    ) -> LocalAuthenticationError {
        let localizedDescription = laError.localizedDescription
        switch context.biometryType {
        case .faceID:
            logger.error("No Face ID enrolled: \(localizedDescription)")
            return .noFaceIdEnrolled
        case .touchID:
            logger.error("No Touch ID enrolled: \(localizedDescription)")
            return .noFingerprintEnrolled
        default:
            logger.error("No biometrics enrolled: \(localizedDescription)")
            return .biometricError
        }
    }
}
