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
                throw mapToLocalAuthenticationError(error, context: context, function: #function)
            } else {
                throw mapToLocalAuthenticationError(
                    NSError(
                        domain: LAError.errorDomain,
                        code: LocalAuthenticationError.unknownError,
                        userInfo: nil
                    ),
                    context: context,
                    function: #function
                )
            }
        }
    }
    
    /// Sets up biometric authentication with the given localized reason, preparing for authentication but not initiating it immediately.
    /// - Parameter localizedReason: A string explaining why authentication is being requested.
    /// - Returns: `true` if biometric authentication was successfully set up, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during setup.
    public func setBiometricAuthentication(localizedReason: String) async throws -> Bool {
        if try await checkBiometricAvailable(with: .biometrics) {
            do {
                return try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: localizedReason)
            } catch {
                throw mapToLocalAuthenticationError(error, context: context, function: #function)
            }
        } else {
            return false
        }
    }
    
    /// Authenticates the user using biometric authentication with the given localized reason.
    /// - Parameter localizedReason: A string explaining why authentication is being requested.
    /// - Returns: `true` if authentication was successful, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during authentication.
    public func authenticate(localizedReason: String) async throws -> Bool {
        if try await checkBiometricAvailable(with: .biometrics) {
            guard context.biometryType != .none else {
                logger.error("\(#function) User face or fingerprint were not recognized")
                throw LocalAuthenticationError.biometricError
            }
            
            do {
                if try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: localizedReason) {
                    return true
                }
            } catch {
                throw mapToLocalAuthenticationError(error, context: context, function: #function)
            }
            logger.error("\(#function) User face or fingerprint were not recognized")
            return false
        } else {
            return false
        }
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
    
    /// Maps an `LAError` to a corresponding `LocalAuthenticationError` for consistent error handling.
    /// - Parameter laError: The `LAError` received from the Local Authentication framework.
    /// - Returns: `LocalAuthenticationError` that represents the equivalent error condition.
    private func mapToLocalAuthenticationError(
        _ error: Error,
        context: LAContext,
        function: String
    ) -> LocalAuthenticationError {
        if let laError = error as? LAError {
            switch laError.code {
            case .authenticationFailed:
                logger.error("\(function) The user failed to provide valid credentials: \(laError.localizedDescription)")
                return .authenticationFailed
            case .userCancel:
                logger.error("\(function) The user canceled the authentication process: \(laError.localizedDescription)")
                return .userCanceled
            case .userFallback:
                logger.error("\(function) The user tapped the fallback button in the authentication dialog, but no fallback is available for the authentication policy: \(laError.localizedDescription)")
                return .userFallback
            case .systemCancel:
                logger.error("\(function) The system canceled authentication: \(laError.localizedDescription)")
                return .systemCancel
            case .appCancel:
                logger.error("\(function) The app canceled authentication: \(laError.localizedDescription)")
                return .appCancel
            case .notInteractive:
                logger.error("\(function) Displaying the required authentication user interface is forbidden: \(laError.localizedDescription)")
                return .notInteractive
            case .biometryLockout:
                logger.error("\(function) Biometry is locked because there were too many failed attempts: \(laError.localizedDescription)")
                return .biometryLockout
            case .biometryDisconnected:
                logger.error("\(function) The device supports biometry only using a removable accessory, but the paired accessory isn’t connected: \(laError.localizedDescription)")
                return .biometryDisconnected
            case .passcodeNotSet:
                logger.error("\(function) Passcode not set: \(laError.localizedDescription)")
                return .noPasscodeSet
            case .biometryNotAvailable:
                logger.error("\(function) Biometry not available: \(laError.localizedDescription)")
                return .biometryNotAvailable
            case .biometryNotPaired:
                logger.error("\(function) The device supports biometry only using a removable accessory, but no accessory is paired: \(laError.localizedDescription)")
                return .biometryNotPaired
            case .biometryNotEnrolled:
                switch context.biometryType {
                case .faceID:
                    logger.error("\(function) No Face ID is enrolled on the device: \(laError.localizedDescription)")
                    return .noFaceIdEnrolled
                case .touchID:
                    logger.error("\(function) No fingerprints are enrolled on the device: \(laError.localizedDescription)")
                    return .noFingerprintEnrolled
                default:
                    logger.error("\(function) No biometrics enrolled: \(laError.localizedDescription)")
                    return .biometricError
                }
            default:
                logger.error("\(function) Unknown LAError: \(laError.localizedDescription)")
                return .error(laError)
            }
        }
        /// Converts NSError from the LAError domain into a type-safe LAError and maps it to custom LocalAuthenticationError
        if let nsError = error as NSError?, nsError.domain == LAError.errorDomain {
            let laError = LAError(_nsError: nsError)
            logger.error("\(function) Caught NSError with LAError domain: \(nsError.localizedDescription)")
            return mapToLocalAuthenticationError(laError, context: context, function: function)
        }
        logger.error("\(function) Unknown error: \(error.localizedDescription)")
        return .error(error)
    }
}
