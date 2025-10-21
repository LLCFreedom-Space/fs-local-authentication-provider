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
    
    /// Maps an `Error` to a corresponding `LocalAuthenticationError` for consistent error handling.
    /// - Parameters:
    ///   - error: The original error thrown by the Local Authentication framework.
    ///   - context: The `LAContext` used during authentication.
    ///   - function: The name of the calling function for detailed logging.
    /// - Returns: A `LocalAuthenticationError` that represents the mapped error condition.
    private func mapToLocalAuthenticationError(_ error: Error, context: LAContext, function: String) -> LocalAuthenticationError {
        if let laError = error as? LAError {
            return handleLAError(laError, context: context, function: function)
        }
        /// Converts NSError from the LAError domain into a type-safe LAError and maps it to custom LocalAuthenticationError
        if let nsError = error as NSError?, nsError.domain == LAError.errorDomain {
            let laError = LAError(_nsError: nsError)
            logger.error("\(function) Caught NSError with LAError domain: \(nsError.localizedDescription)")
            return handleLAError(laError, context: context, function: function)
        }
        logger.error("\(function) Unknown error: \(error.localizedDescription)")
        return .error(error)
    }
    
    /// Maps an `LAError` to a corresponding `LocalAuthenticationError` for consistent error handling.
    /// - Parameters:
    ///   - laError: The `LAError` received from the Local Authentication framework.
    ///   - context: The `LAContext` used during authentication.
    ///   - function: The name of the calling function for logging context.
    /// - Returns: `LocalAuthenticationError` that represents the equivalent error condition.
    private func handleLAError(_ laError: LAError, context: LAContext, function: String) -> LocalAuthenticationError {
        switch laError.code {
        case .authenticationFailed:
            return caseLogerReturn(.authenticationFailed, message: "The user failed to provide valid credentials", function: function, error: laError)
        case .userCancel:
            return caseLogerReturn(.userCanceled, message: "The user canceled the authentication process", function: function, error: laError)
        case .userFallback:
            return caseLogerReturn(.userFallback, message: "User tapped fallback button", function: function, error: laError)
        case .systemCancel:
            return caseLogerReturn(.systemCancel, message: "System canceled authentication", function: function, error: laError)
        case .appCancel:
            return caseLogerReturn(.appCancel, message: "App canceled authentication", function: function, error: laError)
        case .notInteractive:
            return caseLogerReturn(.notInteractive, message: "Displaying UI forbidden", function: function, error: laError)
        case .biometryLockout:
            return caseLogerReturn(.biometryLockout, message: "Biometry locked due to too many failed attempts", function: function, error: laError)
        case .biometryDisconnected:
            return caseLogerReturn(.biometryDisconnected, message: "Biometric accessory not connected", function: function, error: laError)
        case .passcodeNotSet:
            return caseLogerReturn(.noPasscodeSet, message: "Passcode not set", function: function, error: laError)
        case .biometryNotAvailable:
            return caseLogerReturn(.biometryNotAvailable, message: "Biometry not available", function: function, error: laError)
        case .biometryNotPaired:
            return caseLogerReturn(.biometryNotPaired, message: "No paired biometric accessory", function: function, error: laError)
        case .biometryNotEnrolled:
            return handleBiometryNotEnrolledError(context: context, laError: laError, function: function)
        default:
            return caseLogerReturn(.error(laError), message: "Unknown LAError", function: function, error: laError)
        }
    }
    
    /// Handles `.biometryNotEnrolled` errors by mapping them to specific biometric enrollment issues.
    /// - Parameters:
    ///   - context: The `LAContext` containing information about the current biometry type.
    ///   - laError: The `LAError` instance with the `.biometryNotEnrolled` code.
    ///   - function: The name of the calling function for contextual logging.
    /// - Returns: A `LocalAuthenticationError` indicating the missing biometric enrollment type.
    private func handleBiometryNotEnrolledError(context: LAContext, laError: LAError, function: String) -> LocalAuthenticationError {
        switch context.biometryType {
        case .faceID:
            return caseLogerReturn(.noFaceIdEnrolled, message: "No Face ID enrolled", function: function, error: laError)
        case .touchID:
            return caseLogerReturn(.noFingerprintEnrolled, message: "No Touch ID enrolled", function: function, error: laError)
        default:
            return caseLogerReturn(.biometricError, message: "No biometrics enrolled", function: function, error: laError)
        }
    }
    
    /// Logs the specified error message and returns the given `LocalAuthenticationError`.
    /// - Parameters:
    ///   - error: The `LocalAuthenticationError` to return.
    ///   - message: A descriptive message explaining the error context.
    ///   - function: The name of the calling function, used for structured logging.
    ///   - originalError: The original `Error` object for diagnostic information.
    /// - Returns: The same `LocalAuthenticationError` that was passed in.
    private func caseLogerReturn(
        _ error: LocalAuthenticationError,
        message: String,
        function: String,
        error originalError: Error
    ) -> LocalAuthenticationError {
        logger.error("\(function) \(message): \(originalError.localizedDescription)")
        return error
    }
}
