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
    /// - Returns: `true` if biometric authentication is available, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during the check.
    public func checkBiometricAvailable() async throws -> Bool {
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return true
        } else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            return true
        } else {
            if let error {
                switch error.code {
                case LocalAuthenticationError.denied:
                    logger.error("\(#function) Denied access on local authentication with: \(error.localizedDescription)")
                    throw LocalAuthenticationError.deniedAccess
                case LocalAuthenticationError.noBiometricsEnrolled:
                    if context.biometryType == .faceID {
                        logger.error("\(#function) Denied access on face id with: \(error.localizedDescription)")
                        throw LocalAuthenticationError.noFaceIdEnrolled
                    } else if context.biometryType == .touchID {
                        logger.error("\(#function) Denied access on touch id with: \(error.localizedDescription)")
                        throw LocalAuthenticationError.noFingerprintEnrolled
                    } else {
                        logger.error("\(#function) Local Authentication Error: \(error.localizedDescription)")
                        throw LocalAuthenticationError.biometricError
                    }
                default:
                    logger.error("\(#function) Local Authentication Error: \(error.localizedDescription)")
                    throw LocalAuthenticationError.biometricError
                }
            }
            return false
        }
    }
    
    /// Sets up biometric authentication with the given localized reason, preparing for authentication but not initiating it immediately.
    /// - Parameter localizedReason: A string explaining why authentication is being requested.
    /// - Returns: `true` if biometric authentication was successfully set up, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during setup.
    public func setBiometricAuthentication(localizedReason: String) async throws -> Bool {
        if try await checkBiometricAvailable() {
            return try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: localizedReason)
        } else {
            return false
        }
    }
    
    /// Authenticates the user using biometric authentication with the given localized reason.
    /// - Parameter localizedReason: A string explaining why authentication is being requested.
    /// - Returns: `true` if authentication was successful, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during authentication.
    public func authenticate(localizedReason: String) async throws -> Bool {
        if try await checkBiometricAvailable() {
            guard context.biometryType != .none else {
                logger.error("\(#function) User face or fingerprint were not recognized")
                throw LocalAuthenticationError.biometricError
            }
            
            do {
                if try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: localizedReason) {
                    return true
                }
            } catch LAError.userCancel {
                throw LocalAuthenticationError.userCanceled
            } catch {
                throw error
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
}
