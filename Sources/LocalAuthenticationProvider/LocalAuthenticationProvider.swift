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
    @discardableResult public func checkBiometricAvailable() async throws -> Bool {
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return true
        } else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            return true
        } else {
            if let error {
                switch error.code {
                case LocalAuthenticationError.denied:
                    logger.error("\(#file) \(#function) Denied access on local authentication with: \(error.localizedDescription)")
                    throw LocalAuthenticationError.deniedAccess
                case LocalAuthenticationError.noBiometricsEnrolled:
                    if context.biometryType == .faceID {
                        logger.error("\(#file) \(#function) Denied access on face id with: \(error.localizedDescription)")
                        throw LocalAuthenticationError.noFaceIdEnrolled
                    } else if context.biometryType == .touchID {
                        logger.error("\(#file) \(#function) Denied access on touch id with: \(error.localizedDescription)")
                        throw LocalAuthenticationError.noFingerprintEnrolled
                    } else {
                        logger.error("\(#file) \(#function) Local Authentication Error: \(error.localizedDescription)")
                        throw LocalAuthenticationError.biometricError
                    }
                default:
                    logger.error("\(#file) \(#function) Local Authentication Error: \(error.localizedDescription)")
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
    @discardableResult public func authenticate(localizedReason: String) async throws -> Bool {
        if try await checkBiometricAvailable() {
            guard context.biometryType != .none else {
                logger.error("\(#file) \(#function) User face or fingerprint were not recognized")
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
            
            logger.error("\(#file) \(#function) User face or fingerprint were not recognized")
            return false
        } else {
            return false
        }
    }
    
    /// Retrieves the type of biometric authentication available on the device.
    /// - Returns: The available biometric type (.none, .touchID, .faceID, or .opticID if available).
    public func getBiometricType() async -> BiometricType {
        let result = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        logger.log("\(#file) \(#function) evaluated policy with result \(result)")
        switch context.biometryType {
        case .none:
            return .none
        case .touchID:
            return .touchID
        case .faceID:
            return .faceID
        case .opticID:
            if #available(iOS 17.0, *) {
                return .opticID
            } else {
                return .none
            }
        @unknown default:
            return .none
        }
    }
}
