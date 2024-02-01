//
//  LocalAuthenticationProviderProtocol.swift
//  DealogX
//
//  Created by Mykhailo Bondarenko on 21.07.2022.
//

import Foundation

/// Defines the methods required for managing local authentication functionality.
public protocol LocalAuthenticationProviderProtocol {
    /// Checks if biometric authentication is available on the device.
    ///
    /// - Returns: `true` if biometric authentication is available, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during the check.
    func checkBiometricAvailable() async throws -> Bool
    
    /// Sets up biometric authentication with the given localized reason, preparing for authentication but not initiating it immediately.
    ///
    /// - Parameter localizedReason: A string explaining why authentication is being requested.
    /// - Returns: `true` if biometric authentication was successfully set up, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during setup.
    func setBiometricAuthentication(localizedReason: String) async throws -> Bool
    
    /// Authenticates the user using biometric authentication with the given localized reason.
    ///
    /// - Parameter localizedReason: A string explaining why authentication is being requested.
    /// - Returns: `true` if authentication was successful, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during authentication.
    ///
    func authenticate(localizedReason: String) async throws -> Bool
    
    /// Retrieves the type of biometric authentication available on the device.
    ///
    /// - Returns: The available biometric type (.none, .touchID, .faceID, or .opticID if available).
    func getBiometricType() async -> BiometricType
}
