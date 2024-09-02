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
    /// - Parameter policy: The policy to evaluate.
    /// - Returns: `true` if biometric authentication is available, `false` otherwise.
    /// - Throws: An appropriate `LocalAuthenticationError` if an error occurs during the check.
    func checkBiometricAvailable(with policy: LocalAuthenticationPolicy) async throws -> Bool
    
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
    func authenticate(localizedReason: String) async throws -> Bool
    
    /// Retrieves the type of biometric authentication available on the device.
    ///
    /// - Returns: The available biometric type (.none, .touchID, .faceID, or .opticID if available).
    func getBiometricType() async -> BiometricType
}
