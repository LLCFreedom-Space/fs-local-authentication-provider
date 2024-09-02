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
//  LocalAuthenticationError.swift
//
//
//  Created by Mykhailo Bondarenko on 19.07.2022.
//

import Foundation

/// Represents errors that can occur during local authentication.
public enum LocalAuthenticationError: Error {
    // MARK: - Error codes for common local authentication errors.
    
    /// -5, LAError.Code.passcodeNotSet
    public static let passcodeNotSet: Int = -5
    
    /// -6, LAError.Code.biometryNotAvailable
    public static let denied: Int = -6
    
    /// -7, LAError.Code.biometryNotEnrolled
    public static let noBiometricsEnrolled: Int = -7
    
    /// 0
    public static let unknownError: Int = 0
    
    /// The user canceled the authentication process.
    case userCanceled
    
    /// A general biometric error occurred.
    case biometricError
    
    /// Access to local authentication was denied.
    case deniedAccess
    
    /// No Face ID is enrolled on the device.
    case noFaceIdEnrolled
    
    /// No fingerprints are enrolled on the device.
    case noFingerprintEnrolled
    
    /// A passcode isn’t set on the device.
    case noPasscodeSet
    
    /// An underlying error occurred.
    ///
    /// - Parameter error: The underlying error.
    case error(_ error: Error)
}
