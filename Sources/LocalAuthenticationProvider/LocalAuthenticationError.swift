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
    
    /// -6
    public static let denied: Int = -6
    
    /// -7
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
    
    /// An underlying error occurred.
    ///
    /// - Parameter error: The underlying error.
    case error(_ error: Error)
}
