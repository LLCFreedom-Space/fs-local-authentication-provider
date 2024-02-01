//
//  BiometricType.swift
//
//
//  Created by Mykhailo Bondarenko on 19.07.2022.
//

import Foundation

/// Represents the different types of biometric authentication available on a device.
public enum BiometricType {
    /// No biometric authentication is available.
    case none
    
    /// Facial recognition using Face ID.
    case faceID
    
    /// Fingerprint scanning using Touch ID.
    case touchID
    
    /// Iris recognition using Optic ID (available on iOS 17.0 and later).
    @available(iOS 17.0, macOS 14.0, *)
    case opticID
    
    /*
     public var description: String {
     switch self {
     case .none:
     return "No Biometrics"
     case .faceID:
     return "Face ID"
     case .touchID:
     return "Touch ID"
     case .opticID:
     return "Optic ID"
     }
     }
     */
}
