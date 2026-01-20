//
//  LAContext+Extensions.swift
//
//
//  Created by Andriy Vasyk on 02.09.2024.
//

import Foundation
import LocalAuthentication

extension LAContext {
    internal func canEvaluate(policy: LocalAuthenticationPolicy, error: NSErrorPointer) -> Bool {
        return self.canEvaluatePolicy(policy.laPolicy, error: error)
    }
    
    /// Resolves the biometric type supported by the current context.
    var resolvedBiometricType: BiometricType {
        if biometryType == .none {
            return .none
        }
        if biometryType == .faceID {
            return .faceID
        }
        if biometryType == .touchID {
            return .touchID
        }
        if #available(iOS 17.0, macOS 14.0, *) {
            if biometryType == .opticID {
                return .opticID
            }
        }
        return .none
    }
}
