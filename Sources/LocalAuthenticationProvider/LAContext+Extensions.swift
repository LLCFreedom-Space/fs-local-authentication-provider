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
        let localPolicy: LAPolicy
        switch policy {
        case .authentication:
            localPolicy = .deviceOwnerAuthentication
        case .biometrics:
            localPolicy = .deviceOwnerAuthenticationWithBiometrics
#if os(macOS)
        case .watch:
            localPolicy = .deviceOwnerAuthenticationWithWatch
        case .biometricsOrWatch:
            localPolicy = .deviceOwnerAuthenticationWithBiometricsOrWatch
#endif
        }

        return self.canEvaluatePolicy(localPolicy, error: error)
    }
}
