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
        case .watch:
            localPolicy = .deviceOwnerAuthenticationWithWatch
        case .biometrics:
            localPolicy = .deviceOwnerAuthenticationWithBiometrics
        case .biometricsOrWatch:
            localPolicy = .deviceOwnerAuthenticationWithBiometricsOrWatch
        }

        return self.canEvaluatePolicy(localPolicy, error: error)
    }
}
