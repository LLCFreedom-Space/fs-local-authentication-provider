//
//  LocalAuthenticationPolicy+Extensions.swift
//
//
//  Created by Artem Panasenko on 19.01.2026.
//

import LocalAuthentication

extension LocalAuthenticationPolicy {
    var laPolicy: LAPolicy {
        switch self {
        case .authentication:
            return .deviceOwnerAuthentication
        case .biometrics:
            return .deviceOwnerAuthenticationWithBiometrics
#if os(macOS)
        case .watch:
            return .deviceOwnerAuthentication
        case .biometricsOrWatch:
            return .deviceOwnerAuthentication
#endif
        }
    }
}
