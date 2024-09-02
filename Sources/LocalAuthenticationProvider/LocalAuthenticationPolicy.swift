//
//  LocalAuthenticationPolicy.swift
//
//
//  Created by Andriy Vasyk on 02.09.2024.
//

import Foundation

public enum LocalAuthenticationPolicy: Int {
    /// Device owner will be authenticated using a biometric method (Touch ID).
    case biometrics = 1

    /// Device owner will be authenticated by biometry or user password.
    case authentication = 2

    /// Device owner will be authenticated by Apple Watch.
    case watch = 3

    /// Device owner will be authenticated by biometry or Apple Watch.
    case biometricsOrWatch = 4
}
