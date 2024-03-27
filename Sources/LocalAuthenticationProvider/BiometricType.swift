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
//  BiometricType.swift
//
//
//  Created by Mykhailo Bondarenko on 19.07.2022.
//

import Foundation
import LocalAuthentication

/// Represents the different types of biometric authentication available on a device.
public enum BiometricType: String {
    /// No biometric authentication is available.
    case none
    
    /// Facial recognition using Face ID.
    case faceID
    
    /// Fingerprint scanning using Touch ID.
    case touchID
    
    /// Iris recognition using Optic ID (available on iOS 17.0 and later).
    @available(iOS 17.0, macOS 14.0, *)
    case opticID
}
