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
//  MockLAContext.swift
//
//
//  Created by Mykhailo Bondarenko on 23.07.2022.
//

import Foundation
import LocalAuthentication

/// Mock implementation of `LAContext` for testing local authentication functionality.
final class MockLAContext: LAContext {
    /// Overrides the actual biometric type available on the device during testing.
    override var biometryType: LABiometryType {
        return _biometryType
    }
    
    private let successEvaluatePolicies: [LAPolicy]
    private var canEvaluatePolicyError: NSError?
    private let canEvaluatePolicies: [LAPolicy]
    private let _biometryType: LABiometryType
    private let evaluatePolicyError: Error?
    
    /// Initializes a new `MockLAContext` instance for testing.
    ///
    /// - Parameters:
    /// - successEvaluatePolicies: The policies that will return `true` when evaluated.
    /// - canEvaluatePolicyError: An error to return when `canEvaluatePolicy` is called, or `nil` for no error.
    /// - canEvaluatePolicies: The policies that `canEvaluatePolicy` will return `true` for.
    /// - biometryType: The biometric type to simulate.
    init(
        successEvaluatePolicies: [LAPolicy] = [],
        canEvaluatePolicyError: NSError? = nil,
        canEvaluatePolicies: [LAPolicy] = [],
        biometryType: LABiometryType = .none,
        evaluatePolicyError: Error? = nil
    ) {
        self.successEvaluatePolicies = successEvaluatePolicies
        self.canEvaluatePolicyError = canEvaluatePolicyError
        self.canEvaluatePolicies = canEvaluatePolicies
        self._biometryType = biometryType
        self.evaluatePolicyError = evaluatePolicyError
    }
    
    /// Overrides `canEvaluatePolicy` to simulate specific evaluation results for testing.
    ///
    /// - Parameters:
    /// - policy: The policy to check.
    /// - error: An optional error pointer to set if an error occurs.
    /// - Returns: `true` if the policy can be evaluated, `false` otherwise.
    override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        error?.pointee = canEvaluatePolicyError
        return canEvaluatePolicies.contains(policy)
    }
    
    /// Overrides `evaluatePolicy` to simulate specific authentication results for testing.
    ///
    /// - Parameters:
    /// - policy: The policy to evaluate.
    /// - localizedReason: The reason for authentication.
    /// - Returns: `true` if authentication is successful, `false` otherwise.
    override func evaluatePolicy(_ policy: LAPolicy, localizedReason: String) async throws -> Bool {
        if let error = evaluatePolicyError {
            throw error
        }
        return successEvaluatePolicies.contains(policy)
    }
}
