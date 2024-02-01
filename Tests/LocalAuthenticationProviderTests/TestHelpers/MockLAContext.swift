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
        biometryType: LABiometryType = .none
    ) {
        self.successEvaluatePolicies = successEvaluatePolicies
        self.canEvaluatePolicyError = canEvaluatePolicyError
        self.canEvaluatePolicies = canEvaluatePolicies
        self._biometryType = biometryType
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
        return successEvaluatePolicies.contains(policy)
    }
}
