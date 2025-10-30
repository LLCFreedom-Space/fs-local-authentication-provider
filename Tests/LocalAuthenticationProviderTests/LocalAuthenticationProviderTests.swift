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
//  LocalAuthenticationProviderTests.swift
//
//
//  Created by Mykhailo Bondarenko on 23.07.2022.
//

import XCTest
import LocalAuthentication
@testable import LocalAuthenticationProvider

final class LocalAuthenticationProviderTests: XCTestCase {
    func testCanEvaluatePolicyWhenOwnerAuthenticatedWithBiometrics() async throws {
        let context = MockLAContext(canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics])
        let provider = LocalAuthenticationProvider(context: context)
        let checkBiometricsSuccess = try await provider.checkBiometricAvailable(with: .biometrics)
        XCTAssert(checkBiometricsSuccess)
    }
    
    func testCanEvaluatePolicyWhenOwnerNotAuthenticateWithBiometricsIssue() async throws {
        let errorCode = LocalAuthenticationError.unknownError
        let context = MockLAContext(
            canEvaluatePolicyError: NSError(domain: LAError.errorDomain, code: errorCode)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable(with: .biometrics)
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.error(let thrownError) {
            XCTAssertEqual((thrownError as NSError).code, errorCode)
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testCanEvaluatePolicyWhenOwnerAlreadyAuthenticated() async throws {
        let context = MockLAContext(canEvaluatePolicies: [.deviceOwnerAuthentication])
        let provider = LocalAuthenticationProvider(context: context)
        let checkBiometricsSuccess = try await provider.checkBiometricAvailable(with: .authentication)
        XCTAssert(checkBiometricsSuccess)
    }
    
    func testCanEvaluatePolicyWhenAccessDenied() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.authenticationFailed)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.authenticationFailed {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testCanEvaluatePolicyWhenPasscodeNotSet() async {
        let errorCode = LocalAuthenticationError.passcodeNotSet
        let context = MockLAContext(
            canEvaluatePolicyError: NSError(domain: LAError.errorDomain, code: errorCode)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable(with: .biometrics)
            XCTFail(".noPasscodeSet error must be thrown")
        } catch LocalAuthenticationError.noPasscodeSet {
        } catch {
            XCTFail("Unexpected error thrown: \(error), - must be .noPasscodeSet")
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsIssue() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(
            canEvaluatePolicyError: NSError(domain: LAError.errorDomain, code: errorCode)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable(with: .biometrics)
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.biometricError {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsFaceIDFails() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(
            canEvaluatePolicyError: NSError(domain: LAError.errorDomain, code: errorCode),
            biometryType: .faceID
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable(with: .biometrics)
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.noFaceIdEnrolled {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsTouchIDFails() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(
            canEvaluatePolicyError: NSError(domain: LAError.errorDomain, code: errorCode),
            biometryType: .touchID
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable(with: .biometrics)
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.noFingerprintEnrolled {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testCanEvaluatePolicyWhenUnknownError() async {
        let errorCode = LocalAuthenticationError.unknownError
        let expectedError = NSError(domain: LAError.errorDomain, code: errorCode)
        let context = MockLAContext(canEvaluatePolicyError: expectedError)
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable(with: .biometrics)
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.error(let error) {
            XCTAssertEqual(error as NSError, expectedError)
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testEvaluatePolicyWhenBiometricsSetSuccessful() async throws {
        let context = MockLAContext(
            successEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics])
        let provider = LocalAuthenticationProvider(context: context)
        let successResult = try await provider.setBiometricAuthentication(
            localizedReason: "Please authenticate yourself for activate Biometric authentication"
        )
        XCTAssert(successResult)
    }
    
    func testEvaluatePolicyWhenCheckFailed() async throws {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics]
        )
        let provider = LocalAuthenticationProvider(context: context)
        let failedResult = try await provider.setBiometricAuthentication(
            localizedReason: "Please authenticate yourself for activate Biometric authentication"
        )
        XCTAssertFalse(failedResult)
    }
    
    func testAuthenticateWhenFailCheck() async throws {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID
        )
        let provider = LocalAuthenticationProvider(context: context)
        let failedResult = try await provider.authenticate(
            localizedReason: "Please authenticate yourself for activate Biometric authentication"
        )
        XCTAssertFalse(failedResult)
    }
    
    func testAuthenticationWhenFailCheckBiometryType() async throws {
        let context = MockLAContext(canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics])
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.biometricError {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testAuthenticationWhenSuccessCheckBiometryType() async throws {
        let context = MockLAContext(
            successEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID)
        let provider = LocalAuthenticationProvider(context: context)
        let successResult = try await provider.authenticate(
            localizedReason: "Please authenticate yourself for activate Biometric authentication"
        )
        XCTAssert(successResult)
    }
    
    func testAuthenticationWhenFailedEvaluatePolicy() async throws {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID)
        let provider = LocalAuthenticationProvider(context: context)
        let failedResult = try await provider.authenticate(
            localizedReason: "Please authenticate yourself for activate Biometric authentication"
        )
        XCTAssertFalse(failedResult)
    }
    
    func testGetBiometryTypeWhenSuccess() async throws {
        var context = MockLAContext(biometryType: .none)
        var provider = LocalAuthenticationProvider(context: context)
        let nonType = await provider.getBiometricType()
        
        XCTAssert(nonType == .none)
        
        context = MockLAContext(biometryType: .faceID)
        provider = LocalAuthenticationProvider(context: context)
        let faceIDType = await provider.getBiometricType()
        XCTAssert(faceIDType == .faceID)
        
        context = MockLAContext(biometryType: .touchID)
        provider = LocalAuthenticationProvider(context: context)
        let touchIDType = await provider.getBiometricType()
        XCTAssert(touchIDType == .touchID)
        if #available(iOS 17.0, macOS 14.0, *) {
            context = MockLAContext(biometryType: .opticID)
            provider = LocalAuthenticationProvider(context: context)
            let opticIDType = await provider.getBiometricType()
            XCTAssert(opticIDType == .opticID)
        }
    }
    
    func testMapToLocalAuthenticationErrorUserCancel() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.userCancel)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.userCanceled {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorUserFallback() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.userFallback)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.userFallback {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorSystemCancel() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.systemCancel)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.systemCancel {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorAppCancel() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.appCancel)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.appCancel {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorNotInteractive() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.notInteractive)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.notInteractive {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorBiometryLockout() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.biometryLockout)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.biometryLockout {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorBiometryDisconnected() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.biometryDisconnected)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.biometryDisconnected {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorBiometryNotAvailable() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.biometryNotAvailable)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.biometryNotAvailable {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorBiometryNotPaired() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.biometryNotPaired)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.biometryNotPaired {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorInvalidContext() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.invalidContext)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.invalidContext {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorInvalidDimensions() async {
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: LAError(.invalidDimensions)
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.invalidDimensions {
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
    
    func testMapToLocalAuthenticationErrorGenericNSError() async {
        let nsError = NSError(domain: "CustomDomain", code: 111)
        let context = MockLAContext(
            canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics],
            biometryType: .faceID,
            evaluatePolicyError: nsError
        )
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.authenticate(localizedReason: "Test")
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.error(let error) {
            XCTAssertEqual((error as NSError).domain, "CustomDomain")
            XCTAssertEqual((error as NSError).code, 111)
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
}
