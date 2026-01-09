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
//  LocalAuthProviderLAErrorCasesTests.swift
//
//
//  Created by Mykola Vasyk on 30.10.2025.
//

import XCTest
import LocalAuthentication
@testable import LocalAuthenticationProvider

final class LocalAuthProviderLAErrorCasesTests: XCTestCase {
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
    
    func testMapToLocalAuthenticationErrorGenericNSError() async {
        let customNSErrorCode = 111
        let nsError = NSError(domain: "CustomDomain", code: customNSErrorCode)
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
            XCTAssertEqual((error as NSError).code, customNSErrorCode)
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
}
