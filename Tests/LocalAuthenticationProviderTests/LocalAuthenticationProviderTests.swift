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
@testable import LocalAuthenticationProvider

final class LocalAuthenticationProviderTests: XCTestCase {
    func testCanEvaluatePolicyWhenOwnerAuthenticatedWithBiometrics() async throws {
        let context = MockLAContext(canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics])
        let provider = LocalAuthenticationProvider(context: context)
        let checkBiometricsSuccess = try await provider.checkBiometricAvailable()
        XCTAssert(checkBiometricsSuccess)
    }
    
    func testCanEvaluatePolicyWhenOwnerNotAuthenticateWithBiometricsIssue() async throws {
        let result = try await provider.checkBiometricAvailable()
        XCTAssertFalse(result)
    }
    
    func testCanEvaluatePolicyWhenOwnerAlreadyAuthenticated() async throws {
        let context = MockLAContext(canEvaluatePolicies: [.deviceOwnerAuthentication])
        let provider = LocalAuthenticationProvider(context: context)
        let checkBiometricsSuccess = try await provider.checkBiometricAvailable()
        XCTAssert(checkBiometricsSuccess)
    }
    
    func testCanEvaluatePolicyWhenAccessDenied() async {
        let errorCode = LocalAuthenticationError.denied
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode))
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.deniedAccess {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }
    
    func testCanEvaluatePolicyWhenPasscodeNotSet() async {
        let errorCode = LocalAuthenticationError.passcodeNotSet
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode))
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable()
            XCTFail(".noPasscodeSet error must be thrown")
        } catch LocalAuthenticationError.noPasscodeSet {
        } catch {
            XCTFail("Unexpected error thrown - must be .noPasscodeSet")
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsIssue() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode))
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.biometricError {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsFaceIDFails() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode), biometryType: .faceID)
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.noFaceIdEnrolled {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsTouchIDFails() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode), biometryType: .touchID)
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.noFingerprintEnrolled {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }
    
    func testCanEvaluatePolicyWhenUnknownError() async {
        let errorCode = LocalAuthenticationError.unknownError
        let expectedError = NSError(domain: "", code: errorCode)
        let context = MockLAContext(canEvaluatePolicyError: expectedError)
        let provider = LocalAuthenticationProvider(context: context)
        do {
            _ = try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch LocalAuthenticationError.error(let error) {
            XCTAssertEqual(error as NSError, expectedError)
        } catch {
            XCTFail("Unexpected error thrown")
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
        let failedResult = try await provider.setBiometricAuthentication(
            localizedReason: "Please authenticate yourself for activate Biometric authentication"
        )
        XCTAssertFalse(failedResult)
    }
    
    func testEvaluatePolicyWhenBiometricsSetFailed() async throws {
        let context = MockLAContext(canEvaluatePolicies: [.deviceOwnerAuthenticationWithBiometrics])
        let provider = LocalAuthenticationProvider(context: context)
        let failedResult = try await provider.setBiometricAuthentication(
            localizedReason: "Please authenticate yourself for activate Biometric authentication"
        )
        XCTAssertFalse(failedResult)
    }
    
    func testAuthenticateWhenFailCheck() async throws {
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
            XCTFail("Unexpected error thrown")
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
}
