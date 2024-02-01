//
//  LocalAuthenticationProviderTests.swift
//
//
//  Created by Mykhailo Bondarenko on 23.07.2022.
//

import XCTest
@testable import LocalAuthenticationProvider

final class LocalAuthenticationProviderTests: XCTestCase {
    func testCanEvaluatePolicyWhenOwnetAuthenticatedWithBiometrics() async throws {
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
            try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch {
            XCTAssertEqual(LocalAuthenticationError.deniedAccess.localizedDescription, error.localizedDescription)
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsIssue() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode))
        let provider = LocalAuthenticationProvider(context: context)
        do {
            try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch {
            XCTAssertEqual(LocalAuthenticationError.biometricError.localizedDescription, error.localizedDescription)
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsFaceIDFails() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode), biometryType: .faceID)
        let provider = LocalAuthenticationProvider(context: context)
        do {
            try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch {
            XCTAssertEqual(LocalAuthenticationError.noFaceIdEnrolled.localizedDescription, error.localizedDescription)
        }
    }
    
    func testCanEvaluatePolicyWhenBiometricsTouchIDFails() async {
        let errorCode = LocalAuthenticationError.noBiometricsEnrolled
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode), biometryType: .touchID)
        let provider = LocalAuthenticationProvider(context: context)
        do {
            try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch {
            XCTAssertEqual(LocalAuthenticationError.noFingerprintEnrolled.localizedDescription, error.localizedDescription)
        }
    }
    
    func testCanEvaluatePolicyWhenUnknownError() async {
        let errorCode = LocalAuthenticationError.unknownError
        let context = MockLAContext(canEvaluatePolicyError: NSError(domain: "", code: errorCode))
        let provider = LocalAuthenticationProvider(context: context)
        do {
            try await provider.checkBiometricAvailable()
            XCTFail("Error must be thrown")
        } catch {
            XCTAssertEqual(LocalAuthenticationError.biometricError.localizedDescription, error.localizedDescription)
        }
    }
    
    func testEvaluatePolicyWhenBiometricsSetSuccesful() async throws {
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
        let manager = LocalAuthenticationProvider(context: context)
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
            try await provider.authenticate(localizedReason: "")
            XCTFail("Error must be thrown")
        } catch {
            XCTAssertEqual(LocalAuthenticationError.biometricError.localizedDescription, error.localizedDescription)
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
    }
}
