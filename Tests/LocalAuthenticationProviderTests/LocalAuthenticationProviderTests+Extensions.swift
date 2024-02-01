//
//  LocalAuthenticationProviderTests+Extensions.swift
//
//
//  Created by Mykhailo Bondarenko on 31.01.2024.
//

import Foundation
import LocalAuthenticationProvider

extension LocalAuthenticationProviderTests {
    var provider: LocalAuthenticationProvider {
        LocalAuthenticationProvider(context: MockLAContext())
    }
}
