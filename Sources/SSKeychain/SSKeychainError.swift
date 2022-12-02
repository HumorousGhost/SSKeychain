//
//  SSKeychainError.swift
//  
//
//  Created by Liqun Zhang on 2022/12/2.
//

import Foundation

public enum SSKeychainError: Error {
    case itemNotFound
    case duplicateItem
    case invalidItemFormat
    case unexpectedStatus(OSStatus)
}
