import Foundation
import Security

public struct SSKeychain {
    
    /// get keychain all account
    /// - Parameter name: service name, default ""
    /// - Returns: Array<String>
    public static func allAccount(name: String = "", accessibility: SSAccessibility = .whenUnlocked) -> [String] {
        do {
            return try self.allAccounts(service: name, accessibility: accessibility)
        } catch {
            return []
        }
    }
    
    /// get keychain all account, will throw an exception
    /// - Parameter name: service name, default ""
    /// - Returns: Array<String>
    public static func allAccounts(service name: String = "", accessibility: SSAccessibility = .whenUnlocked) throws -> [String] {
        var query: [String: AnyObject] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnData as String: kCFBooleanTrue,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrAccessible as String: accessibility.rawValue
        ]
        
        if !name.isEmpty {
            query[kSecAttrService as String] = name as AnyObject
        }
        
        var itemCopy: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &itemCopy)
        
        if status == errSecDuplicateItem {
            throw SSKeychainError.duplicateItem
        }
        
        guard status == errSecSuccess else {
            throw SSKeychainError.unexpectedStatus(status)
        }
        
        guard let value = itemCopy else {
            throw SSKeychainError.invalidItemFormat
        }
        
        if value is Array<Any> {
            return (value as! Array<Any>).map {
                if $0 is Data {
                    return String(data: $0 as! Data, encoding: .utf8)!
                } else {
                    return ""
                }
            }
        }
        
        if value is Data {
            return [String(data: value as! Data, encoding: .utf8)!]
        }
        
        return []
    }
    
    /// Get value content according to service name and account
    /// - Parameters:
    ///   - name: service name
    ///   - account: account
    /// - Returns: String
    public static func value(service name: String, account: String, accessibility: SSAccessibility = .whenUnlocked) -> String {
        if let data = self.value(data: name, account: account, accessibility: accessibility) {
            return String(data: data, encoding: .utf8) ?? ""
        }
        return ""
    }
    
    /// Get value content according to service name and account
    /// - Parameters:
    ///   - name: service name
    ///   - account: account
    /// - Returns: Data?
    public static func value(data name: String, account: String, accessibility: SSAccessibility = .whenUnlocked) -> Data? {
        do {
            let data: Data = try value(data: name, account: account, accessibility: accessibility)
            return data
        } catch {}
        return nil
    }
    
    /// Get value content according to service name and account, will throw an exception
    /// - Parameters:
    ///   - name: service
    ///   - account: account
    /// - Returns: Data
    public static func value(data name: String, account: String, accessibility: SSAccessibility = .whenUnlocked) throws -> Data {
        let query: [String: AnyObject] = [
            kSecAttrService as String: name as AnyObject,
            kSecAttrAccount as String: account as AnyObject,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: kCFBooleanTrue,
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: accessibility.rawValue
        ]
        
        var itemCopy: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &itemCopy)
        
        if status == errSecDuplicateItem {
            throw SSKeychainError.duplicateItem
        }
        
        guard status == errSecSuccess else {
            throw SSKeychainError.unexpectedStatus(status)
        }
        
        guard let data = itemCopy as? Data else {
            throw SSKeychainError.invalidItemFormat
        }
        
        return data
    }
    
    /// Delete values based on service name and account
    /// - Parameters:
    ///   - name: service name
    ///   - account: account
    /// - Returns: Bool, Is it deleted successfully
    public static func delete(name: String, account: String, accessibility: SSAccessibility = .whenUnlocked) -> Bool {
        do {
            return try self.delete(service: name, account: account, accessibility: accessibility)
        } catch {}
        return false
    }
    
    /// Delete values based on service name and account, will throw an exception
    /// - Parameters:
    ///   - name: service name
    ///   - account: account
    /// - Returns: Bool, Is it deleted successfully
    public static func delete(service name: String, account: String, accessibility: SSAccessibility = .whenUnlocked) throws -> Bool {
        let query = [
            kSecAttrService as String: name as AnyObject,
            kSecAttrAccount as String: account as AnyObject,
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: accessibility.rawValue
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SSKeychainError.unexpectedStatus(status)
        }
        
        return true
    }
    
    @discardableResult
    /// Set value according to service name and account. If there is a value, modify the value
    /// - Parameters:
    ///   - value: value, String type
    ///   - name: service name
    ///   - account: account
    /// - Returns: Bool, Is it successfully set
    public static func setValue(_ value: String, service name: String, account: String, accessibility: SSAccessibility = .whenUnlocked) -> Bool {
        if let data = value.data(using: .utf8) {
            return self.setValue(data: data, service: name, account: account, accessibility: accessibility)
        }
        return false
    }
    
    @discardableResult
    /// Set value according to service name and account. If there is a value, modify the value
    /// - Parameters:
    ///   - data: value, Data type
    ///   - name: service name
    ///   - account: account
    /// - Returns: Bool, Is it successfully set
    public static func setValue(data: Data, service name: String, account: String, accessibility: SSAccessibility = .whenUnlocked) -> Bool {
        do {
            return try setValue(data, service: name, account: account, accessibility: accessibility)
        } catch {}
        return false
    }
    
    @discardableResult
    /// Set value according to service name and account, will throw an exception. If there is a value, modify the value
    /// - Parameters:
    ///   - data: data, Data Type
    ///   - name: service name
    ///   - account: account
    /// - Returns: Bool, Is it successfully set
    public static func setValue(_ data: Data, service name: String, account: String, accessibility: SSAccessibility = .whenUnlocked) throws -> Bool {
        var query = [
            kSecAttrService as String: name as AnyObject,
            kSecAttrAccount as String: account as AnyObject,
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: accessibility.rawValue
        ]
        let value: Data? = self.value(data: name, account: account, accessibility: accessibility)
        if value == data {
            return true
        }
        var status: OSStatus!
        if value == nil || value!.isEmpty {
            query[kSecValueData as String] = data as AnyObject
            status = SecItemAdd(query as CFDictionary, nil)
        } else {
            let attributes = [
                kSecValueData as String: data as AnyObject
            ]
            status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        }
        if status == errSecDuplicateItem {
            throw SSKeychainError.duplicateItem
        }
        
        guard status == errSecSuccess else {
            throw SSKeychainError.unexpectedStatus(status)
        }
        return true
    }
}
