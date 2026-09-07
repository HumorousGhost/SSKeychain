import Foundation
import Security

public enum SSAccessibility {
    case whenUnlocked                       // Only when the device is unlocked
    case whenUnlockedThisDeviceOnly
    case afterFirstUnlock                   // The system will unlock for the first time after a reboot until the next reboot.
    case afterFirstUnlockThisDeviceOnly     // Same as above, but without backup or migration.
    case whenPasscodeSetThisDeviceOnly      // A password must have been set; the password will be automatically deleted after the user disables it.

    var rawValue: CFString {
        switch self {
        case .whenUnlocked:                    return kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly:      return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock:                return kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly:  return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly:   return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }
}
