# SSKeychain

Since there is no Swift version of the SSKeychain tripartite library, I tried to do it myself.

## Cocoapods

```swift
pod 'SSKeychain_Swift'
```
or
```swift
pod 'SSKeychain_Swift', git: 'https://github.com/HumorousGhost/SSKeychain.git'
```

## Usage

```swift
import SSKeychain

private func keychain() {
    let arr = SSKeychain.allAccount()
    print("arr = \(arr)")
    
    let isSave = SSKeychain.setValue("123", service: "com.keychain", account: "admin")
    print("is save \(isSave)")
    
    let password = SSKeychain.value(service: "com.keychain", account: "admin")
    print("password \(password)")
    
    let arr2 = SSKeychain.allAccount(name: "com.keychain")
    print("arr2 = \(arr2)")
    
    let isSave2 = SSKeychain.setValue("456", service: "com.keychain", account: "admin")
    print("is save 2 = \(isSave2)")
    
    let password2 = SSKeychain.value(service: "com.keychain", account: "admin")
    print("password 2 = \(password2)")
}
```

## Installation

You can add SSKeychain to an Xcode project by adding it as a package dependency

* From the **File** menu, select **Swift Packages** -> **Add Package Dependency**...
* Enter https://github.com/HumorousGhost/SSKeychain into the package repository URL text field.
* Link **SSKeychain** to your application target.

