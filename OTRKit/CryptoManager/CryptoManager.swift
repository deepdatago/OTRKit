//
//  CryptoManager.swift
//  OTRKit
//
//  Created by tnnd on 6/23/18.
//

import Foundation
import RNCryptor

@objc public class CryptoManager: NSObject {
    @objc public static func decryptDataWithSymmetricKey(key:NSString, base64Input:NSString) -> NSString! {
        let inputStr = base64Input as String
        NSLog("encrypted string: \((inputStr))")
        let inputData = Data(base64Encoded: inputStr)!
        let keyData = (key as String).data(using: .utf8)!
        
        let decryptedData = aesCBCDecrypt(data:inputData, keyData:keyData)!
        return String(data: decryptedData, encoding: String.Encoding.utf8)! as NSString
    }
    
    @objc public static func encryptDataWithSymmetricKey(key:NSString, input:NSString) -> NSString! {
        let inputData = (input as String).data(using: .utf8)!
        let keyData = (key as String).data(using: .utf8)!
        return aesCBCEncrypt(data:inputData, keyData:keyData)!.base64EncodedString() as NSString
    }

    private static func aesCBCDecrypt(data:Data, keyData:Data) -> Data? {
        let keyLength = keyData.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            return nil
        }
        
        // let ivSize = kCCBlockSizeAES128;
        let clearLength = size_t(data.count)
        var clearData = Data(count:clearLength)
        
        var numBytesDecrypted :size_t = 0
        let options   = CCOptions(kCCOptionPKCS7Padding + kCCOptionECBMode)
        
        let cryptStatus = clearData.withUnsafeMutableBytes {cryptBytes in
            data.withUnsafeBytes {dataBytes in
                keyData.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            options,
                            keyBytes, keyLength,
                            dataBytes,
                            dataBytes, clearLength,
                            cryptBytes, clearLength,
                            &numBytesDecrypted)
                }
            }
        }
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            clearData.count = numBytesDecrypted
        }
        else {
            return nil
        }
        
        return clearData;
    }
    
    private static func aesCBCEncrypt(data:Data, keyData:Data) -> Data? {
        let keyLength = keyData.count
        let validKeyLengths = [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256]
        if (validKeyLengths.contains(keyLength) == false) {
            return nil
        }
        
        // changed according to http://www.riptutorial.com/swift/example/27054/aes-encryption-in-ecb-mode-with-pkcs7-padding
        // let ivSize = kCCBlockSizeAES128;
        let cryptLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)
        
        let status = cryptData.withUnsafeMutableBytes {ivBytes in
            SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, ivBytes)
        }
        if (status != 0) {
            return nil
        }
        
        var numBytesEncrypted :size_t = 0
        let options   = CCOptions(kCCOptionPKCS7Padding + kCCOptionECBMode)
        
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            data.withUnsafeBytes {dataBytes in
                keyData.withUnsafeBytes {keyBytes in
                    CCCrypt(CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            options,
                            keyBytes, keyLength,
                            cryptBytes,
                            dataBytes, data.count,
                            cryptBytes, cryptLength,
                            &numBytesEncrypted)
                }
            }
        }
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.count = numBytesEncrypted
        }
        else {
            return nil
        }
        
        return cryptData;
    }
}
