//
//  CryptoManager.swift
//  OTRKit
//
//  Created by tnnd on 6/23/18.
//

import Foundation
import RNCryptor
import Security

// let _typePublic = 0;
// let _typePrivate = 1;
let publicKeyTag = "com.deepdatago.publicKeyTag";
let privateKeyTag = "com.deepdatago.privateKeyTag";
let kPublicPrivateKeySize = 4096


@objc public class CryptoManager: NSObject {
    @objc public static func decryptStringWithSymmetricKey(key:NSString, base64Input:NSString) -> NSString! {
        let inputStr = base64Input as String
        NSLog("encrypted string: \((inputStr))")
        let inputData = Data(base64Encoded: inputStr)!
        let keyData = (key as String).data(using: .utf8)!
        
        let decryptedData = aesCBCDecrypt(data:inputData, keyData:keyData)!
        return String(data: decryptedData, encoding: String.Encoding.utf8)! as NSString
    }
    
    @objc public static func encryptStringWithSymmetricKey(key:NSString, input:NSString) -> NSString! {
        let inputData = (input as String).data(using: .utf8)!
        let keyData = (key as String).data(using: .utf8)!
        return aesCBCEncrypt(data:inputData, keyData:keyData)!.base64EncodedString() as NSString
    }

    @objc public static func decryptDataWithSymmetricKey(key:NSString, inputData:Data) -> Data! {
        let keyData = (key as String).data(using: .utf8)!
        
        return aesCBCDecrypt(data:inputData, keyData:keyData)!
    }
    
    @objc public static func encryptDataWithSymmetricKey(key:NSString, inputData:Data) -> Data! {
        let keyData = (key as String).data(using: .utf8)!
        return aesCBCEncrypt(data:inputData, keyData:keyData)!
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

    @objc public static func getKeyByKeyTag(keyTagName:NSString) -> NSString {
        // let keyValue = RSAUtils.getRSAKeyFromKeychain(keyTagName as String);
        
        // keyValue.
        var dataPtr:CFTypeRef?
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTagName,
            kSecReturnData as String: true
        ]
        
        let qResult = SecItemCopyMatching(query as CFDictionary, &dataPtr)
        if (dataPtr == nil) {
            return "";
        }
        
        // error handling with `qResult` ...
 
        let data = dataPtr as! Data
        if (data == nil) {
            return ""
        }
        let cryptoImportExportManager = CryptoExportImportManager()
        return cryptoImportExportManager.exportRSAPublicKeyToPEM(data, keyType: kSecAttrKeyTypeRSA as String, keySize: kPublicPrivateKeySize) as NSString
    }
    
    private static func formatPrivateKeyPEM(key:String) -> String! {
        /*
        if (keyType == _typePublic)
        {
            var finalPubKeyStr = "-----BEGIN RSA PUBLIC KEY-----\n"
            finalPubKeyStr = finalPubKeyStr + key
            finalPubKeyStr = finalPubKeyStr + "\n-----END RSA PUBLIC KEY-----"
            return finalPubKeyStr;
        }
        */
        var finalPrivateKeyStr = "-----BEGIN RSA PRIVATE KEY-----\n"
        finalPrivateKeyStr = finalPrivateKeyStr + key
        finalPrivateKeyStr = finalPrivateKeyStr + "\n-----END RSA PRIVATE KEY-----"
        return finalPrivateKeyStr;
    }

    @objc public static func getPublicKeyString() -> NSString {
        return CryptoManager.getKeyByKeyTag(keyTagName: publicKeyTag as NSString)
    }

    @objc public static func generateKeyPairTags() -> Bool {
        if (getKeyByKeyTag(keyTagName: publicKeyTag as NSString).length > 0)
        {
            return true;
        }
        var statusCode: OSStatus?
        var publicKey: SecKey?
        var privateKey: SecKey?
        let publicKeyAttr: [NSObject: NSObject] = [
            kSecAttrIsPermanent:true as NSObject,
            kSecAttrApplicationTag:(publicKeyTag as String).data(using: String.Encoding.utf8)! as NSObject,
            kSecClass: kSecClassKey, // added this value
            kSecReturnData: kCFBooleanTrue] // added this value
        let privateKeyAttr: [NSObject: NSObject] = [
            kSecAttrIsPermanent:true as NSObject,
            kSecAttrApplicationTag:(publicKeyTag as String).data(using: String.Encoding.utf8)! as NSObject,
            kSecClass: kSecClassKey, // added this value
            kSecReturnData: kCFBooleanTrue] // added this value
        
        var keyPairAttr = [NSObject: NSObject]()
        keyPairAttr[kSecAttrKeyType] = kSecAttrKeyTypeRSA
        keyPairAttr[kSecAttrKeySizeInBits] = kPublicPrivateKeySize as NSObject
        keyPairAttr[kSecPublicKeyAttrs] = publicKeyAttr as NSObject
        keyPairAttr[kSecPrivateKeyAttrs] = privateKeyAttr as NSObject
        
        statusCode = SecKeyGeneratePair(keyPairAttr as CFDictionary, &publicKey, &privateKey)
        var finalPubKeyStr: String!
        var finalPrivateKeyStr: String!
        
        if statusCode == noErr && publicKey != nil && privateKey != nil {
            print("Key pair generated OK")
            var resultPublicKey: AnyObject?
            var resultPrivateKey: AnyObject?
            let statusPublicKey = SecItemCopyMatching(publicKeyAttr as CFDictionary, &resultPublicKey)
            let statusPrivateKey = SecItemCopyMatching(privateKeyAttr as CFDictionary, &resultPrivateKey)
            
            if statusPublicKey == noErr {
                if let publicKey = resultPublicKey as? Data {
                    let cryptoImportExportManager = CryptoExportImportManager()
                    finalPubKeyStr = cryptoImportExportManager.exportRSAPublicKeyToPEM(publicKey, keyType: kSecAttrKeyTypeRSA as String, keySize: kPublicPrivateKeySize)
                    print("Public Key: \((finalPubKeyStr))")
                }
            }
            
            if statusPrivateKey == noErr {
                if let privateKey = resultPrivateKey as? Data {
                    // print("Private Key: \((privateKey.base64EncodedString()))")
                    finalPrivateKeyStr = CryptoManager.formatPrivateKeyPEM(key:privateKey.base64EncodedString())
                }
            }
        } else {
            print("Error generating key pair: \(String(describing: statusCode))")
            return false;
        }
        try! RSAUtils.addRSAPublicKey(finalPubKeyStr, tagName: publicKeyTag as String)
        try! RSAUtils.addRSAPrivateKey(finalPrivateKeyStr, tagName: privateKeyTag as String)

        return true;
    }
    
    @objc public static func encryptStrWithPublicKey(publicKey:NSString, input:NSString) -> NSString! {
        if (input.length > 380)
        {
            // public key can only encrypt to certain length of string, less than 512 characters?
            return "";
        }
        let publicKeyTag = "publicKey_" + MD5HashToBase64(string:(publicKey as String))
        try! RSAUtils.addRSAPublicKey((publicKey as String), tagName: publicKeyTag)
        let publicKeyEncryptedData = RSAUtils.encryptWithRSAKey(str: (input as String), tagName: publicKeyTag)
        return ((publicKeyEncryptedData?.base64EncodedString())! as NSString)
    }
    
    private static func MD5HashToBase64(string: String) -> String! {
        let messageData = string.data(using:.utf8)!
        var digestData = Data(count: Int(CC_MD5_DIGEST_LENGTH))
        
        _ = digestData.withUnsafeMutableBytes {digestBytes in
            messageData.withUnsafeBytes {messageBytes in
                CC_MD5(messageBytes, CC_LONG(messageData.count), digestBytes)
            }
        }
        return digestData.base64EncodedString()
    }


}
