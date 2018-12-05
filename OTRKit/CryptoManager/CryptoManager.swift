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
let PUBLIC_KEY_TAG = "com.deepdatago.publicKeyTag";
let PRIVATE_KEY_TAG = "com.deepdatago.privateKeyTag";
let kPublicPrivateKeySize = 4096


@objc public class CryptoManager: NSObject {
    @objc public static func decryptStringWithSymmetricKey(key:NSString, base64Input:NSString) -> NSString! {
        let inputStr = base64Input as String
        // NSLog("encrypted string: \((inputStr))")
        guard let inputData = Data(base64Encoded: inputStr) else {return ""}
        let keyData = (key as String).data(using: .utf8)!
        
        let decryptedData = aesCBCDecrypt(data:inputData, keyData:keyData)!
        guard let returnStr = String(data: decryptedData, encoding: String.Encoding.utf8) else {return ""}
        return returnStr as NSString
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
        return CryptoManager.getKeyByKeyTag(keyTagName: PUBLIC_KEY_TAG as NSString)
    }

    @objc public static func generateKeyPairTags() -> Bool {
        if (getKeyByKeyTag(keyTagName: PUBLIC_KEY_TAG as NSString).length > 0)
        {
            return true;
        }
        var statusCode: OSStatus?
        var publicKey: SecKey?
        var privateKey: SecKey?
        let publicKeyAttr: [NSObject: NSObject] = [
            kSecAttrIsPermanent:true as NSObject,
            kSecAttrApplicationTag:PUBLIC_KEY_TAG.data(using: String.Encoding.utf8)! as NSObject,
            kSecClass: kSecClassKey, // added this value
            kSecReturnData: kCFBooleanTrue] // added this value
        let privateKeyAttr: [NSObject: NSObject] = [
            kSecAttrIsPermanent:true as NSObject,
            kSecAttrApplicationTag:PRIVATE_KEY_TAG.data(using: String.Encoding.utf8)! as NSObject,
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
            // print("Key pair generated OK")
            var resultPublicKey: AnyObject?
            var resultPrivateKey: AnyObject?
            let statusPublicKey = SecItemCopyMatching(publicKeyAttr as CFDictionary, &resultPublicKey)
            let statusPrivateKey = SecItemCopyMatching(privateKeyAttr as CFDictionary, &resultPrivateKey)
            
            if statusPublicKey == noErr {
                if let publicKey = resultPublicKey as? Data {
                    /*
                    finalPubKeyStr = "-----BEGIN RSA PUBLIC KEY-----\n"
                    finalPubKeyStr = finalPubKeyStr + publicKey.base64EncodedString()
                    
                    // print("Public Key: \((publicKey.base64EncodedString()))")
                    // let publicKeyStr = publicKey.base64EncodedString()
                    finalPubKeyStr = finalPubKeyStr + "\n-----END RSA PUBLIC KEY-----"
                    */
                    // let cryptoImportExportManager = CryptoExportImportManager()
                    // finalPubKeyStr = cryptoImportExportManager.exportRSAPublicKeyToPEM(publicKey, keyType: kSecAttrKeyTypeRSA as String, keySize: kPublicPrivateKeySize)
                    // print("Public Key: \((finalPubKeyStr))")
                }
            }
            
            if statusPrivateKey == noErr {
                if let privateKey = resultPrivateKey as? Data {
                    // print("Private Key: \((privateKey.base64EncodedString()))")
                    // finalPrivateKeyStr = CryptoManager.formatPrivateKeyPEM(key:privateKey.base64EncodedString())
                    /*
                    finalPrivateKeyStr = "-----BEGIN RSA PRIVATE KEY-----\n"
                    finalPrivateKeyStr = finalPrivateKeyStr + privateKey.base64EncodedString()
                    finalPrivateKeyStr = finalPrivateKeyStr + "\n-----END RSA PRIVATE KEY-----"
                    */
                }
            }
        } else {
            print("Error generating key pair: \(String(describing: statusCode))")
            return false;
        }
        // try! RSAUtils.addRSAPublicKey(finalPubKeyStr, tagName:PUBLIC_KEY_TAG)
        // try! RSAUtils.addRSAPrivateKey(finalPrivateKeyStr, tagName:PRIVATE_KEY_TAG)
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

    @objc public static func encryptStrWithPublicKeyTag(keyTag:NSString, input:NSString) -> NSString! {
        if (input.length > 380)
        {
            // public key can only encrypt to certain length of string, less than 512 characters?
            return "";
        }
        var publicKeyTag = keyTag as String
        if publicKeyTag.count == 0 {
            publicKeyTag = PUBLIC_KEY_TAG
        }
        
        let publicKeyEncryptedData = RSAUtils.encryptWithRSAKey(str: (input as String), tagName: publicKeyTag)
        return ((publicKeyEncryptedData?.base64EncodedString())! as NSString)
    }

    @objc public static func decryptStrWithPrivateKeyTag(keyTag:NSString, inputBase64Encoded:NSString) -> NSString! {
        var keyTagToUse = keyTag as String
        if keyTagToUse.count == 0 {
            keyTagToUse = PRIVATE_KEY_TAG
        }
        let decodedData = Data(base64Encoded: (inputBase64Encoded) as String)
        let decryptedData = RSAUtils.decryptWithRSAKey(encryptedData: decodedData!, tagName: keyTagToUse)
        if (decryptedData == nil) {
            return ""
        }
        var backToString = String(data: decryptedData!, encoding: String.Encoding.utf8) as String!
        if (backToString == nil) {
            return ""
        }
        return backToString! as NSString
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

    private static func getPrivateKeyRef() -> SecKey? {
        var keyRef: AnyObject?
        let query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnRef): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFString,
            String(kSecAttrApplicationTag): PRIVATE_KEY_TAG as CFString,
            ]
        
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
        var key : SecKey?
        
        switch status {
        case noErr:
            if let ref = keyRef {
                // key = (ref as! SecKey)
                return (ref as! SecKey)
            }
        default:
            break
        }
        return key
    }
    
    private static func signString(input: String, privateKeyTag: String, urlEncode: Bool) -> String {
        let inputData = (input as String).data(using: String.Encoding.utf8)!

        let key = getPrivateKeyRef()
        if (key == nil) {
            return ""
        }

        let hash = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))!
        // Create SHA256 hash of the message
        CC_SHA256((inputData as NSData).bytes, CC_LONG(inputData.count), hash.mutableBytes.assumingMemoryBound(to: UInt8.self))
        
        // Sign the hash with the private key
        let blockSize = SecKeyGetBlockSize(key!)
        
        let hashDataLength = Int(hash.length)
        let hashData = hash.bytes.bindMemory(to: UInt8.self, capacity: hash.length)
        
        if let result = NSMutableData(length: Int(blockSize)) {
            let encryptedData = result.mutableBytes.assumingMemoryBound(to: UInt8.self)
            var encryptedDataLength = blockSize
            
            let status = SecKeyRawSign(key!, .PKCS1SHA256, hashData, hashDataLength, encryptedData, &encryptedDataLength)
            
            if status == noErr {
                // Create Base64 string of the result
                result.length = encryptedDataLength
                let signature = result.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))

                if (urlEncode) {
                    return signature.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
                }
                
                return signature
            }
        }
        
        return ""
    }

    @objc public static func signStrWithPrivateKey(input: NSString, urlEncode: Bool = false) -> NSString!
    {
        return signString(input: input as String, privateKeyTag: PRIVATE_KEY_TAG, urlEncode: urlEncode) as NSString
    }
}
