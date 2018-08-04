//
//  DeepDatagoManager.swift
//  OTRKit
//
//  Created by tnnd on 7/26/18.
//

import Foundation
import Geth

@objc public class DeepDatagoManager: NSObject {
    public var keyStore:GethKeyStore;
    private let keyStorePath = "/keystore";
    public override init() {
        let datadir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
        keyStore = GethNewKeyStore(datadir + keyStorePath, GethLightScryptN, GethLightScryptP);
    }
    
    @objc public func getRegisterRequest(password:NSString) -> NSString! {
        if (password == nil) {
            return nil;
        }
        
        let accounts = (keyStore.getAccounts())!
        var newAccount: GethAccount
        if (accounts.size() <= 0) {
            newAccount = createUser(ks:keyStore, password:password as String!)
        }
        else {
            newAccount = try! accounts.get(0)
        }
        
        var publicKeyPEM:NSString = ""

        if (CryptoManager.generateKeyPairTags())
        {
            publicKeyPEM = CryptoManager.getPublicKeyString()
            // print(publicKeyPEM);
        }
        else {
            return nil;
        }
        
        let registerRequestStr = createRegisterRequest(ks:keyStore, account:newAccount, password:password as String, publicKeyPEM:publicKeyPEM as String)!
        // print("register request: \((registerRequestStr))")


        return registerRequestStr as NSString;
    }

    private func signTransaction(ks: GethKeyStore, account:GethAccount, password: String, data: Data) -> String {
        var error: NSError?
        let to    = GethNewAddressFromHex("0x0000000000000000000000000000000000000000", &error)
        // GethTransaction* GethNewTransaction(int64_t nonce, GethAddress* to, GethBigInt* amount, int64_t gasLimit, GethBigInt* gasPrice, NSData* data);
        var gasLimit: Int64
        gasLimit = 0
        // let data = "abc".data(using: .utf8)
        let tx    = GethNewTransaction(1, to, GethNewBigInt(0), gasLimit, GethNewBigInt(0), data) // Random empty transaction
        let chain = GethNewBigInt(1) // Chain identifier of the main net
        
        // Sign a transaction with multiple manually cancelled authorizations
        try! ks.unlock(account, passphrase: password)
        let signed = try! ks.signTx(account, tx: tx, chainID: chain)
        let signedTrans = try! signed.encodeJSON()
        return signedTrans
    }

    private func createRegisterRequest(ks: GethKeyStore, account: GethAccount, password: String, publicKeyPEM: String!) -> String! {
        // let myString = publicKeyPEM as NSString
        // let myNSData = myString.data(using: String.Encoding.utf8.rawValue)! as NSData
        
        let data = publicKeyPEM.data(using: .utf8)!
        let transactionStr = signTransaction(ks: ks, account: account, password: password, data: data)
        var request: NSMutableDictionary = NSMutableDictionary()
        request.setValue(transactionStr, forKey:"transaction")
        request.setValue(account.getAddress().getHex(), forKey:"sender_address")
        
        let aesKey = "5978A3C7E8BC4F8CB2D6080C18A5F689"
        let senderName = "Name"
        request.setValue(CryptoManager.encryptStringWithSymmetricKey(key: aesKey as NSString, input: senderName as NSString), forKey:"name")
        
        
        let jsonData = try! JSONSerialization.data(withJSONObject: request, options: JSONSerialization.WritingOptions()) as NSData
        let jsonString = NSString(data: jsonData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        return jsonString
    }

    private func createUser(ks: GethKeyStore, password: String) -> GethAccount {
        let newAccount = try! ks.newAccount(password)
        return newAccount
    }

}
