//
//  DeepDatagoManager.swift
//  OTRKit
//
//  Created by tnnd on 7/26/18.
//

import Foundation
import Geth
import SAMKeychain
import AFNetworking

let _keychainService = "com.deepdatago.AESKeyService"
let _keychainAccountForAllFriends = "account.SymmetricKeyForAllFriends"
let BASEURL = "https://dev.deepdatago.com/service/" // accounts/get_public_key/<account_id>/
let DUMMY_ACCOUNT = "0x0000000000000000000000000000000000000000"

let TAG_FRIEND_REQUEST_SYMMETRIC_KEY = "friend_request_symmetric_key"
let TAG_ALL_FRIENDS_SYMMETRIC_KEY = "all_friends_symmetric_key"
let TAG_TRANSACTION = "transaction"
let TAG_SENDER_ADDRESS = "sender_address"

@objc public class DeepDatagoManager: NSObject {
    public var keyStore:GethKeyStore;
    private let keyStorePath = "/keystore";
    public override init() {
        let datadir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
        keyStore = GethNewKeyStore(datadir + keyStorePath, GethLightScryptN, GethLightScryptP);
    }
    
    @objc public func getRegisterRequest(password:NSString, nickName:NSString) -> NSString! {
        if (password.length == 0) {
            return nil;
        }
        
        let accounts = (keyStore.getAccounts())!
        var newAccount: GethAccount
        if (accounts.size() <= 0) {
            newAccount = createUser(ks:keyStore, password:password as String)
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
        try! keyStore.unlock(newAccount, passphrase: password as String)

        let registerRequestStr = createRegisterRequest(ks:keyStore, account:newAccount, nickName:nickName as String, publicKeyPEM:publicKeyPEM as String)!
        // print("register request: \((registerRequestStr))")


        return registerRequestStr as NSString;
    }

    private func getPublicKeyRequest(account:String) -> String! {
        let url = URL(string: BASEURL + "accounts/get_public_key/" + account + "/")
        var request = URLRequest(url: url!)
        request.httpMethod = "GET"
        var responseString = ""
        do {
            let response: AutoreleasingUnsafeMutablePointer<URLResponse?>? = nil
            let data = try NSURLConnection.sendSynchronousRequest(request, returning:response)
            responseString = String(data: data, encoding: String.Encoding.utf8)!
            let jsonData = responseString.data(using: .utf8)!
            let jsonArray = try JSONSerialization.jsonObject(with: jsonData, options : .allowFragments) as? Dictionary<String,Any>
            let publicKeyStr = (jsonArray!["publicKey"])!
            return publicKeyStr as! String;
            // let newResponse = (response?.pointee)!
            // let responseData = String(data: (response?.pointee)!, encoding: NSUTF8StringEncoding)
        } catch let error as NSError{
            print (error.localizedDescription)
            return "";
        }
        return responseString;
    }

    @objc public func getAddFriendRequest(account:NSString) -> NSString! {
        let publicKey = getPublicKeyRequest(account:(account as String))
        
        var aesKeyForAllFriends = SAMKeychain.password(forService:_keychainService, account:_keychainAccountForAllFriends);
        let aesKeyForFriend = UUID().uuidString.replacingOccurrences(of: "-", with: "");
        
        let encryptedKeyForAllFriends = CryptoManager.encryptStrWithPublicKey(publicKey: (publicKey! as NSString), input: (aesKeyForAllFriends! as NSString) )
        let encryptedKeyForFriend = CryptoManager.encryptStrWithPublicKey(publicKey: (publicKey! as NSString), input: (aesKeyForFriend as NSString) )

        var requestData: NSMutableDictionary = NSMutableDictionary()
        requestData.setValue(encryptedKeyForFriend, forKey:TAG_FRIEND_REQUEST_SYMMETRIC_KEY)
        requestData.setValue(encryptedKeyForAllFriends, forKey:TAG_ALL_FRIENDS_SYMMETRIC_KEY)

        return nil;
    }
    
    private func signTransaction(ks: GethKeyStore, account:GethAccount, data: Data) -> String {
        var error: NSError?
        let to    = GethNewAddressFromHex(DUMMY_ACCOUNT, &error)
        var gasLimit: Int64
        gasLimit = 0
        let tx    = GethNewTransaction(1, to, GethNewBigInt(0), gasLimit, GethNewBigInt(0), data) // Random empty transaction
        let chain = GethNewBigInt(1) // Chain identifier of the main net
        
        // Sign a transaction with multiple manually cancelled authorizations
        // try! ks.unlock(account, passphrase: password)
        let signed = try! ks.signTx(account, tx: tx, chainID: chain)
        let signedTrans = try! signed.encodeJSON()
        return signedTrans
    }

    private func createRegisterRequest(ks: GethKeyStore, account: GethAccount, nickName: String, publicKeyPEM: String!) -> String! {
        
        let data = publicKeyPEM.data(using: .utf8)!
        let transactionStr = signTransaction(ks: ks, account: account, data: data)
        var request: NSMutableDictionary = NSMutableDictionary()
        request.setValue(transactionStr, forKey:TAG_TRANSACTION)
        request.setValue(account.getAddress().getHex(), forKey:TAG_SENDER_ADDRESS)
        
        var aesKey = SAMKeychain.password(forService:_keychainService, account:_keychainAccountForAllFriends);
        if (aesKey == nil) {
            aesKey = UUID().uuidString.replacingOccurrences(of: "-", with: "");
            // print("account_sharedKey: \((aesKey))")

            let success = SAMKeychain.setPassword(aesKey!, forService:_keychainService, account: _keychainAccountForAllFriends);
            if (!success) {
                return nil;
            }
        }
        
        request.setValue(CryptoManager.encryptStringWithSymmetricKey(key: aesKey! as NSString, input: nickName as NSString), forKey:"name")
        
        
        let jsonData = try! JSONSerialization.data(withJSONObject: request, options: JSONSerialization.WritingOptions()) as NSData
        let jsonString = NSString(data: jsonData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        return jsonString
    }

    private func createUser(ks: GethKeyStore, password: String) -> GethAccount {
        let newAccount = try! ks.newAccount(password)
        return newAccount
    }

}
