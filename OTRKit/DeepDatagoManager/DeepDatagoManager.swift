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
let _keychainFriendPrefix = "account.FriendSymmetricKey_"
let _keychainGethAccountPassword = "account.GethPassword"

let BASEURL = "https://dev.deepdatago.com/service/" // accounts/get_public_key/<account_id>/
let ACCOUNT_GET_PUBLIC_KEY_API = "accounts/get_public_key/"
let REQUEST_FRIEND_API = "request/friend/"
let REQUEST_SUMMARY_API = "request/summary/?"

let DUMMY_ACCOUNT = "0x0000000000000000000000000000000000000000"

let TAG_FRIEND_REQUEST_SYMMETRIC_KEY = "friend_request_symmetric_key"
let TAG_ALL_FRIENDS_SYMMETRIC_KEY = "all_friends_symmetric_key"
let TAG_TRANSACTION = "transaction"
let TAG_SENDER_ADDRESS = "sender_address"

@objc public class DeepDatagoManager: NSObject {
    static let shared = DeepDatagoManager()
    
    public var keyStore:GethKeyStore;
    private let keyStorePath = "/keystore";
    private override init() {
        let datadir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
        keyStore = GethNewKeyStore(datadir + keyStorePath, GethLightScryptN, GethLightScryptP);
    }
    
    @objc public static func sharedInstance() -> DeepDatagoManager {
        return DeepDatagoManager.shared
    }

    @objc public func getPasswordForAllFriends() -> NSString! {
        let passwordForAllFriends = SAMKeychain.password(forService:_keychainService, account:_keychainAccountForAllFriends)!;
        return passwordForAllFriends as NSString;
    }

    @objc public func getRegisterRequest(password:NSString, nickName:NSString) -> NSString! {
        if (password.length == 0) {
            return nil;
        }
        
        let accounts = (keyStore.getAccounts())!
        // var newAccount: GethAccount
        var newAccount = getAccount()
        if (newAccount == nil) {
            newAccount = createUser(ks:keyStore, password:password as String)
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
        // try! keyStore.unlock(newAccount, passphrase: password as String)
        // [CRYPTO_TALK] TODO - can we just unlock account once without saving account password for
        // future transaction signing?
        let success = SAMKeychain.setPassword(password as String, forService:_keychainService, account: _keychainGethAccountPassword);
        
        if (!success) {
            return "";
        }

        let registerRequestStr = createRegisterRequest(ks:keyStore, account:newAccount!, nickName:nickName as String, publicKeyPEM:publicKeyPEM as String)!
        // print("register request: \((registerRequestStr))")


        return registerRequestStr as NSString;
    }

    private func getAccount() -> GethAccount! {
        let accounts = (keyStore.getAccounts())!
        var newAccount: GethAccount
        if (accounts.size() <= 0) {
            return nil
        }
        else {
            newAccount = try! accounts.get(0)
        }
        return newAccount
    }
    
    private func getPublicKeyRequest(account:String) -> String! {
        let data = sendGETRequest(urlString:(BASEURL + ACCOUNT_GET_PUBLIC_KEY_API + account + "/"))
        if (data == nil) {
            return ""
        }
        let responseString = String(data: data!, encoding: String.Encoding.utf8)!
        let jsonData = responseString.data(using: .utf8)!
        do {
            let jsonArray = try JSONSerialization.jsonObject(with: jsonData, options : .allowFragments) as? Dictionary<String,Any>
            let publicKeyStr = (jsonArray!["publicKey"])!
            return publicKeyStr as! String;
        } catch let error as NSError{
            print (error.localizedDescription)
        }
        return ""
    }

    private func sendPOSTRequest(urlString:String, input:String) -> Data! {
        print(urlString)
        let url = URL(string: urlString)
        var request = URLRequest(url: url!)
        request.httpMethod = "POST"
        let inputData = input.data(using: .utf8)!
        request.httpBody = inputData
        request.setValue("application/json", forHTTPHeaderField: "ContentType")
        do {
            var response2: URLResponse?
            let data = try NSURLConnection.sendSynchronousRequest(request, returning:&response2)
            if ((response2! as! HTTPURLResponse).statusCode != 200) {
                return nil
            }
            return data;
        } catch let error as NSError{
            print (error.localizedDescription)
        }
        return nil;
    }

    private func sendGETRequest(urlString:String) -> Data! {
        let url = URL(string: urlString)
        var request = URLRequest(url: url!)
        request.httpMethod = "GET"
        do {
            var response2: URLResponse?
            let data = try NSURLConnection.sendSynchronousRequest(request, returning:&response2)
            if ((response2! as! HTTPURLResponse).statusCode != 200) {
                return nil
            }

            return data;
        } catch let error as NSError{
            print (error.localizedDescription)
        }
        return nil;
    }

    @objc public func addFriendRequest(account:NSString) -> Void {
        let publicKey = getPublicKeyRequest(account:(account as String))
        
        let aesKeyForAllFriends = SAMKeychain.password(forService:_keychainService, account:_keychainAccountForAllFriends);
        let aesKeyForFriend = UUID().uuidString.replacingOccurrences(of: "-", with: "");

        let encryptedKeyForAllFriends = CryptoManager.encryptStrWithPublicKey(publicKey: (publicKey! as NSString), input: (aesKeyForAllFriends! as NSString) )
        let encryptedKeyForFriend = CryptoManager.encryptStrWithPublicKey(publicKey: (publicKey! as NSString), input: (aesKeyForFriend as NSString) )

        var requestData: NSMutableDictionary = NSMutableDictionary()
        requestData.setValue(encryptedKeyForFriend, forKey:TAG_FRIEND_REQUEST_SYMMETRIC_KEY)
        requestData.setValue(encryptedKeyForAllFriends, forKey:TAG_ALL_FRIENDS_SYMMETRIC_KEY)
        let keysRequestData = try! JSONSerialization.data(withJSONObject: requestData, options: JSONSerialization.WritingOptions())
        // let keysRequestString = NSString(data: keysRequestData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        // let encrpytedKeyStrData = encryptedKeysStr.data(using: .utf8)!
        let gethAccount = getAccount()
        let transactionStr = signTransaction(ks: keyStore, account: gethAccount!, data: keysRequestData)

        var friendRequest: NSMutableDictionary = NSMutableDictionary()
        friendRequest.setValue(0, forKey:"action_type")
        friendRequest.setValue("0x" + (account as String), forKey:"to_address")
        friendRequest.setValue(gethAccount?.getAddress().getHex(), forKey:"from_address")
        friendRequest.setValue(transactionStr, forKey:"request")
        let friendRequestData = try! JSONSerialization.data(withJSONObject: friendRequest, options: JSONSerialization.WritingOptions()) as NSData
        let friendRequestDataString = NSString(data: friendRequestData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        
        let data = sendPOSTRequest(urlString:(BASEURL + REQUEST_FRIEND_API), input: friendRequestDataString);
        if (data == nil) {
            return ()
        }

        let keyChainFriendAccount = _keychainFriendPrefix + (account as String)
        let success = SAMKeychain.setPassword(aesKeyForFriend, forService:_keychainService, account: keyChainFriendAccount);
        
        if (!success) {
            return ();
        }

        // let responseString = String(data: data!, encoding: String.Encoding.utf8)!

        return ();
    }
    
    private func signTransaction(ks: GethKeyStore, account:GethAccount, data: Data) -> String {
        var error: NSError?
        let to    = GethNewAddressFromHex(DUMMY_ACCOUNT, &error)
        var gasLimit: Int64
        gasLimit = 0
        let tx    = GethNewTransaction(1, to, GethNewBigInt(0), gasLimit, GethNewBigInt(0), data) // Random empty transaction
        let chain = GethNewBigInt(1) // Chain identifier of the main net
        
        // Sign a transaction with multiple manually cancelled authorizations
        let accountPassword = SAMKeychain.password(forService:_keychainService, account:_keychainGethAccountPassword);
        try! ks.unlock(account, passphrase: accountPassword)
        
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
        
        let encryptedNickName = CryptoManager.encryptStringWithSymmetricKey(key: aesKey as! NSString, input: nickName as NSString)
        
        // request.setValue(CryptoManager.encryptStringWithSymmetricKey(key: aesKey! as NSString, input: encryptedNickName!), forKey:"name")
        request.setValue(encryptedNickName, forKey:"name")

        
        let jsonData = try! JSONSerialization.data(withJSONObject: request, options: JSONSerialization.WritingOptions()) as NSData
        let jsonString = NSString(data: jsonData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        return jsonString
    }

    private func createUser(ks: GethKeyStore, password: String) -> GethAccount {
        let newAccount = try! ks.newAccount(password)
        return newAccount
    }

    @objc public func getSummary(toAddress: NSString) -> NSString! {
        // request/summary/?param1=value1&param2=value2
        // to_address = 0x...
        // b64encoded_signature = ...
        // time_stamp=unix time
        let timeInterval = NSDate().timeIntervalSince1970
        let timeStr = String(format: "%.0f", timeInterval)
        let sign = CryptoManager.signStrWithPrivateKey(input: (timeStr as NSString), urlEncode: true)
        // print(sign!);

        return "";
    }

}
