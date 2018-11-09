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
let _keychainFriendPrefix = "account.FriendSymmetricKey_" // for friends
let _keychainAllFriendsKeyPrefix = "account.AllFriendsKey_" // for friends
let _keychainGethAccountPassword = "account.GethPassword"

let BASEURL = "https://dev.deepdatago.com/service/" // accounts/get_public_key/<account_id>/
let ACCOUNT_GET_PUBLIC_KEY_API = "accounts/get_public_key/"
let REQUEST_FRIEND_API = "request/friend/"
let REQUEST_SUMMARY_API = "request/summary/?"
let REQUEST_APPROVED_DETAILS_API = "request/approved_details/?"

let DUMMY_ACCOUNT = "0x0000000000000000000000000000000000000000"

let TAG_FRIEND_REQUEST_SYMMETRIC_KEY = "friend_request_symmetric_key"
let TAG_ALL_FRIENDS_SYMMETRIC_KEY = "all_friends_symmetric_key"
let TAG_TRANSACTION = "transaction"
let TAG_SENDER_ADDRESS = "sender_address"
let TAG_TO_ADDRESS = "to_address"
let TAG_FROM_ADDRESS = "from_address"
let TAG_TIME_STAMP = "time_stamp"
let TAG_B64_ENCODED_SIGNATURE = "b64encoded_signature"
let TAG_APPROVED_REQUEST = "approved_request"
let TAG_REQUEST = "request"

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

        let success = setSymmetricKeyForAccount(account: (account as String), aesKey: aesKeyForFriend)

        let data = sendPOSTRequest(urlString:(BASEURL + REQUEST_FRIEND_API), input: friendRequestDataString);
        if (data == nil) {
            return ()
        }

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

    @objc public func getApprovedDetails(toAddress: NSString) -> NSString! {
        // request/approved_details/?param1=value1&param2=value2
        // to_address = 0x...
        // from_address = 0x...
        // b64encoded_signature = ...
        // time_stamp=unix time
        var requestStr = TAG_TO_ADDRESS + "=0x" + (toAddress as String)
        let fromAddress = getAccount().getAddress().getHex()
        requestStr = requestStr + "&" + TAG_FROM_ADDRESS + "=" + fromAddress!

        let timeInterval = NSDate().timeIntervalSince1970
        let timeStr = String(format: "%.0f", timeInterval)
        requestStr += "&" + TAG_TIME_STAMP + "=" + timeStr
        let sign = CryptoManager.signStrWithPrivateKey(input: (timeStr as NSString), urlEncode: true)
        // print(sign!);
        requestStr += "&" + TAG_B64_ENCODED_SIGNATURE + "=" + (sign! as String)

        let data = sendGETRequest(urlString:(BASEURL + REQUEST_APPROVED_DETAILS_API + requestStr + "/"))
        if (data == nil) {
            return ""
        }
        let responseString = String(data: data!, encoding: String.Encoding.utf8)!
        let jsonData = responseString.data(using: .utf8)!

        do {
            let jsonArray = try JSONSerialization.jsonObject(with: jsonData, options : .allowFragments) as? Dictionary<String,Any>
            for item in jsonArray! {
                // guard let myStr = item["approved_request"] as? [String: Any] else {}
                if (item.key == TAG_APPROVED_REQUEST) {
                    let tmpJsonData = (item.value as! String).data(using: .utf8)!
                    let json2 = try JSONSerialization.jsonObject(with: tmpJsonData, options : .allowFragments) as? Dictionary<String,Any>
                    for item2 in json2! {
                        if (item2.key == TAG_ALL_FRIENDS_SYMMETRIC_KEY) {
                            var encryptedStr = (item2.value as! String)
                            let decryptedStr = CryptoManager.decryptStrWithPrivateKeyTag(keyTag: (PRIVATE_KEY_TAG as NSString), inputBase64Encoded: encryptedStr as NSString)!
                            // print(decryptedStr as String)
                            // save all_friends_symmetric_key
                            setAllFriendsKeyForAccount(account: (toAddress as String), aesKey: (decryptedStr as String))
                            break
                        }
                    }
                    break
                    // print (item.value as! String)
                }
            }
        } catch let error as NSError{
            print (error.localizedDescription)
        }

        return "";
    }

    @objc public func getAllFriendsKeyByAccount(account: NSString) -> NSString! {
        let gethAccount = getAccount()
        let selfAccount = gethAccount?.getAddress().getHex().replacingOccurrences(of: "0x", with: "")
        if (selfAccount?.lowercased() == (account as String).lowercased()) {
            return getPasswordForAllFriends()
        }
        
        let aesKey = getAllFriendsKeyForAccount(account: (account as String)) as NSString
        return aesKey
    }

    private func setSymmetricKeyForAccount(account: String, aesKey: String) -> Bool {
        let keyChainFriendAccount = _keychainFriendPrefix + (account as String)
        let success = SAMKeychain.setPassword(aesKey, forService:_keychainService, account: keyChainFriendAccount);
        return success;
    }
    
    // private func getSymmetricKeyForAccount(account: String) -> String {
    @objc public func getSymmetricKeyForAccount(account: NSString) -> NSString! {
        let keyChainFriendAccount = _keychainFriendPrefix + (account as String)
        let aesKey = SAMKeychain.password(forService:_keychainService, account:keyChainFriendAccount);
        if (aesKey == nil) {
            return "";
        }
        return aesKey! as NSString;
    }

    private func setAllFriendsKeyForAccount(account: String, aesKey: String) -> Bool {
        let keyChainFriendAccount = _keychainAllFriendsKeyPrefix + (account as String)
        let success = SAMKeychain.setPassword(aesKey, forService:_keychainService, account: keyChainFriendAccount);
        return success;
    }
    
    private func getAllFriendsKeyForAccount(account: String) -> String {
        let keyChainFriendAccount = _keychainAllFriendsKeyPrefix + (account as String)
        let aesKey = SAMKeychain.password(forService:_keychainService, account:keyChainFriendAccount);
        if (aesKey == nil) {
            return "";
        }
        return aesKey!;
    }

}
