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
let _keychainDecryptedNickNamePrefix = "account.NickNameOf_" // for friend's nick name
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
let TAG_FRIEND_REQUEST = "friend_request"
let TAG_REQUEST = "request"
let TAG_ACTION_TYPE = "action_type"

@objc public enum RequestActionType: Int {
    case friendRequest = 0
    case approveRequest = 1
}

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

    @objc public func friendRequestSync(account:NSString, requestType:Int) -> Void {
        // JSON structure of friend request:
        // {
        //   "action_type": 0, // or 1 to approve
        //   "to_address": "0x<to_address>",
        //   "from_address": "0x<from_address>"
        //   "request": "signed transaction string"
        // }
        // where "signed transaction string" has input structure:
        // {
        //   "friend_request_symmetric_key": "<public_key_encrypted symmetric key>",
        //        Note: this field is optional if to approve a friend request, as this is already exchanged
        //   "all_friends_symmetric_key": "<public_key_encrypted symmetric key>",
        //        Note: this public key is always using the one for to_address' public key
        // }

        let publicKey = getPublicKeyRequest(account:(account as String))
        var requestData: NSMutableDictionary = NSMutableDictionary()
        
        // let aesKeyForAllFriends = SAMKeychain.password(forService:_keychainService, account:_keychainAccountForAllFriends);
        let aesKeyForAllFriends = getPasswordForAllFriends()

        let encryptedKeyForAllFriends = CryptoManager.encryptStrWithPublicKey(publicKey: (publicKey! as NSString), input: (aesKeyForAllFriends! as NSString) )
        requestData.setValue(encryptedKeyForAllFriends, forKey:TAG_ALL_FRIENDS_SYMMETRIC_KEY)

        if (requestType == RequestActionType.friendRequest.rawValue)
        {
            let aesKeyForFriend = getSymmetricKey(account: (account as NSString))
            let encryptedKeyForFriend = CryptoManager.encryptStrWithPublicKey(publicKey: (publicKey! as NSString), input: (aesKeyForFriend as! NSString) )
            requestData.setValue(encryptedKeyForFriend, forKey:TAG_FRIEND_REQUEST_SYMMETRIC_KEY)
        }
        
        let keysRequestData = try! JSONSerialization.data(withJSONObject: requestData, options: JSONSerialization.WritingOptions())
        // let keysRequestString = NSString(data: keysRequestData as Data, encoding: String.Encoding.utf8.rawValue) as! String
        // let encrpytedKeyStrData = encryptedKeysStr.data(using: .utf8)!
        let gethAccount = getAccount()
        let transactionStr = signTransaction(ks: keyStore, account: gethAccount!, data: keysRequestData)

        var friendRequest: NSMutableDictionary = NSMutableDictionary()
        friendRequest.setValue(requestType, forKey:TAG_ACTION_TYPE)
        if (requestType == RequestActionType.friendRequest.rawValue)
        {
            friendRequest.setValue("0x" + (account as String).lowercased(), forKey:TAG_TO_ADDRESS)
            friendRequest.setValue(gethAccount?.getAddress().getHex().lowercased(), forKey:TAG_FROM_ADDRESS)
        }
        else
        {
            // to approve the friend request, need to reverse the from_address/to_address
            friendRequest.setValue("0x" + (account as String).lowercased(), forKey:TAG_FROM_ADDRESS)
            friendRequest.setValue(gethAccount?.getAddress().getHex().lowercased(), forKey:TAG_TO_ADDRESS)
        }

        friendRequest.setValue(transactionStr, forKey:TAG_REQUEST)
        let friendRequestData = try! JSONSerialization.data(withJSONObject: friendRequest, options: JSONSerialization.WritingOptions()) as NSData
        let friendRequestDataString = NSString(data: friendRequestData as Data, encoding: String.Encoding.utf8.rawValue) as! String

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
                            setAllFriendsKey(account: (toAddress as String), aesKey: (decryptedStr as String))
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

    @objc public func getAllFriendsKey(account: NSString) -> NSString! {
        let gethAccount = getAccount()
        let selfAccount = gethAccount?.getAddress().getHex().replacingOccurrences(of: "0x", with: "")
        if (selfAccount?.lowercased() == (account as String).lowercased()) {
            return getPasswordForAllFriends()
        }
        
        let keyChainFriendAccount = _keychainAllFriendsKeyPrefix + (account as String)
        let aesKey = SAMKeychain.password(forService:_keychainService, account:keyChainFriendAccount);
        if (aesKey == nil) {
            return "";
        }
        return aesKey! as NSString
    }

    private func setSymmetricKey(account: String, aesKey: String) -> Bool {
        if (account.count == 0 || aesKey.count == 0) {
            return false
        }
        let accountStr = account.replacingOccurrences(of: "0x", with: "")
        let keyChainFriendAccount = _keychainFriendPrefix + accountStr
        let success = SAMKeychain.setPassword(aesKey, forService:_keychainService, account: keyChainFriendAccount);
        return success;
    }

    @objc public func getSymmetricKey(account: NSString) -> NSString! {
        let keyChainFriendAccount = _keychainFriendPrefix + (account as String)
        var aesKey = SAMKeychain.password(forService:_keychainService, account:keyChainFriendAccount);
        if (aesKey == nil || (aesKey! as String).count == 0) {
            aesKey = UUID().uuidString.replacingOccurrences(of: "-", with: "");
            setSymmetricKey(account: (account as String), aesKey: aesKey!)
        }
        return aesKey! as NSString;
    }

    private func setAllFriendsKey(account: String, aesKey: String) -> Bool {
        if (account.count == 0 || aesKey.count == 0) {
            return false
        }
        let accountStr = account.replacingOccurrences(of: "0x", with: "")

        let keyChainFriendAccount = _keychainAllFriendsKeyPrefix + accountStr
        let success = SAMKeychain.setPassword(aesKey, forService:_keychainService, account: keyChainFriendAccount);
        return success;
    }

    private func setDecryptedNick(account: String, nickName: String) -> Bool {
        if (account.count == 0 || nickName.count == 0) {
            return false
        }
        let accountStr = account.replacingOccurrences(of: "0x", with: "")
        
        let keyChainFriendAccount = _keychainDecryptedNickNamePrefix + accountStr
        let success = SAMKeychain.setPassword(nickName, forService:_keychainService, account: keyChainFriendAccount);
        return success;
    }

    @objc public func getDecryptedNick(account: NSString) -> NSString! {
        let keyChainFriendAccount = _keychainDecryptedNickNamePrefix + (account as String)
        var nickName = SAMKeychain.password(forService:_keychainService, account:keyChainFriendAccount);
        if (nickName == nil || (nickName! as String).count == 0) {
            return ""
        }
        return nickName! as NSString;
    }

    private func processSummary(summary: String) -> Bool {
        let jsonData = summary.data(using: .utf8)!
        do {
            var requestObj = try JSONSerialization.jsonObject(with: jsonData, options : .allowFragments) as? Dictionary<String,Any>
            let friendRequestStr = (requestObj![TAG_FRIEND_REQUEST] as! NSArray)
            let approvedRequestStr = (requestObj![TAG_APPROVED_REQUEST] as! NSArray)
            
            if (friendRequestStr.count == 0) {
                return false
            }
            // requestObj = try JSONSerialization.jsonObject(with: friendRequestData, options : .allowFragments) as? Dictionary<String,Any>
            for item in friendRequestStr {
                let tmpItem = (item as! NSDictionary)
                let itemName = tmpItem["name"] as! String
                let itemFromAddress = tmpItem[TAG_FROM_ADDRESS] as! String
                let itemRequest = tmpItem[TAG_REQUEST] as! String
                let itemRequestData = (itemRequest as! String).data(using: .utf8)!
                
                requestObj = try JSONSerialization.jsonObject(with: itemRequestData, options : .allowFragments) as? Dictionary<String,Any>
                
                let friendRequestKey = requestObj![TAG_FRIEND_REQUEST_SYMMETRIC_KEY] as! String
                
                let decryptedFriendRequestKey = CryptoManager.decryptStrWithPrivateKeyTag(keyTag: (PRIVATE_KEY_TAG as NSString), inputBase64Encoded: friendRequestKey as NSString)!
                setSymmetricKey(account: itemFromAddress, aesKey: decryptedFriendRequestKey as String)
                let allFriendsKey = requestObj![TAG_ALL_FRIENDS_SYMMETRIC_KEY] as! String
                let decryptedAllFriendsKey = CryptoManager.decryptStrWithPrivateKeyTag(keyTag: (PRIVATE_KEY_TAG as NSString), inputBase64Encoded: allFriendsKey as NSString)!
                _ = setAllFriendsKey(account: itemFromAddress, aesKey: decryptedAllFriendsKey as String)
                let decryptedName = CryptoManager.decryptStringWithSymmetricKey(key: decryptedAllFriendsKey, base64Input: itemName as NSString)
                _ = setDecryptedNick(account: itemFromAddress, nickName: decryptedName as! String)
                // print(decryptedName)
            }
            // return publicKeyStr as! String;
        } catch let error as NSError{
            print (error.localizedDescription)
            return false
        }
        return true

    }
    @objc public func getSummary(account: NSString) -> Bool {
        /*
         request: request/summary/?param1=value1&param2=value2
         params: to_address=0x08438F6Cba0396B747d08951Ba75f79481F68A5d time_stamp=1523765429 b64encoded_signature=PPKOAbbrS4u8HVjDVYoT74DX7BO2U1sFL1f7UoPmO9fmY5ByRd5mRp8BFlyCeqbe2K5u9koW7FGW%0Aqbqjd9%2FFdi4UFFSnXsF8UI3ESwiXFatXpIHAgBUusqOayFh5sktZXaOUD3CqycGu9SsVFoHPYXuO%0AzNBFESubsPDXEFikgL6jQvNMrHkCYXbHliVaUfrDlEP1dFw1VZcwtBOVyadc6rqbyepokBNavf8I%0AxtxSd3XTF4RqVBvq27wfp2wYJqt%2BtmK4jYBrUVWC93Evye6hRfZfSNYQVNw6TnOU1MyZcXY73xdN%0AopXAO5FolriEHvPmdqriXwvDXbikoAZDh%2BRyvw%3D%3D%0A
         response:
         {
         "msg": "Success",
         "request": [
         {
         "from_address": "f021a64E5227A786AC2ed1A605Dcd3dD5B63A29b",
         "name": "GxYUXbZygO1gFCwgZVI32w==\n",
         "request": "e4Z+LqONOT0RSAToWfUSkxzMnLyMyZ7nJSGjn3lUxfjJM3+LccuPX+XoeG+RV10Edi/emvOjYGym\nvGPUUR8ksU0NUiVdU1X+9xNMdDoqgD4tn2KDzxsU8hwbdLeQjovtkOFksKwpIy0Tidrfe6YhyfFE\narPqtgH3TnP1/9tUjUZf/td1nBL2KRIABCEE+ccs//y6xldb5p8o4SaIUj3oYyNA2ACcz9HmXNgc\n5ks4LAwgyyllKjou4uwqaJxy644JNxgba44bIvp01z6uNar85ihP2cmSvHUwLshUxKyANVHQVSAW\ncnMLkRDzZ/1VMxhV/wZECo20lgXcimxrTawh2Q==\n"
         },
         {
         "from_address": "8E8b666F134EDd37D95eD182F5AC33d8a21E359E",
         "name": "GxYUXbZygO1gFCwgZVI32w==\n",
         "request": "Ub6yEsQEIdrNMf6OXsxw43XN5TnUK48oU61Hjg5sVi5j1daiBn1OFnjPuSHcFXLLyh9x8dw/MzUy\nEj6ykofLNl2OldvLEqlWkpXld+QJyZ5uatLP7nf9Z/HYSdz8sGPUOJAbITG5uGhBplZYZ5owEqny\nUftfu8EON83iBJX2O/AMXzw6ZFtHUv3B7JJZ23/NOivHZRq0aRQme/bSQ2SBACEmOmF4feZxZ+z3\nHAQTAkKCs1AMk67iXmq8m1pZu6s3vC5Tf0kkT/KLXyVJHpqOg2kkD4QBybC34x/UPZm3OUlhXuS8\npgBap7YbYU13WSRIpi2iKM3M8QO+W3x0gGT7Kg==\n"
         }
         ]
         }
        */
        
        var accountStr = account as String;
        if (accountStr.count <= 0) {
            accountStr = getAccount().getAddress().getHex()
        }
        var requestStr = "";
        requestStr += TAG_TO_ADDRESS + "=" + accountStr;
        
        let timeInterval = NSDate().timeIntervalSince1970
        let timeStr = String(format: "%.0f", timeInterval)
        requestStr += "&" + TAG_TIME_STAMP + "=" + timeStr

        let sign = CryptoManager.signStrWithPrivateKey(input: (timeStr as NSString), urlEncode: true)
        // print(sign!);
        requestStr += "&" + TAG_B64_ENCODED_SIGNATURE + "=" + (sign! as String)

        let data = sendGETRequest(urlString:(BASEURL + REQUEST_SUMMARY_API + requestStr + "/"))
        if (data == nil) {
            return false
        }
        let responseString = String(data: data!, encoding: String.Encoding.utf8)!

        return processSummary(summary: responseString)
    }
}
