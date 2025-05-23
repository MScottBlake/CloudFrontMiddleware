//
//  CloudFrontMiddleware.swift
//  CloudFrontMiddleware
//
//  Created by Greg Neagle on 5/16/25.
//

import Foundation
import Security

private let BUNDLE_ID = "com.github.aaronburchfield.cloudfront" as CFString
private let CERT_PREFERENCE_NAME = "cloudfront_certificate"

/// read a preference
func pref(_ prefName: String) -> Any? {
    return CFPreferencesCopyAppValue(prefName as CFString, BUNDLE_ID)
}

/// Attempt to get the private key, first trying preferences, then looking for a local file
func getPrivateKey() -> SecKey? {
    // paths to search for file containing our private key
    let keyFilename = "munkiaccess.pem"
    let keyFilePaths = [
        (Bundle.main.bundlePath as NSString).appendingPathComponent("middleware/\(keyFilename)"),
        (Bundle.main.bundlePath as NSString).appendingPathComponent(keyFilename),
    ]

    if let prefCert = pref(CERT_PREFERENCE_NAME) as? String {
        // this should be a base64-encoded string
        if let data = Data(base64Encoded: prefCert) {
            return rsaPrivateKeyFromPemData(data)
        }
        // maybe it's just a "raw" PEM string
        return rsaPrivateKeyFromPemString(prefCert)
    }
    if let prefCert = pref(CERT_PREFERENCE_NAME) as? Data {
        return rsaPrivateKeyFromPemData(prefCert)
    }
    // pref wasn't set, or wrong type, try to read from a file
    for pathname in keyFilePaths {
        if FileManager.default.fileExists(atPath: pathname),
           let data = FileManager.default.contents(atPath: pathname)
        {
            return rsaPrivateKeyFromPemData(data)
        }
    }

    // we got nothin'
    return nil
}

/// Return a request policy signature.
func signRequestPolicy(_ requestPolicy: String, withKey key: SecKey) -> String {
    guard let signatureData = signSHA1(Data(requestPolicy.utf8), withKey: key) else {
        return ""
    }
    let signtureString = signatureData.base64EncodedString()
    return signtureString
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "=", with: "_")
        .replacingOccurrences(of: "/", with: "~")
}

/// encode policy request dict as json-formatted string
func makeJsonPolicyRequest(url: String, expires: Int) -> String {
    // TODO: this will break if url has quotes
    // (are we going to encounter unencoded quote characters here?)
    return """
    {"Statement":[{"Resource":"\(url)","Condition":{"DateLessThan":{"AWS:EpochTime":\(expires)}}}]}
    """
    // the following is the "correct" way to do this, but the ordering of the elements in the
    // generated string is different that that of the Python implementation, making it difficult
    // to prove the Swift code is doing the same (equivalent) thing
    /*
     let requestPolicyDict = [
         "Statement": [
             ["Resource": url, "Condition": ["DateLessThan": ["AWS:EpochTime": "\(expires)"]]]
         ]
     ]
     if JSONSerialization.isValidJSONObject(requestPolicyDict),
        let requestPolicyData = try? JSONSerialization.data(withJSONObject: requestPolicyDict, options: []),
        let requestPolicyString = String(data: requestPolicyData, encoding: .utf8)
     {
         return requestPolicyString.replacingOccurrences(of: " ", with: "")
     }
     return ""
      */
}

/// Assemble a CloudFront request.
func assembleCloudFrontRequest(url: String, key: SecKey, accessId: String, expires: Int) -> String {
    // Format a request policy for the resource
    let requestPolicy = makeJsonPolicyRequest(url: url, expires: expires)
    // Sign and encode request policy
    let signature = signRequestPolicy(requestPolicy, withKey: key)
    // Format and return the final request URL
    return "\(url)?Expires=\(expires)&Signature=\(signature)&Key-Pair-Id=\(accessId)"
}

/// Generate a CloudFront URL
func generateCloudFrontURL(_ url: String) -> String {
    guard let key = getPrivateKey() else {
        return url
    }
    let accessId = pref("access_id") as? String ?? ""
    let expireAfter = pref("expire_after") as? Int ?? 60
    let expires = Int(Date().timeIntervalSince1970) + expireAfter * 60
    return assembleCloudFrontRequest(url: url, key: key, accessId: accessId, expires: expires)
}

class CloudFrontMiddleware: MunkiMiddleware {
    /// Modify the request URL to contain a signature for CloudFront
    func processRequest(_ request: MunkiMiddlewareRequest) -> MunkiMiddlewareRequest {
        // TODO: don't modify the URL if it's not a CloudFront URL
        // IOW, check if URL contains cloudfront.net, or a specific domain specified
        // by the admin in a preference. Similar to how the s3 middleware does it:
        // let s3endpoint = pref("S3Endpoint") as? String ?? "s3.amazonaws.com"
        let url = generateCloudFrontURL(request.url)
        var modifiedRequest = request
        modifiedRequest.url = url
        return modifiedRequest
    }
}

// MARK: dylib "interface"

final class CloudFrontMiddlewareBuilder: MiddlewarePluginBuilder {
    override func create() -> MunkiMiddleware {
        return CloudFrontMiddleware()
    }
}

/// Function with C calling style for our dylib.
/// We use it to instantiate the MunkiMiddleware object and return an instance
@_cdecl("createPlugin")
public func createPlugin() -> UnsafeMutableRawPointer {
    return Unmanaged.passRetained(CloudFrontMiddlewareBuilder()).toOpaque()
}
