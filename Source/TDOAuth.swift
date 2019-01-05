//
//  TDOAuth.swift
//  TDOAuth
//
//  Created by Adam Kaplan on 9/19/18.
//

import UIKit
import CommonCrypto.CommonHMAC

/*
 + (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                    parameters:(NSDictionary *)unencodedParameters
                    host:(NSString *)host
                    consumerKey:(NSString *)consumerKey
                    consumerSecret:(NSString *)consumerSecret
                    accessToken:(NSString *)accessToken
                    tokenSecret:(NSString *)tokenSecret
                    scheme:(NSString *)scheme
                    requestMethod:(NSString *)method
                    dataEncoding:(TDOAuthContentType)dataEncoding
                    headerValues:(NSDictionary *)headerValues
                    signatureMethod:(TDOAuthSignatureMethod)signatureMethod;
 */

/// Generic protocol to support OAuth 1.0 signers, examples provided in the RFC:
/// HMAC-SHA1 (Client Secret + Shared Secret) https://tools.ietf.org/html/rfc5849#section-3.4.2
/// RSA-SHA1  (Client Secret) https://tools.ietf.org/html/rfc5849#section-3.4.3
/// PLAINTEXT (Client Secret + Shared Secret) https://tools.ietf.org/html/rfc5849#section-3.4.4
///
/// (SHA1 has not been secure in ages, but the spec allows any algo like SHA256)
public protocol OAuth1Signer {

    associatedtype KeyMaterial

    var signatureMethod: String { get }

    init(withMaterial: KeyMaterial)

    func sign(_ value: String) -> String
}

public class OAuth1Sha256Signer: OAuth1Signer {

    public typealias KeyMaterial = (consumerSecret: String, accessTokenSecret: String?)

    public let signatureMethod = "HMAC-SHA256"

    private let parBakedHmacContext: CCHmacContext

    public required init(withMaterial material: KeyMaterial) {
        var signingKey = OAuth1Sha256Signer.generateSigningKey(material: material)
        let signingKeyLength = signingKey.lengthOfBytes(using: String.Encoding.utf8)

        var context = CCHmacContext()
        let contextPtr = UnsafeMutablePointer(&context)
        CCHmacInit(contextPtr, CCHmacAlgorithm(kCCHmacAlgSHA256), &signingKey, signingKeyLength)
        parBakedHmacContext = context
    }

    public func sign(_ value: String) -> String {
        var valueLocal = value
        let valueLength = value.lengthOfBytes(using: .utf8)

        var context = parBakedHmacContext
        let signed = withUnsafeMutablePointer(to: &context) { ctx -> String in
            CCHmacUpdate(ctx, &valueLocal, valueLength)
            var buffer = UnsafeMutableBufferPointer<UInt32>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))
            CCHmacFinal(ctx, &buffer)
            let data = Data(buffer: buffer)
            return data.base64EncodedString()
        }
        return signed
    }

    // The signature secret is created by concatenating the consumer secret and access token
    public static func generateSigningKey(material: KeyMaterial) -> String {
        var generatedSecret = material.consumerSecret.appending("&")
        if let accessTokenSecret = material.accessTokenSecret {
            generatedSecret.append(contentsOf: accessTokenSecret)
        }
        return generatedSecret
    }
}

/// See https://tools.ietf.org/html/rfc5849
open class OAuth1<T: OAuth1Signer> {

    public let consumerKey: String

    public let accessToken: String?

    public var signer: T

    //private let oauthParameters: [String: Any]

    public init(withConsumerKey consumerKey: String, accessToken: String?, signer: T) {
        self.consumerKey = consumerKey
        self.accessToken = accessToken
        self.signer = signer

//        oauthParameters = [
//            "oauth_consumer_key":       consumerKey,
//            "oauth_nonce":              nonce(),
//            "oauth_timestamp":          timestamp(),
//            "oauth_version":            "1.0",
//            "oauth_signature_method":   signer.signatureMethod,
//            "oauth_token":              accessToken
//        ]
    }
}

//func x() {
//    let oa1 = OAuth1<OAuth1Sha256Signer>(withConsumerKey: "", consumerSecret: "", accessToken: nil, accessTokenSecret: nil)
//    oa1.signer = OAuth1Sha256Signer()
//}
