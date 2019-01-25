import Foundation

/// Generic protocol to support OAuth 1.0 signers, examples provided in the RFC:
/// HMAC-SHA1 (Client Secret + Shared Secret) https://tools.ietf.org/html/rfc5849#section-3.4.2
/// RSA-SHA1  (Client Secret) https://tools.ietf.org/html/rfc5849#section-3.4.3
/// PLAINTEXT (Client Secret + Shared Secret) https://tools.ietf.org/html/rfc5849#section-3.4.4
///
/// (SHA1 has not been secure in ages, but the spec allows any algo like SHA256)
public protocol OAuth1Signer {

    associatedtype KeyMaterial

    var signatureMethod: String { get }

    init(keyMaterial: KeyMaterial)

    func sign(_ value: String) -> String
}

public extension OAuth1Signer where KeyMaterial == (consumerSecret: String, accessTokenSecret: String?) {

    // The signature secret is created by concatenating the consumer secret and access token
    public static func generateSigningKey(material: KeyMaterial) -> String {
        var generatedSecret = material.consumerSecret.appending("&")
        if let accessTokenSecret = material.accessTokenSecret {
            generatedSecret.append(contentsOf: accessTokenSecret)
        }
        return generatedSecret
    }
}

