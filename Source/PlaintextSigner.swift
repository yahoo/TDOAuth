import Foundation

public class PlaintextSigner: OAuth1Signer {

    public typealias KeyMaterial = (consumerSecret: String, accessTokenSecret: String?)

    public let signatureMethod = "PLAINTEXT"

    let signature: String

    public required init(keyMaterial: KeyMaterial) {
        signature = PlaintextSigner.generateSigningKey(material: keyMaterial)
    }

    public func sign(_ value: String) -> String {
        return signature
    }
}
