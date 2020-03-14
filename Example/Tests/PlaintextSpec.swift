// Copyright 2020, Verizon Media.
// Licensed under the terms of the MIT license. See LICENSE file in https://github.com/yahoo/TDOAuth for terms.

@testable import TDOAuth
import XCTest

// Most of the default values here are taken from the RFC 5839 examples
//
// A great resource to verify tests that are not covered by the RFC examples
// and for debugging is this fantastic tool: http://lti.tools/oauth/
class PlaintextSpec: XCTestCase {
    
    let rfcRequest = URLRequest(url: URL(string: "http://photos.example.net/photos?size=original&file=vacation.jpg")!)

    func testSignatureWithKeyAndSecret() {
        let rfcMaterial: PlaintextSigner.KeyMaterial = SharedSecrets(consumerSecret: "kd94hf93k423kf44", accessTokenSecret: "pfkkdhi9sl3r4s00")
        let signer = PlaintextSigner(keyMaterial: rfcMaterial)
        let oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)

        let signedRequest = oauth1.sign(request: rfcRequest)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth oauth_token=\"nnch734d00sl2jdk\", oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"PLAINTEXT\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"kd94hf93k423kf44%26pfkkdhi9sl3r4s00\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    func testSignatureWithKeyOnly() {
        let rfcMaterial: PlaintextSigner.KeyMaterial = SharedSecrets(consumerSecret: "kd94hf93k423kf44", accessTokenSecret: nil)
        let signer = PlaintextSigner(keyMaterial: rfcMaterial)
        let oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)

        let signedRequest = oauth1.sign(request: rfcRequest)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth oauth_token=\"nnch734d00sl2jdk\", oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"PLAINTEXT\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"kd94hf93k423kf44%26\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }
}
