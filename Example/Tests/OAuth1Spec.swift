// Copyright 2020, Verizon Media.
// Licensed under the terms of the MIT license. See LICENSE file in https://github.com/yahoo/TDOAuth for terms.

@testable import TDOAuth
import XCTest

// Most of the default values here are taken from the RFC 5839 examples
//
// A great resource to verify tests that are not covered by the RFC examples
// and for debugging is this fantastic tool: http://lti.tools/oauth/
class RFC5839Spec: XCTestCase {
    let rfcRequest = URLRequest(url: URL(string: "http://photos.example.net/photos?size=original&file=vacation.jpg")!)

    let rfcMaterial: HMACSigner.KeyMaterial = SharedSecrets(consumerSecret: "kd94hf93k423kf44", accessTokenSecret: "pfkkdhi9sl3r4s00")

    var signer: HMACSigner! = nil
    var oauth1: TestOAuth1<HMACSigner>! = nil

    override func setUp() {
        signer = HMACSigner(algorithm: .sha1, material: rfcMaterial)
        oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)
    }

    //MARK: - RFC Examples

    func testConformsToSection3_1() {
        // Example from RFC:
        //
        // POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
        // Host: example.com
        // Content-Type: application/x-www-form-urlencoded
        // Authorization: OAuth realm="Example",
        //      oauth_consumer_key="9djdj82h48djs9d2",
        //      oauth_token="kkk9d7dh3k39sjv7",
        //      oauth_signature_method="HMAC-SHA1",
        //      oauth_timestamp="137131201",
        //      oauth_nonce="7d8f3e4a",
        //      oauth_signature="r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D"
        //
        // c2&a3=2+q
        // NOTE:
        // The RFC shows a different oauth_signature, but it is wrong. The correct
        // signature is depicted above, per http://www.rfc-editor.org/errata/eid2550

        var request = URLRequest(url: URL(string: "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b")!)
        request.httpMethod = "POST"
        request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = "c2&a3=2+q".data(using: .utf8)

        let material: HMACSigner.KeyMaterial = SharedSecrets(consumerSecret: "j49sk3j29djd", accessTokenSecret: "dh893hdasih9")
        let signer = HMACSigner(algorithm: .sha1, material: material)
        let oauth1 = TestOAuth1(withConsumerKey: "9djdj82h48djs9d2", accessToken: "kkk9d7dh3k39sjv7", signer: signer)
        oauth1.testNonce = "7d8f3e4a"
        oauth1.testTimestamp = "137131201"

        let signedRequest = oauth1.sign(request: request, realm: "Example", includeVersionParameter: false)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth realm=\"Example\", oauth_token=\"kkk9d7dh3k39sjv7\", oauth_nonce=\"7d8f3e4a\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"9djdj82h48djs9d2\", oauth_timestamp=\"137131201\", oauth_signature=\"r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    func testConformsToSection1_2() {
        // Example from Section 1.2
        //
        // POST /initiate HTTP/1.1
        // Host: photos.example.net
        // Authorization: OAuth realm="Photos",
        //      oauth_consumer_key="dpf43f3p2l4k3l03",
        //      oauth_signature_method="HMAC-SHA1",
        //      oauth_timestamp="137131200",
        //      oauth_nonce="wIjqoS",
        //      oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",
        //      oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"

        let signer = HMACSigner(algorithm: .sha1, material: SharedSecrets(consumerSecret: "kd94hf93k423kf44", accessTokenSecret: nil))
        let oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: nil, signer: signer)
        oauth1.testNonce = "wIjqoS"
        oauth1.testTimestamp = "137131200"

        var request = URLRequest(url: URL(string: "https://photos.example.net/initiate")!)
        request.httpMethod = "POST"
        let signedRequest = oauth1.sign(request: request, callback: "http://printer.example.com/ready", realm: "Photos", includeVersionParameter: false)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth realm=\"Photos\", oauth_nonce=\"wIjqoS\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"137131200\", oauth_callback=\"http%3A%2F%2Fprinter.example.com%2Fready\", oauth_signature=\"74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

//    func testConformsToSection2_1() {
//        // Example from Section 2.1
//        //
//        // POST /request_temp_credentials HTTP/1.1
//        // Host: server.example.com
//        // Authorization: OAuth realm="Example",
//        //    oauth_consumer_key="jd83jd92dhsh93js",
//        //    oauth_signature_method="PLAINTEXT",
//        //    oauth_callback="http%3A%2F%2Fclient.example.net%2Fcb%3Fx%3D1",
//        //    oauth_signature="ja893SD9%26"
//
//        oauth1.includeVersionParameter = false
//        oauth1.testNonce = "chapoH"
//        oauth1.testTimestamp = "137131202"
//
//        let plaintextSigner = PlaintextSigner(keyMaterial: (consumerSecret: "", accessTokenSecret: nil)
//        let oauth1Plaintext = OAuth1(withConsumerKey: "jd83jd92dhsh93js", accessToken: nil, signer: plaintextSigner)
//        let signedRequest = oauth1Plaintext.sign(request: rfcRequest, realm: "Example")
//        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")
//
//        let expected = "OAuth realm=\"Photos\", oauth_token=\"nnch734d00sl2jdk\", oauth_nonce=\"chapoH\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"137131202\", oauth_signature=\"MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D\""
//
//        XCTAssertNotNil(signedRequest)
//        XCTAssertEqual(authHeader, expected)
//    }

    //MARK: - Realm

    func testRealm_includesRealm() {
        let signedRequest = oauth1.sign(request: rfcRequest, realm: "http://photos.example.net/photos")
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth realm=\"http://photos.example.net/photos\", oauth_token=\"nnch734d00sl2jdk\", oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    func testRealm_excludesRealm() {
        let signedRequest = oauth1.sign(request: rfcRequest)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth oauth_token=\"nnch734d00sl2jdk\", oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    //MARK: - Version

    func testVersion_includesVersion() {
        let signedRequest = oauth1.sign(request: rfcRequest, includeVersionParameter: true)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth oauth_token=\"nnch734d00sl2jdk\", oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    func testVersion_excludesVersion() {
        let signedRequest = oauth1.sign(request: rfcRequest, includeVersionParameter: false)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth oauth_token=\"nnch734d00sl2jdk\", oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_signature=\"dLOLK%2BRer90siIrHXE0LMA6Y6X4%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    //MARK: - Access Token

    func testAccessToken_includesAccessToken() {
        let signedRequest = oauth1.sign(request: rfcRequest)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth oauth_token=\"nnch734d00sl2jdk\", oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    func testAccessToken_excludesAccessToken() {
        let rfcMaterial: HMACSigner.KeyMaterial = SharedSecrets(consumerSecret: "kd94hf93k423kf44", accessTokenSecret: nil)
        signer = HMACSigner(algorithm: .sha1, material: rfcMaterial)
        oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: nil, signer: signer)

        let signedRequest = oauth1.sign(request: rfcRequest)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"Jg5MXVnexhzMDTv7IBUy3goIGqc%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    // This is a nonsensical edge case wherein the access_token is optional
    // but the RFC does not state that the token_secret MUST be omitted
    // if the access_token is not provided. Logically the client wouldn't
    // have a secret without a token, but whatever...
    func testAccessToken_excludesAccessTokenNotSecret() {
        oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: nil, signer: signer)

        let signedRequest = oauth1.sign(request: rfcRequest)
        let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        let expected = "OAuth oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"WxydVSuTSrs7nu8nqCUpbRQuu%2FU%3D\""

        XCTAssertNotNil(signedRequest)
        XCTAssertEqual(authHeader, expected)
    }

    func testIgnoresHostCase() {
        oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: nil, signer: signer)

        let signedRequest = oauth1.sign(request: rfcRequest)
        let expectAuthHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        var uppercaseRequest = rfcRequest
        var components = URLComponents(url: uppercaseRequest.url!, resolvingAgainstBaseURL: false)
        let uppercaseHost = components?.host?.uppercased()
        components?.host = uppercaseHost
        uppercaseRequest.url = components?.url!

        let signedRequest2 = oauth1.sign(request: uppercaseRequest)
        let gotAuthHeader = signedRequest2?.value(forHTTPHeaderField: "Authorization")

        XCTAssertNotNil(signedRequest2)
        XCTAssertEqual(expectAuthHeader, gotAuthHeader)
    }

    func testIgnoresSchemeCase() {
        oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: nil, signer: signer)

        let signedRequest = oauth1.sign(request: rfcRequest)
        let expectAuthHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        var uppercaseRequest = rfcRequest
        var components = URLComponents(url: uppercaseRequest.url!, resolvingAgainstBaseURL: false)
        let uppercaseHost = components?.scheme?.uppercased()
        components?.scheme = uppercaseHost
        uppercaseRequest.url = components?.url!

        let signedRequest2 = oauth1.sign(request: uppercaseRequest)
        let gotAuthHeader = signedRequest2?.value(forHTTPHeaderField: "Authorization")

        XCTAssertNotNil(signedRequest2)
        XCTAssertEqual(expectAuthHeader, gotAuthHeader)
    }

    func testRespectsTrailingSlashesCase() {
        oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: nil, signer: signer)

        var components = URLComponents(url: rfcRequest.url!, resolvingAgainstBaseURL: false)
        components?.path = "/a/b/c/"
        var request = rfcRequest
        request.url = components?.url!

        let signedRequest = oauth1.sign(request: request)
        let gotAuthHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

        XCTAssertNotNil(signedRequest)
        let expect = "OAuth oauth_nonce=\"kllo9940pd9333jh\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_timestamp=\"1191242096\", oauth_version=\"1.0\", oauth_signature=\"ixhhhte3356BnKrwap0ZttXlIFg%3D\""
        XCTAssertEqual(expect, gotAuthHeader)
    }
}
