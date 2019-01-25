// https://github.com/Quick/Quick

import Quick
import Nimble
@testable import TDOAuth

class TableOfContentsSpec: QuickSpec {
    override func spec() {
        // Most of the default values here are taken from the RFC 5839 examples
        //
        // A great resource to verify tests that are not covered by the RFC examples
        // and for debugging is this fantastic tool: http://lti.tools/oauth/

        let rfcRequest = URLRequest(url: URL(string: "http://photos.example.net/photos?size=original&file=vacation.jpg")!)

        let rfcMaterial: HMACSigner.KeyMaterial = (consumerSecret: "kd94hf93k423kf44", accessTokenSecret: "pfkkdhi9sl3r4s00")

        var signer: HMACSigner! = nil
        var oauth1: TestOAuth1<HMACSigner>! = nil

        beforeEach {
            signer = HMACSigner(algorithm: .sha1, material: rfcMaterial)
            oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)
        }

        describe("RFC 5839 Examples") {

            it("Conforms to RFC example section 3.1") {
                // POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
                // Host: example.com
                // Content-Type: application/x-www-form-urlencoded
                // Authorization: OAuth realm="Example",
                //      oauth_consumer_key="9djdj82h48djs9d2",
                //      oauth_token="kkk9d7dh3k39sjv7",
                //      oauth_signature_method="HMAC-SHA1",
                //      oauth_timestamp="137131201",
                //      oauth_nonce="7d8f3e4a",
                //      oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"
                //
                // c2&a3=2+q

                var request = URLRequest(url: URL(string: "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b")!)
                request.httpMethod = "POST"
                request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
                request.httpBody = "c2&a3=2+q".data(using: .utf8)

                let material: HMACSigner.KeyMaterial = (consumerSecret: "j49sk3j29djd", accessTokenSecret: "dh893hdasih9")
                signer = HMACSigner(algorithm: .sha1, material: material)
                oauth1 = TestOAuth1(withConsumerKey: "9djdj82h48djs9d2", accessToken: "kkk9d7dh3k39sjv7", signer: signer)
                oauth1.includeVersionParameter = false
                oauth1.testNonce = "7d8f3e4a"
                oauth1.testTimestamp = "137131201"

                let signedRequest = oauth1.sign(request: request, realm: "Example")
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth realm=\"Example\", oauth_consumer_key=\"9djdj82h48djs9d2\", oauth_nonce=\"7d8f3e4a\", oauth_timestamp=\"137131201\", oauth_signature_method=\"HMAC-SHA1\", oauth_token=\"kkk9d7dh3k39sjv7\", oauth_signature=\"r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            it("Conforms to RFC example section 1.2") {
                // POST /initiate HTTP/1.1
                // Host: photos.example.net
                // Authorization: OAuth realm="Photos",
                //      oauth_consumer_key="dpf43f3p2l4k3l03",
                //      oauth_signature_method="HMAC-SHA1",
                //      oauth_timestamp="137131200",
                //      oauth_nonce="wIjqoS",
                //      oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",
                //      oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"

                oauth1.includeVersionParameter = false
                oauth1.testNonce = "chapoH"
                oauth1.testTimestamp = "137131202"

                let signedRequest = oauth1.sign(request: rfcRequest, realm: "Photos")
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth realm=\"Photos\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"chapoH\", oauth_timestamp=\"137131202\", oauth_signature_method=\"HMAC-SHA1\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }
        }

        context("realm") {
            it("includes realm") {
                let signedRequest = oauth1.sign(request: rfcRequest, realm: "http://photos.example.net/photos")
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth realm=\"http://photos.example.net/photos\", oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA1\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            it("excludes realm") {
                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA1\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }
        }

        context("version") {
            it("includes version") {
                oauth1.includeVersionParameter = true

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA1\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            it("excludes version") {
                oauth1.includeVersionParameter = false

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA1\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"dLOLK%2BRer90siIrHXE0LMA6Y6X4%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }
        }

        context("access token") {
            it("includes access token") {
                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA1\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            it("excludes access token") {
                let rfcMaterial: HMACSigner.KeyMaterial = (consumerSecret: "kd94hf93k423kf44", accessTokenSecret: nil)
                signer = HMACSigner(algorithm: .sha1, material: rfcMaterial)
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: nil, signer: signer)

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA1\", oauth_version=\"1.0\", oauth_signature=\"Jg5MXVnexhzMDTv7IBUy3goIGqc%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            // This is a nonsensical edge case wherein the access_token is optional
            // but the RFC does not state that the token_secret MUST be omitted
            // if the access_token is not provided. Logically the client wouldn't
            // have a secret without a token, but whatever...
            it("excludes access token, but has token secret") {
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: nil, signer: signer)

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA1\", oauth_version=\"1.0\", oauth_signature=\"WxydVSuTSrs7nu8nqCUpbRQuu%2FU%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }
        }
    }
}
