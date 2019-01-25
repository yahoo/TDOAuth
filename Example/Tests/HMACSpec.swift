// https://github.com/Quick/Quick

import Quick
import Nimble
@testable import TDOAuth

class HMACSpec: QuickSpec {
    override func spec() {
        // Most of the default values here are taken from the RFC 5839 examples
        //
        // A great resource to verify tests that are not covered by the RFC examples
        // and for debugging is this fantastic tool: http://lti.tools/oauth/
        describe("hmac signatures") {

            let rfcRequest = URLRequest(url: URL(string: "http://photos.example.net/photos?size=original&file=vacation.jpg")!)

            let rfcMaterial: HMACSigner.KeyMaterial = (consumerSecret: "kd94hf93k423kf44", accessTokenSecret: "pfkkdhi9sl3r4s00")

            var signer: HMACSigner! = nil
            var oauth1: TestOAuth1<HMACSigner>! = nil

            beforeEach {
                signer = HMACSigner(algorithm: .sha1, material: rfcMaterial)
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)
            }
            
            it("uses sha224") {
                signer = HMACSigner(algorithm: .sha224, material: rfcMaterial)
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA224\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"ycgflrLS%2B1kf4HAiA5YbFWTlosayqxpESKfC%2FA%3D%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            it("uses sha256") {
                signer = HMACSigner(algorithm: .sha256, material: rfcMaterial)
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA256\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"WVPzl1j6ZsnkIjWr7e3OZ3jkenL57KwaLFhYsroX1hg%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            it("uses sha384") {
                signer = HMACSigner(algorithm: .sha384, material: rfcMaterial)
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA384\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"l59uSHEtmBKa3ePDQbKT3yYr7KBiI9NbN0qX6xj594WQz%2FcWLoTX1871hNYq2Q6P\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            it("uses sha512") {
                signer = HMACSigner(algorithm: .sha512, material: rfcMaterial)
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"HMAC-SHA512\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"nQYVqZl8EkEH4fThSn%2B25i1gc68aX%2BFHTHSAXrxIl2ixdAofXM%2Fpq2x90UaOFIZQxvkzE5VRZpPbjo6i%2Bfe6rg%3D%3D\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

        }
    }
}
