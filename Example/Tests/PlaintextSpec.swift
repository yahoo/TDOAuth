// https://github.com/Quick/Quick

import Quick
import Nimble
@testable import TDOAuth

class PlaintextSpec: QuickSpec {
    override func spec() {
        // Most of the default values here are taken from the RFC 5839 examples
        //
        // A great resource to verify tests that are not covered by the RFC examples
        // and for debugging is this fantastic tool: http://lti.tools/oauth/
        describe("plaintext signature") {

            let rfcRequest = URLRequest(url: URL(string: "http://photos.example.net/photos?size=original&file=vacation.jpg")!)

            var rfcMaterial: PlaintextSigner.KeyMaterial! = nil
            var signer: PlaintextSigner! = nil
            var oauth1: TestOAuth1<PlaintextSigner>! = nil

            it("signs with key and secret") {
                rfcMaterial = (consumerSecret: "kd94hf93k423kf44", accessTokenSecret: "pfkkdhi9sl3r4s00")
                signer = PlaintextSigner(keyMaterial: rfcMaterial)
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"PLAINTEXT\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"kd94hf93k423kf44%26pfkkdhi9sl3r4s00\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

            it("signs with key only") {
                rfcMaterial = (consumerSecret: "kd94hf93k423kf44", accessTokenSecret: nil)
                signer = PlaintextSigner(keyMaterial: rfcMaterial)
                oauth1 = TestOAuth1(withConsumerKey: "dpf43f3p2l4k3l03", accessToken: "nnch734d00sl2jdk", signer: signer)

                let signedRequest = oauth1.sign(request: rfcRequest)
                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")

                let expected = "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_nonce=\"kllo9940pd9333jh\", oauth_timestamp=\"1191242096\", oauth_signature_method=\"PLAINTEXT\", oauth_version=\"1.0\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature=\"kd94hf93k423kf44%26\""

                expect(signedRequest).toNot(beNil())
                expect(authHeader).to(equal(expected))
            }

        }
    }
}
