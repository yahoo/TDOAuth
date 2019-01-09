// https://github.com/Quick/Quick

import Quick
import Nimble
@testable import TDOAuth

class TableOfContentsSpec: QuickSpec {
    override func spec() {
        describe("RFC Spec Tests") {

            describe("parameter normalization") {
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

                var request = URLRequest(url: URL(string: "https://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b")!)
                request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
                request.httpBody = "c2&a3=2+q".data(using: .utf8)

                let material: OAuth1Sha256Signer.KeyMaterial = (consumerSecret: "CONSUMER SECRET", accessTokenSecret: "TOKEN SECERT")
                let signer = OAuth1Sha256Signer(withMaterial: material)
                let oauth1: OAuth1<OAuth1Sha256Signer> = OAuth1(withConsumerKey: "KEY", accessToken: "TOKEN", signer: signer)
                let signedRequest = oauth1.sign(request: request)

                let authHeader = signedRequest?.value(forHTTPHeaderField: "Authorization")
                expect(signedRequest).toNot(beNil())
            }

        }
    }
}
