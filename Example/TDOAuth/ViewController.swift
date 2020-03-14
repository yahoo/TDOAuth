// Copyright 2020, Verizon Media.
// Licensed under the terms of the MIT license. See LICENSE file in https://github.com/yahoo/TDOAuth for terms.

import UIKit
import TDOAuth

class ViewController: UIViewController {

    // Provide these 4 values based on your specific use case
    // See the README file for additional examples.
    var consumerSecret: String = "my-consumer-secret"
    var consumerKey: String = "my-consmer-key"
    var accessToken: String? = nil
    var accessTokenSecret: String? = nil

    /// Generate our OAuth1 signer
    lazy var oauth1: OAuth1<HMACSigner> = {
        let secrets = SharedSecrets(consumerSecret: consumerSecret, accessTokenSecret: accessTokenSecret)
        let sha1Signer = HMACSigner(algorithm: .sha1, material: secrets)
        return OAuth1(withConsumerKey: consumerKey, accessToken: accessToken, signer: sha1Signer)
    }()

    /// Feed requests into our OAuth1 signer to produce signed versions of those requests.
    /// The only modificataion to the provided request is setting the Authorization HTTP header value.
    func makeSignedRequest() -> URLRequest? {
        guard let url = URL(string: "https://finance.yahoo.com") else { return nil }
        let request = URLRequest(url: url)

        let signedRequest = oauth1.sign(request: request)
        return signedRequest
    }
}
