import Foundation
@testable import TDOAuth

public class TestOAuth1<T: OAuth1Signer>: OAuth1<T> {
    public var testNonce = "kllo9940pd9333jh"
    public override var nonce: String { return testNonce }

    public var testTimestamp = "1191242096"
    public override var timestamp: String { return testTimestamp  }
}
