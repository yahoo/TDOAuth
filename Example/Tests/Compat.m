// Copyright 2020, Verizon Media.
// Licensed under the terms of the MIT license. See LICENSE file in https://github.com/yahoo/TDOAuth for terms.

#import <XCTest/XCTest.h>
#import <TDOAuth/TDOAuth.h>
#import "TDOAuth_Tests-Swift.h"

@interface ObjcCompatSpec : XCTestCase @end

@implementation ObjcCompatSpec

+ (void)setUp {
    [super setUp];
    [TDOAuthCompat setTestSigner];
}

+ (NSURLRequest *)makeGetRequest
{
    return [TDOAuth URLRequestForPath:@"/service"
                        GETParameters:@{@"foo": @"bar"}
                                 host:@"api.example.com"
                          consumerKey:@"abcd"
                       consumerSecret:@"efgh"
                          accessToken:@"ijkl"
                          tokenSecret:@"mnop"];
}

+ (NSURLRequest *)makeGetComponentsRequest
{
    NSURLComponents *components = [NSURLComponents new];
    components.scheme = @"http";
    components.host = @"api.example.com";
    components.path = @"/service";
    components.queryItems = @[[NSURLQueryItem queryItemWithName:@"foo" value:@"baz"],
                              [NSURLQueryItem queryItemWithName:@"foo" value:@"bar"]];
    return [TDOAuth URLRequestForGETURLComponents:components
                                      consumerKey:@"abcd"
                                   consumerSecret:@"efgh"
                                      accessToken:@"ijkl"
                                      tokenSecret:@"mnop"];
}

+ (NSURLRequest *)makePostRequest
{
    return [TDOAuth URLRequestForPath:@"/service"
                       POSTParameters:@{@"foo": @"bar"}
                                 host:@"api.example.com"
                          consumerKey:@"abcd"
                       consumerSecret:@"efgh"
                          accessToken:@"ijkl"
                          tokenSecret:@"mnop"];
}
+ (NSURLRequest *)makePostRequestWithDataEncoding:(TDOAuthContentType)dataEncoding
{
    return [TDOAuth URLRequestForPath:@"/service"
                           parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                 host:@"api.example.com"
                          consumerKey:@"abcd"
                       consumerSecret:@"efgh"
                          accessToken:@"ijkl"
                          tokenSecret:@"mnop"
                               scheme:@"http"
                        requestMethod:@"POST"
                         dataEncoding:dataEncoding
                         headerValues:nil
                      signatureMethod:TDOAuthSignatureMethodHmacSha1];
}
+ (NSURLRequest *)makeGenericRequestWithHTTPMethod:(NSString *)method
{
    return [TDOAuth URLRequestForPath:@"/service"
                           parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                 host:@"api.example.com"
                          consumerKey:@"abcd"
                       consumerSecret:@"efgh"
                          accessToken:@"ijkl"
                          tokenSecret:@"mnop"
                               scheme:@"http"
                        requestMethod:method
                         dataEncoding:TDOAuthContentTypeUrlEncodedForm
                         headerValues:nil
                      signatureMethod:TDOAuthSignatureMethodHmacSha1];
}

- (void)testGetMethod
{
    NSURLRequest *getRequest = [self.class makeGetRequest];
    XCTAssert([[getRequest HTTPMethod] isEqualToString:@"GET"],
              "method (verb) expected to be GET");
}

- (void)testGetBody
{
    NSURLRequest *getRequest = [self.class makeGetRequest];
    NSData *body = [getRequest HTTPBody];
    //NSString *bodyString = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    XCTAssertNil(body,
                 "body expected to be nil");
}

- (void)testGetUrl
{
    NSURLRequest *getRequest = [self.class makeGetRequest];
    NSString *url = [[getRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"http://api.example.com/service?foo=bar"],
              "url does not match expected value");

    NSString *contentType = [getRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssertNil(contentType,
              @"Content-Type was present when not expected)");

    NSString *contentLength = [getRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssertNil(contentLength,
              @"Content-Length was set when not expected)");

}

#ifdef TEST_NSURLCOMPONENTS
- (void)testGetComponentsUrl
{
    NSURLRequest *getRequest = [TDOAuthTest makeGetComponentsRequest];
    NSString *url = [[getRequest URL] absoluteString];
    XCTAssertEqualObjects(url, @"http://api.example.com/service?foo=baz&foo=bar",
              "url does not match expected value");

    NSString *contentType = [getRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssertNil(contentType,
              @"Content-Type was present when not expected)");

    NSString *contentLength = [getRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssertNil(contentLength,
              @"Content-Length was set when not expected)");

}
#endif

- (void)testGetUrlWithHttps
{
    NSURLRequest *httpsRequest = [TDOAuth URLRequestForPath: @"/service"
                                              GETParameters:@{@"foo": @"bar"}
                                                     scheme:@"https"
                                                       host:@"api.example.com"
                                                consumerKey:@"abcd"
                                             consumerSecret:@"efgh"
                                                accessToken:@"ijkl"
                                                tokenSecret:@"mnop"];
    NSString *url = [[httpsRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"https://api.example.com/service?foo=bar"],
              @"url does not match expected value");


}
- (void)testGetHeaderAuthField
{
    NSURLRequest *getRequest = [self.class makeGetRequest];
    NSString *authHeader = [getRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
                                "oauth_nonce=\"static-nonce-for-testing\", "\
                                "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
                                "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
                                "oauth_signature=\"O4hspbDTqHlLdqfXxR0jSly9bkU%3D\"";
    XCTAssertEqualObjects(authHeader, expectedHeader,
              @"Expected header value does does not match");
}

- (void)testGetComponentsHeaderAuthField
{
    NSURLRequest *getRequest = [self.class makeGetComponentsRequest];
    NSString *authHeader = [getRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
                                "oauth_nonce=\"static-nonce-for-testing\", "\
                                "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
                                "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
                                "oauth_signature=\"jNwFfrG89t4oSjeWzEy%2BTH%2F2qzk%3D\"";
    XCTAssertEqualObjects(authHeader, expectedHeader,
              @"Expected header value does does not match");
}

- (void)testPostMethod
{
    NSURLRequest *postRequest = [self.class makePostRequest];
    XCTAssert([[postRequest HTTPMethod] isEqualToString:@"POST"],
              "method (verb) expected to be POST");
}
- (void)testPostBody
{
    NSURLRequest *postRequest = [self.class makePostRequest];
    NSData *body = [postRequest HTTPBody];
    NSString *bodyString = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    XCTAssert([bodyString isEqualToString:@"foo=bar"],
              "body expected to be structured");
}

- (void)testPostUrl
{
    NSURLRequest *postRequest = [self.class makePostRequest];
    NSString *url = [[postRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"https://api.example.com/service"],
              "url does not match expected value");

    NSString *contentType = [postRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssert([contentType isEqualToString:@"application/x-www-form-urlencoded"],
              @"Content-Type is not expected value)");

    NSString *contentLength = [postRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssert([contentLength isEqualToString:@"7"],
              @"Content-Length is not expected value)");

    NSString *acceptValue = [postRequest valueForHTTPHeaderField: @"Accept"];
    XCTAssertNil(acceptValue,
                 @"Accept is not expected value)");

}

- (void)testPostUrlParameters
{
    NSURLRequest *postRequest = [self.class makePostRequestWithDataEncoding:TDOAuthContentTypeUrlEncodedQuery];

    NSString *url = [[postRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"http://api.example.com/service?foo=bar&baz=bonk"],
              "url does not match expected value");

    NSString *contentType = [postRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssertNil(contentType,
                 @"Content-Type was present when not expected)");

    NSString *contentLength = [postRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssertNil(contentLength,
                 @"Content-Length was set when not expected)");
}

- (void)testPostHeaderAuthField
{
    NSURLRequest *postRequest = [self.class makePostRequest];
    NSString *authHeader = [postRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"pr%2ForWfyT9CsKTGW85AwjHmFjd8%3D\"";
    XCTAssertEqualObjects(authHeader, expectedHeader,
              @"Expected header value does does not match");
}

- (void)testHeadUrl
{
    NSURLRequest *headRequest = [self.class makeGenericRequestWithHTTPMethod:@"HEAD"];

    NSString *url = [[headRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"http://api.example.com/service?foo=bar&baz=bonk"],
              "url does not match expected value");

    NSString *contentType = [headRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssertNil(contentType,
                 @"Content-Type was present when not expected)");

    NSString *contentLength = [headRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssertNil(contentLength,
                 @"Content-Length was set when not expected)");

}

- (void)testDeleteUrl
{
    NSURLRequest *deleteRequest = [self.class makeGenericRequestWithHTTPMethod:@"DELETE"];

    NSString *url = [[deleteRequest URL] absoluteString];
    XCTAssertEqualObjects(url, @"http://api.example.com/service?foo=bar&baz=bonk",
              "url does not match expected value");

    NSString *contentType = [deleteRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssertNil(contentType,
                 @"Content-Type was present when not expected)");

    NSString *contentLength = [deleteRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssertNil(contentLength,
                 @"Content-Length was set when not expected)");

}

- (void)testGenericCallHasRightMethod
{
    NSURLRequest *genericRequest = [self.class makeGenericRequestWithHTTPMethod:@"BEG"];
    XCTAssert([[genericRequest HTTPMethod] isEqualToString:@"BEG"],
              "method (verb) expected to be BEG");
}

- (void)testGenericRequiresPath
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:nil
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"http"
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeUrlEncodedForm
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    XCTAssertNil(genericRequest,
                 "should fail when path is missing");
}

- (void)testGenericRequiresHost
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:nil
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"http"
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeUrlEncodedForm
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    XCTAssertNil(genericRequest,
                 "should fail when host is missing");
}


- (void)testGenericRequiresScheme
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:nil
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeUrlEncodedForm
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    XCTAssertNil(genericRequest,
              "should fail when scheme is missing");
}

- (void)testGenericRequiresMethod
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"http"
                                                requestMethod:nil
                                                 dataEncoding:TDOAuthContentTypeUrlEncodedForm
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    XCTAssertNil(genericRequest,
                 "should fail when method is missing");
}
- (void)testGenericJson
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"http"
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeJsonObject
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    NSString *url = [[genericRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"http://api.example.com/service"],
              "url does not match expected value");

    NSString *contentType = [genericRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssert([contentType isEqualToString:@"application/json"],
              @"Content-Type is not expected value)");

    NSString *contentLength = [genericRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssert([contentLength isEqualToString:@"26"],
              @"Content-Length is not expected value)");

    NSString *acceptValue = [genericRequest valueForHTTPHeaderField: @"Accept"];
    XCTAssertNil(acceptValue,
              @"Accept should not be present");

    NSData *body = [genericRequest HTTPBody];
    NSString *bodyString = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    XCTAssert([bodyString isEqualToString:@"{\"foo\":\"bar\",\"baz\":\"bonk\"}"],
              "body expected to be JSON object");

}
- (void)testGenericJsonWithNoData
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:nil
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"http"
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeJsonObject
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    NSString *url = [[genericRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"http://api.example.com/service"],
              "url does not match expected value");

    NSString *contentType = [genericRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssertNil(contentType,
              @"Content-Type should not be present");

    NSString *contentLength = [genericRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssertNil(contentLength,
                 @"Content-Length should not be present");

    NSString *acceptValue = [genericRequest valueForHTTPHeaderField: @"Accept"];
    XCTAssertNil(acceptValue,
                 @"Accept should not be present");

    NSData *body = [genericRequest HTTPBody];
    XCTAssertNil(body,
                 @"body should not be present");

}

- (void)testGenericUrl
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"ftp" // Not really valid, but it lets us test
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeUrlEncodedForm
                                                 headerValues:@{@"Accept": @"application/json"}
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    NSString *url = [[genericRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"ftp://api.example.com/service"],
              "url does not match expected value");

    NSString *contentType = [genericRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssert([contentType isEqualToString:@"application/x-www-form-urlencoded"],
              @"Content-Type is not expected value)");

    NSString *contentLength = [genericRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssert([contentLength isEqualToString:@"16"],
              @"Content-Length is not expected value)");

    NSString *acceptValue = [genericRequest valueForHTTPHeaderField: @"Accept"];
    XCTAssert([acceptValue isEqualToString:@"application/json"],
              @"Accept is not expected value)");
}
- (void)testGenericHeaderAuthField
{
    NSURLRequest *genericRequest = [self.class makeGenericRequestWithHTTPMethod:@"BEG"];
    NSString *authHeader = [genericRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"ycBj862NX5D9cCFrtWcBU2uzkdc%3D\"";
    XCTAssertEqualObjects(authHeader, expectedHeader,
              @"Expected header value does does not match");
}
- (void)testGenericEncodesJson
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"http" // Not really valid, but it lets us test
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeJsonObject
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    NSString *authHeader = [genericRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"%2FUo90sRcITkznrl9UoOqN8fCv40%3D\"";
    XCTAssertEqualObjects(authHeader, expectedHeader,
              @"Expected header value does does not match");
}
- (void)testGenericRecognizesSHA256
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"ftp" // Not really valid, but it lets us test
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeUrlEncodedForm
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha256];
    NSString *authHeader = [genericRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA256\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"pRxssqcfFnrUqF7i2L5j%2BpCk57gu33m3c9az5kNGors%3D\"";
    XCTAssertEqualObjects(authHeader, expectedHeader,
              @"Expected header value does does not match");
}
- (void)testGenericRejectsInvalidSignatureMethod
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"ftp" // Not really valid, but it lets us test
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeUrlEncodedForm
                                                 headerValues:nil
                                              signatureMethod:(TDOAuthSignatureMethod)1234];
    XCTAssertNil(genericRequest,
                 @"Expected request to fail with invalid hash function");
}
- (void)testGenericRejectsInvalidContentType
{
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"ftp" // Not really valid, but it lets us test
                                                requestMethod:@"BEG"
                                                 dataEncoding:(TDOAuthContentType)1234
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    XCTAssertNil(genericRequest,
                 @"Expected request to fail with invalid hash function");
}

- (void)testGenericURLEncoding {
    NSURLRequest *genericRequest = [TDOAuth URLRequestForPath:@"/service/\\subDirectoryWithBackslash"
                                                   parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                         host:@"api.example.com"
                                                  consumerKey:@"abcd"
                                               consumerSecret:@"efgh"
                                                  accessToken:@"ijkl"
                                                  tokenSecret:@"mnop"
                                                       scheme:@"ftp" // Not really valid, but it lets us test
                                                requestMethod:@"BEG"
                                                 dataEncoding:TDOAuthContentTypeUrlEncodedForm
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    NSString *url = [[genericRequest URL] absoluteString];
    XCTAssertEqualObjects(url, @"ftp://api.example.com/service/%5CsubDirectoryWithBackslash",
                          "url does not match expected value");

    NSString *authHeader = [genericRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"SVHQ336AsUnnwG48LIsyr%2FYDi6A%3D\"";
    XCTAssertEqualObjects(authHeader, expectedHeader, @"Expected header value does does not match");
}

- (void)testGetURLEncoding {
    NSURLRequest *getRequest = [TDOAuth URLRequestForPath:@"/service/\\subDirectoryWithBackslash"
                                            GETParameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                                     host:@"api.example.com"
                                              consumerKey:@"abcd"
                                           consumerSecret:@"efgh"
                                              accessToken:@"ijkl"
                                              tokenSecret:@"mnop"];
    NSString *url = [[getRequest URL] absoluteString];
    XCTAssertEqualObjects(url, @"http://api.example.com/service/%5CsubDirectoryWithBackslash?foo=bar&baz=bonk",
              "url does not match expected value");

    NSString *authHeader = [getRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"am5ojjNME7KLGoPwpBBGnAJA3g4%3D\"";
    XCTAssertEqualObjects(authHeader, expectedHeader, @"Expected header value does does not match");
}

- (void)testGetURLEncodingWithSpecialCharacters
{
    NSURLRequest *getRequest = [TDOAuth URLRequestForPath:@"/service/\\subDirectoryWithBackslash"
                                            GETParameters:@{@"foo": @"^!*'();:@&=+$,/?%#[]{}\"`<>\\| abc123._-~."}
                                                     host:@"api.example.com"
                                              consumerKey:@"abcd"
                                           consumerSecret:@"efgh"
                                              accessToken:@"ijkl"
                                              tokenSecret:@"mnop"];
    NSString *url = [[getRequest URL] absoluteString];
    XCTAssertEqualObjects(url, @"http://api.example.com/service/%5CsubDirectoryWithBackslash?foo=%5E%21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%3F%25%23%5B%5D%7B%7D%22%60%3C%3E%5C%7C%20abc123._-~.",
                          "url does not match expected value");
}

@end
