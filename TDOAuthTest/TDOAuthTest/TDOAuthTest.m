//
//  TDOAuthTest.m
//  TDOAuthTest
//
//  Created by Bob Fitterman on 3/22/15.
//
//

#import <XCTest/XCTest.h>
#import "TDOAuthTest.h"

@implementation TDOAuthTest

- (void)setUp
{
    [super setUp];
    [TDOAuth enableStaticValuesForAutomatedTests];
}
- (void)tearDown
{
    [super tearDown];
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
+ (NSURLRequest *)makeGenericRequest
{
    return [TDOAuth URLRequestForPath:@"/service"
                           parameters:@{@"foo": @"bar", @"baz": @"bonk"}
                                 host:@"api.example.com"
                          consumerKey:@"abcd"
                       consumerSecret:@"efgh"
                          accessToken:@"ijkl"
                          tokenSecret:@"mnop"
                               scheme:@"http"
                        requestMethod:@"BEG"
                         headerValues:nil
                      signatureMethod:TDOAuthSignatureMethodHmacSha1];
}

- (void)testGetMethod
{
    NSURLRequest *getRequest = [TDOAuthTest makeGetRequest];
    XCTAssert([[getRequest HTTPMethod] isEqualToString:@"GET"],
              "method (verb) expected to be GET");
}

- (void)testGetBody
{
    NSURLRequest *getRequest = [TDOAuthTest makeGetRequest];
    NSData *body = [getRequest HTTPBody];
    //NSString *bodyString = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    XCTAssertNil(body,
                 "body expected to be nil");
}

- (void)testGetUrl
{
    NSURLRequest *getRequest = [TDOAuthTest makeGetRequest];
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
    NSURLRequest *getRequest = [TDOAuthTest makeGetRequest];
    NSString *authHeader = [getRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
                                "oauth_nonce=\"static-nonce-for-testing\", "\
                                "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
                                "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
                                "oauth_signature=\"O4hspbDTqHlLdqfXxR0jSly9bkU%3D\"";
    XCTAssert([authHeader isEqualToString:expectedHeader],
              @"Expected header value does does not match");
}

- (void)testPostMethod
{
    NSURLRequest *postRequest = [TDOAuthTest makePostRequest];
    XCTAssert([[postRequest HTTPMethod] isEqualToString:@"POST"],
              "method (verb) expected to be POST");
}
- (void)testPostBody
{
    NSURLRequest *postRequest = [TDOAuthTest makePostRequest];
    NSData *body = [postRequest HTTPBody];
    NSString *bodyString = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    XCTAssert([bodyString isEqualToString:@"foo=bar"],
              "body expected to be structured");
}

- (void)testPostUrl
{
    NSURLRequest *postRequest = [TDOAuthTest makePostRequest];
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
- (void)testPostHeaderAuthField
{
    NSURLRequest *postRequest = [TDOAuthTest makePostRequest];
    NSString *authHeader = [postRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"pr%2ForWfyT9CsKTGW85AwjHmFjd8%3D\"";
    XCTAssert([authHeader isEqualToString:expectedHeader],
              @"Expected header value does does not match");
}

- (void)testGenericCallHasRightMethod
{
    NSURLRequest *genericRequest = [TDOAuthTest makeGenericRequest];
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
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha1];
    XCTAssertNil(genericRequest,
                 "should fail when method is missing");
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
    NSURLRequest *genericRequest = [TDOAuthTest makeGenericRequest];
    NSString *authHeader = [genericRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"ycBj862NX5D9cCFrtWcBU2uzkdc%3D\"";
    XCTAssert([authHeader isEqualToString:expectedHeader],
              @"Expected header value does does not match");
}
- (void)testGenericHeaderRecognizesSHA256
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
                                                 headerValues:nil
                                              signatureMethod:TDOAuthSignatureMethodHmacSha256];
    NSString *authHeader = [genericRequest valueForHTTPHeaderField:@"Authorization"];
    NSString *expectedHeader = @"OAuth oauth_token=\"ijkl\", "\
    "oauth_nonce=\"static-nonce-for-testing\", "\
    "oauth_signature_method=\"HMAC-SHA256\", oauth_consumer_key=\"abcd\", "\
    "oauth_timestamp=\"1456789012\", oauth_version=\"1.0\", "\
    "oauth_signature=\"pRxssqcfFnrUqF7i2L5j%2BpCk57gu33m3c9az5kNGors%3D\"";
    XCTAssert([authHeader isEqualToString:expectedHeader],
              @"Expected header value does does not match");
}
- (void)testGenericHeaderRejectsInvalidSignatureMethod
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
                                                 headerValues:nil
                                              signatureMethod:(TDOAuthSignatureMethod)1234];
    XCTAssertNil(genericRequest,
                 @"Expected request to fail with invalid hash function");
}

@end
