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
    getRequest = [TDOAuth URLRequestForPath:@"/service"
                              GETParameters:@{@"foo": @"bar"}
                                       host:@"api.example.com"
                                consumerKey:@"abcd"
                             consumerSecret:@"efgh"
                                accessToken:@"ijkl"
                                tokenSecret:@"mnop"];
    postRequest = [TDOAuth URLRequestForPath:@"/service"
                              POSTParameters:@{@"foo": @"bar"}
                                        host:@"api.example.com"
                                 consumerKey:@"abcd"
                              consumerSecret:@"efgh"
                                 accessToken:@"ijkl"
                                 tokenSecret:@"mnop"];

}

- (void)tearDown
{
    getRequest = nil;
    [super tearDown];
}

- (void)testGetMethod
{
    
    XCTAssert([[getRequest HTTPMethod] isEqualToString:@"GET"],
              "method (verb) expected to be GET");
}

- (void)testGetBody
{
    NSData *body = [getRequest HTTPBody];
    //NSString *bodyString = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    XCTAssertNil(body,
                 "body expected to be nil");
}

- (void)testGetUrl
{
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
    // Not a very complete test. It needs to parse the whole thing and force the time to a set value.
    NSString *authHeader = [getRequest valueForHTTPHeaderField:@"Authorization"];
    //OAuth oauth_token="ijkl", oauth_nonce="DCD69F8B-654C-4316-ACC3-891F4FE561D4", oauth_signature_method="HMAC-SHA1", oauth_consumer_key="abcd", oauth_timestamp="1427068142", oauth_version="1.0", oauth_signature="9NQezmVaPBLhnvpRQ6LPawoiBDw%3D"
    XCTAssert([authHeader hasPrefix:@"OAuth oauth_token=\"ijkl\", oauth_nonce=\""],
              @"Expected beginning of header to be canned value");
}

- (void)testPostMethod
{
    XCTAssert([[postRequest HTTPMethod] isEqualToString:@"POST"],
              "method (verb) expected to be POST");
}
- (void)testPostBody
{
    NSData *body = [postRequest HTTPBody];
    NSString *bodyString = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    XCTAssert([bodyString isEqualToString:@"foo=bar"],
              "body expected to be structured");
}

- (void)testPostUrl
{
    NSString *url = [[postRequest URL] absoluteString];
    XCTAssert([url isEqualToString:@"https://api.example.com/service"],
              "url does not match expected value");
    
    NSString *contentType = [postRequest valueForHTTPHeaderField: @"Content-Type"];
    XCTAssert([contentType isEqualToString:@"application/x-www-form-urlencoded"],
              @"Content-Type is not expected value)");

    NSString *contentLength = [postRequest valueForHTTPHeaderField: @"Content-Length"];
    XCTAssert([contentLength isEqualToString:@"7"],
              @"Content-Length is not expected value)");

}
- (void)testPostHeaderAuthField
{
    // Not a very complete test. It needs to parse the whole thing and force the time to a set value.
    NSString *authHeader = [getRequest valueForHTTPHeaderField:@"Authorization"];
    //OAuth oauth_token="ijkl", oauth_nonce="DCD69F8B-654C-4316-ACC3-891F4FE561D4", oauth_signature_method="HMAC-SHA1", oauth_consumer_key="abcd", oauth_timestamp="1427068142", oauth_version="1.0", oauth_signature="9NQezmVaPBLhnvpRQ6LPawoiBDw%3D"
    XCTAssert([authHeader hasPrefix:@"OAuth oauth_token=\"ijkl\", oauth_nonce=\""],
              @"Expected beginning of header to be canned value");
}
@end
