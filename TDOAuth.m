/*
 Copyright 2011 TweetDeck Inc. All rights reserved.

 Design and implementation, Max Howell, @mxcl.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY TweetDeck Inc. ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 EVENT SHALL TweetDeck Inc. OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 The views and conclusions contained in the software and documentation are
 those of the authors and should not be interpreted as representing official
 policies, either expressed or implied, of TweetDeck Inc.
*/

#import "TDOAuth.h"
#import <CommonCrypto/CommonHMAC.h>
#import <OMGUserAgent.h>

#define TDPCEN(s) \
    ((__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(NULL, (__bridge CFStringRef)[s description], NULL, CFSTR("!*'();:@&=+$,/?%#[]"), kCFStringEncodingUTF8))

#define TDChomp(s) { \
    const NSUInteger length = [s length]; \
    if (length > 0) \
        [s deleteCharactersInRange:NSMakeRange(length - 1, 1)]; \
}

#ifndef TDOAuthURLRequestTimeout
#define TDOAuthURLRequestTimeout 30.0
#endif

static int TDOAuthUTCTimeOffset = 0;
static BOOL TDOAuthUseStaticValuesForAutomatedTesting = NO;

static NSString* nonce() {
    if (TDOAuthUseStaticValuesForAutomatedTesting) {
        return @"static-nonce-for-testing";
    } else {
        CFUUIDRef uuid = CFUUIDCreate(NULL);
        CFStringRef s = CFUUIDCreateString(NULL, uuid);
        CFRelease(uuid);
        return (__bridge_transfer NSString *)s;
    }
}

static NSString* timestamp() {
    time_t t;
    if (TDOAuthUseStaticValuesForAutomatedTesting) {
        t = 1456789012;
    } else {
        time(&t);
    }
    mktime(gmtime(&t));
    return [NSString stringWithFormat:@"%ld", t + TDOAuthUTCTimeOffset];
}



@implementation TDOAuth
{
    NSURL *url;
    NSString *signature_secret;
    NSString *signature_method;
    NSDictionary *oauthParams; // these are pre-percent encoded
    NSDictionary *params;     // these are pre-percent encoded
    NSString *method;
    NSString *unencodedHostAndPathWithoutQuery; // we keep this because NSURL drops trailing slashes and the port number
}

- (id)initWithConsumerKey:(NSString *)consumerKey
           consumerSecret:(NSString *)consumerSecret
              accessToken:(NSString *)accessToken
              tokenSecret:(NSString *)tokenSecret
          signatureMethod:(NSString *)signatureMethod
{
    signature_method = signatureMethod; // Validated by the caller
    oauthParams = [NSDictionary dictionaryWithObjectsAndKeys:
                  consumerKey,      @"oauth_consumer_key",
                  nonce(),          @"oauth_nonce",
                  timestamp(),      @"oauth_timestamp",
                  @"1.0",           @"oauth_version",
                  signature_method, @"oauth_signature_method",
                  accessToken,      @"oauth_token",
                  // LEAVE accessToken last or you'll break XAuth attempts
                  nil];
    signature_secret = [NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret ?: @""];
    return self;
}

- (NSString *)signature_base {
    NSMutableDictionary *sigParams = [params mutableCopy];
    [sigParams addEntriesFromDictionary:oauthParams];

    NSMutableString *p3 = [NSMutableString stringWithCapacity:256];
    NSArray *keys = [[sigParams allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *key in keys)
    {
        //[p3 appendString:TDPCEN(key)];
        [p3 appendString:key];
        [p3 appendString:@"="];
        [p3 appendString:[sigParams[key] description]];
        [p3 appendString:@"&"];
    }
    TDChomp(p3);

    return [NSString stringWithFormat:@"%@&%@%%3A%%2F%%2F%@&%@",
            method,
            url.scheme.lowercaseString,
            TDPCEN(unencodedHostAndPathWithoutQuery),
            TDPCEN(p3)];
}

- (NSString *)signature {
    NSData *sigbase = [[self signature_base] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *secret = [signature_secret dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableData *digest;
    NSString *result;
    if ([signature_method isEqualToString:@"HMAC-SHA256"]) {
        digest = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA256, secret.bytes, secret.length, sigbase.bytes, sigbase.length, digest.mutableBytes);
    } else {
        // SHA1
        digest = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA1, secret.bytes, secret.length, sigbase.bytes, sigbase.length, digest.mutableBytes);
    }
    result = [digest base64EncodedStringWithOptions:NSDataBase64Encoding76CharacterLineLength];
    return result;
}


- (NSString *)authorizationHeader {
    NSMutableString *header = [NSMutableString stringWithCapacity:512];
    [header appendString:@"OAuth "];
    for (NSString *key in oauthParams.allKeys)
    {
        [header appendString:[key description]];
        [header appendString:@"=\""];
        [header appendString:[oauthParams[key] description]];
        [header appendString:@"\", "];
    }
    [header appendString:@"oauth_signature=\""];
    [header appendString:TDPCEN(self.signature)];
    [header appendString:@"\""];
    return header;
}

- (NSMutableURLRequest *)requestWithHeaderValues:(NSDictionary *)headerValues {
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:url
                                                      cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                  timeoutInterval:TDOAuthURLRequestTimeout];
    [rq setValue:OMGUserAgent() forHTTPHeaderField:@"User-Agent"];
    [rq setValue:[self authorizationHeader] forHTTPHeaderField:@"Authorization"];
    [rq setValue:@"gzip" forHTTPHeaderField:@"Accept-Encoding"];
    if (headerValues) // nil is allowed
    {
        for (NSString* key in headerValues) {
            id value = [headerValues objectForKey:key];
            if ([value isKindOfClass:[NSString class]])
            {
                [rq setValue:value forHTTPHeaderField:key];
            }
        }
    }
    [rq setHTTPMethod:method];
    return rq;
}

// unencodedParameters are encoded and assigned to self->params, returns encoded queryString
- (id)setParameters:(NSDictionary *)unencodedParameters {
    NSMutableString *queryString = [NSMutableString string];
    NSMutableDictionary *encodedParameters = [NSMutableDictionary new];
    for (NSString *key in unencodedParameters.allKeys)
    {
        NSString *enkey = TDPCEN(key);
        NSString *envalue = TDPCEN(unencodedParameters[key]);
        encodedParameters[enkey] = envalue;
        [queryString appendString:enkey];
        [queryString appendString:@"="];
        [queryString appendString:envalue];
        [queryString appendString:@"&"];
    }
    TDChomp(queryString);
    params = [encodedParameters copy];
    return queryString;
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                      GETParameters:(NSDictionary *)unencodedParameters
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret
{
    return [TDOAuth URLRequestForPath:unencodedPathWithoutQuery
                           parameters:unencodedParameters
                                 host:host
                          consumerKey:consumerKey
                       consumerSecret:consumerSecret
                          accessToken:accessToken
                          tokenSecret:tokenSecret
                               scheme:@"http"
                               method:@"GET"
                         headerValues:nil
                      signatureMethod:nil];
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                         parameters:(NSDictionary *)unencodedParameters
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret
                             scheme:(NSString *)scheme
                             method:(NSString *)method
                       headerValues:(NSDictionary *)headerValues
                    signatureMethod:(NSString *)signatureMethod;
{
    if (!host || !unencodedPathWithoutQuery || !scheme || !method)
        return nil;

    NSString *sm = signatureMethod;
    if (!signatureMethod) {
        sm = @"HMAC-SHA1";
    } else if ((![sm isEqualTo:@"HMAC-SHA1"]) && (![sm isEqualToString:@"HMAC-SHA256"])) {
        return nil;
    }
    TDOAuth *oauth = [[TDOAuth alloc] initWithConsumerKey:consumerKey
                                           consumerSecret:consumerSecret
                                              accessToken:accessToken
                                              tokenSecret:tokenSecret
                                          signatureMethod:sm];

    // We don't use pcen as we don't want to percent encode eg. /, this is perhaps
    // not the most all encompassing solution, but in practice it seems to work
    // everywhere and means that programmer error is *much* less likely.
    NSString *encodedPathWithoutQuery = [unencodedPathWithoutQuery stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];

    id path = [oauth setParameters:unencodedParameters];
    if (path) {
        [path insertString:@"?" atIndex:0];
        [path insertString:encodedPathWithoutQuery atIndex:0];
    } else {
        path = encodedPathWithoutQuery;
    }

    oauth->method = method;
    oauth->unencodedHostAndPathWithoutQuery = [host.lowercaseString stringByAppendingString:unencodedPathWithoutQuery];

    NSMutableURLRequest *rq;
    if ([method isEqualToString:@"GET"])
    {
        oauth->url = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://%@%@",
                                                    scheme, host, path]];
        rq = [oauth requestWithHeaderValues:headerValues];
    }
    else
    {
        oauth->url = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://%@%@",
                                                    scheme, host, unencodedPathWithoutQuery]];
        NSMutableString *postbody = [oauth setParameters:unencodedParameters];
        rq = [oauth requestWithHeaderValues:headerValues];

        if (postbody.length) {
            [rq setHTTPBody:[postbody dataUsingEncoding:NSUTF8StringEncoding]];
            [rq setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
            [rq setValue:[NSString stringWithFormat:@"%lu", (unsigned long)rq.HTTPBody.length] forHTTPHeaderField:@"Content-Length"];
        }
    }

    return rq;
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                      GETParameters:(NSDictionary *)unencodedParameters
                             scheme:(NSString *)scheme
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret;
{
    return [TDOAuth URLRequestForPath:unencodedPathWithoutQuery
                           parameters:unencodedParameters
                                 host:host
                          consumerKey:consumerKey
                       consumerSecret:consumerSecret
                          accessToken:accessToken
                          tokenSecret:tokenSecret
                               scheme:scheme
                               method:@"GET"
                         headerValues:nil
                      signatureMethod:nil];
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPath
                     POSTParameters:(NSDictionary *)unencodedParameters
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret
{
    return [TDOAuth URLRequestForPath:unencodedPath
                           parameters:unencodedParameters
                                 host:host
                          consumerKey:consumerKey
                       consumerSecret:consumerSecret
                          accessToken:accessToken
                          tokenSecret:tokenSecret
                               scheme:@"https"
                               method:@"POST"
                         headerValues:nil
                      signatureMethod:nil];
    
}

+(int)utcTimeOffset
{
    return TDOAuthUTCTimeOffset;
}

+(void)setUtcTimeOffset:(int)offset
{
    TDOAuthUTCTimeOffset = offset;
}

+(void)enableStaticValuesForAutomatedTests
{
    TDOAuthUseStaticValuesForAutomatedTesting = YES;
}
@end
