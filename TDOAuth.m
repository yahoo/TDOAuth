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

@interface NSString (TweetDeck)
- (NSString*)TDOAuthPercentEncoding;
@end

@interface NSMutableString (TweetDeck)
- (void)TDOAuthAppendObject:(NSString *)s;
- (void)TDOAuthChomp;
@end

#ifndef TDOAuthURLRequestTimeout
#define TDOAuthURLRequestTimeout 30.0
#endif
#ifndef TDUserAgent
#warning Don't be a n00b! #define TDUserAgent!
#endif

static int TDOAuthUTCTimeOffset = 0;

@implementation NSString (TweetDeck)
- (NSString *)TDOAuthPercentEncoding
{
    return (__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(NULL, (__bridge CFStringRef) self, NULL, CFSTR("!*'();:@&=+$,/?%#[]"), kCFStringEncodingUTF8);
}
@end

@implementation NSNumber (TweetDeck)
- (NSString *)TDOAuthPercentEncoding
{
    // We permit NSNumbers as parameters, so we need to handle this function call
    return [self stringValue];
}
@end

@implementation NSMutableString (TweetDeck)
- (void)TDOAuthAppendObject:(id)s
{
    if ([s isKindOfClass:[NSString class]])
        [self appendString:s];
    else if ([s isKindOfClass:[NSNumber class]])
        [self appendString:[(NSNumber *)s stringValue]];
    else
        @throw [NSException exceptionWithName:NSInvalidArgumentException
                                       reason:@"Cannot append requested object to a string; must be NSString or NSNumber"
                                     userInfo:@{@"object": s}];
}
- (void)TDOAuthChomp
{
    const NSUInteger length = [self length];
    if (length > 0)
        [self deleteCharactersInRange:NSMakeRange(length - 1, 1)];
}
@end



// If your input string isn't 20 characters this won't work.
static NSString* base64(const uint8_t* input) {
    static const char map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    NSMutableData* data = [NSMutableData dataWithLength:28];
    uint8_t* out = (uint8_t*) data.mutableBytes;

    for (int i = 0; i < 20;) {
        int v  = 0;
        for (const int N = i + 3; i < N; i++) {
            v <<= 8;
            v |= 0xFF & input[i];
        }
        *out++ = map[v >> 18 & 0x3F];
        *out++ = map[v >> 12 & 0x3F];
        *out++ = map[v >> 6 & 0x3F];
        *out++ = map[v >> 0 & 0x3F];
    }
    out[-2] = map[(input[19] & 0x0F) << 2];
    out[-1] = '=';
    return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
}

static NSString* nonce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef s = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    return (__bridge_transfer NSString *)s;
}

static NSString* timestamp() {
    time_t t;
    time(&t);
    mktime(gmtime(&t));
    return [NSString stringWithFormat:@"%ld", t + TDOAuthUTCTimeOffset];
}



@implementation TDOAuth
{
    NSURL *url;
    NSString *signature_secret;
    NSDictionary *params; // these are pre-percent encoded
    NSString *method;
}

- (id)initWithConsumerKey:(NSString *)consumerKey
           consumerSecret:(NSString *)consumerSecret
              accessToken:(NSString *)accessToken
              tokenSecret:(NSString *)tokenSecret
{
    NSMutableDictionary *parameters = [[NSMutableDictionary alloc] init];
    parameters[@"oauth_consumer_key"] = consumerKey;
    parameters[@"oauth_nonce"] = nonce();
    parameters[@"oauth_timestamp"] = timestamp();
    parameters[@"oauth_version"] = @"1.0";
    parameters[@"oauth_signature_method"] = @"HMAC-SHA1";
    if (accessToken)
        parameters[@"oauth_token"] = accessToken;
    params = [parameters copy];
    signature_secret = [NSString stringWithFormat:@"%@&%@", consumerSecret, tokenSecret ?: @""];
    return self;
}

- (NSString *)signature_base {
    NSMutableString *p3 = [NSMutableString stringWithCapacity:256];
    NSArray *keys = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *key in keys)
    {
        [p3 TDOAuthAppendObject:[key TDOAuthPercentEncoding]];
        [p3 TDOAuthAppendObject:@"="];
        [p3 TDOAuthAppendObject:params[key]];
        [p3 TDOAuthAppendObject:@"&"];
    }
    [p3 TDOAuthChomp];

    return [NSString stringWithFormat:@"%@&%@%%3A%%2F%%2F%@%@&%@",
            method,
            url.scheme.lowercaseString,
            url.host.lowercaseString.TDOAuthPercentEncoding,
            url.path.TDOAuthPercentEncoding,
            p3.TDOAuthPercentEncoding];
}

- (NSString *)signature {
    NSData *sigbase = [[self signature_base] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *secret = [signature_secret dataUsingEncoding:NSUTF8StringEncoding];

    uint8_t digest[20] = {0};
    CCHmacContext cx;
    CCHmacInit(&cx, kCCHmacAlgSHA1, secret.bytes, secret.length);
    CCHmacUpdate(&cx, sigbase.bytes, sigbase.length);
    CCHmacFinal(&cx, digest);

    return base64(digest);
}

- (NSString *)authorizationHeader {
    NSMutableString *header = [NSMutableString stringWithCapacity:512];
    [header TDOAuthAppendObject:@"OAuth "];
    for (NSString *key in params.allKeys)
    {
        [header TDOAuthAppendObject:key];
        [header TDOAuthAppendObject:@"=\""];
        [header TDOAuthAppendObject:params[key]];
        [header TDOAuthAppendObject:@"\", "];
    }
    [header TDOAuthAppendObject:@"oauth_signature=\""];
    [header TDOAuthAppendObject:self.signature.TDOAuthPercentEncoding];
    [header TDOAuthAppendObject:@"\""];
    return header;
}

- (NSMutableURLRequest *)request {
    //TODO timeout interval depends on connectivity status
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:url
                                                      cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                  timeoutInterval:TDOAuthURLRequestTimeout];
#ifdef TDUserAgent
    [rq setValue:TDUserAgent forHTTPHeaderField:@"User-Agent"];
#endif
    [rq setValue:[self authorizationHeader] forHTTPHeaderField:@"Authorization"];
    [rq setValue:@"gzip" forHTTPHeaderField:@"Accept-Encoding"];
    [rq setHTTPMethod:method];
    return rq;
}

// unencodedParameters are encoded and added to self->params, returns encoded queryString
- (id)addParameters:(NSDictionary *)unencodedParameters {
    if (!unencodedParameters.count)
        return nil;

    NSMutableString *queryString = [NSMutableString string];
    NSMutableDictionary *encodedParameters = [NSMutableDictionary dictionaryWithDictionary:params];
    for (NSString *key in unencodedParameters.allKeys)
    {
        NSString *enkey = key.TDOAuthPercentEncoding;
        NSString *envalue = [unencodedParameters[key] TDOAuthPercentEncoding];
        encodedParameters[enkey] = envalue;
        [queryString TDOAuthAppendObject:enkey];
        [queryString TDOAuthAppendObject:@"="];
        [queryString TDOAuthAppendObject:envalue];
        [queryString TDOAuthAppendObject:@"&"];
    }
    [queryString TDOAuthChomp];

    params = encodedParameters;

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
    return [self URLRequestForPath:unencodedPathWithoutQuery
                     GETParameters:unencodedParameters
                            scheme:@"http"
                              host:host
                       consumerKey:consumerKey
                    consumerSecret:consumerSecret
                       accessToken:accessToken
                       tokenSecret:tokenSecret];
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
    if (!host || !unencodedPathWithoutQuery)
        return nil;

    TDOAuth *oauth = [[TDOAuth alloc] initWithConsumerKey:consumerKey
                                           consumerSecret:consumerSecret
                                              accessToken:accessToken
                                              tokenSecret:tokenSecret];

    // We don't use pcen as we don't want to percent encode eg. /, this
    // is perhaps not the most all encompassing solution, but in practice
    // it works everywhere and means that programmer error is *much* less
    // likely.
    NSString *encodedPathWithoutQuery = [unencodedPathWithoutQuery stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];

    id path = [oauth addParameters:unencodedParameters];
    if (path) {
        [path insertString:@"?" atIndex:0];
        [path insertString:encodedPathWithoutQuery atIndex:0];
    } else {
        path = encodedPathWithoutQuery;
    }

    oauth->method = @"GET";
    oauth->url = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://%@%@", scheme, host, path]];

    NSURLRequest *rq = [oauth request];
    return rq;
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPath
                     POSTParameters:(NSDictionary *)unencodedParameters
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret
{
    if (!host || !unencodedPath)
        return nil;

    TDOAuth *oauth = [[TDOAuth alloc] initWithConsumerKey:consumerKey
                                           consumerSecret:consumerSecret
                                              accessToken:accessToken
                                              tokenSecret:tokenSecret];
    oauth->url = [[NSURL alloc] initWithScheme:@"https" host:host path:unencodedPath];
    oauth->method = @"POST";

    NSMutableString *postbody = [oauth addParameters:unencodedParameters];
    NSMutableURLRequest *rq = [oauth request];

    if (postbody.length) {
        [rq setHTTPBody:[postbody dataUsingEncoding:NSUTF8StringEncoding]];
        [rq setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
        [rq setValue:[NSString stringWithFormat:@"%lu", (unsigned long)rq.HTTPBody.length] forHTTPHeaderField:@"Content-Length"];
    }

    return rq;
}

+(int)utcTimeOffset
{
    return TDOAuthUTCTimeOffset;
}

+(void)setUtcTimeOffset:(int)offset
{
    TDOAuthUTCTimeOffset = offset;
}

@end
