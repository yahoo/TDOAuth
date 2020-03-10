//
//  TDOAuth.m
//  TDOAuth
//
//  Created by Adam Kaplan on 3/9/20.
//

#import "TDOAuth.h"
#import <TDOAuth/TDOAuth-Swift.h>
#import <OMGHTTPURLRQ/OMGUserAgent.h>

#define TDPCEN(s) \
      ([[s description] stringByAddingPercentEncodingWithAllowedCharacters:[[NSCharacterSet characterSetWithCharactersInString:@"^!*'();:@&=+$,/?%#[]{}\"`<>\\| "] invertedSet]])

#define TDChomp(s) { \
    const NSUInteger length = [s length]; \
    if (length > 0) \
        [s deleteCharactersInRange:NSMakeRange(length - 1, 1)]; \
}

#ifndef TDOAuthURLRequestTimeout
#define TDOAuthURLRequestTimeout 30.0
#endif

@implementation TDOAuth

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
                        requestMethod:@"GET"
                         dataEncoding:TDOAuthContentTypeUrlEncodedForm
                         headerValues:nil
                      signatureMethod:TDOAuthSignatureMethodHmacSha1];
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                      GETParameters:(NSDictionary *)unencodedParameters
                             scheme:(NSString *)scheme
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
                               scheme:scheme
                        requestMethod:@"GET"
                         dataEncoding:TDOAuthContentTypeUrlEncodedForm
                         headerValues:nil
                      signatureMethod:TDOAuthSignatureMethodHmacSha1];
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
                        requestMethod:@"POST"
                         dataEncoding:TDOAuthContentTypeUrlEncodedForm
                         headerValues:nil
                      signatureMethod:TDOAuthSignatureMethodHmacSha1];
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                         parameters:(NSDictionary *)unencodedParameters
                               host:(NSString *)host
                        consumerKey:(NSString *)consumerKey
                     consumerSecret:(NSString *)consumerSecret
                        accessToken:(NSString *)accessToken
                        tokenSecret:(NSString *)tokenSecret
                             scheme:(NSString *)scheme
                      requestMethod:(NSString *)method
                       dataEncoding:(TDOAuthContentType)dataEncoding
                       headerValues:(NSDictionary *)headerValues
                    signatureMethod:(TDOAuthSignatureMethod)signatureMethod
{
    if (!host || !unencodedPathWithoutQuery || !scheme || !method) {
        return nil;
    }

    NSURLRequest *request = [self generateURLRequestForPath:unencodedPathWithoutQuery
                                                 parameters:unencodedParameters
                                                       host:host
                                                     scheme:scheme
                                              requestMethod:method
                                               dataEncoding:dataEncoding
                                               headerValues:headerValues];
    if (!request) {
        return nil;
    }

    return [TDOAuthCompat signRequest:request
                          consumerKey:consumerKey ?: @""
                       consumerSecret:consumerSecret ?: @""
                          accessToken:accessToken
                          tokenSecret:tokenSecret
                      signatureMethod:signatureMethod];
}

// METHOD ADAPTED FROM LEGACY OAUTH1 CLIENT
+ (NSURLRequest *)generateURLRequestForPath:(NSString *)unencodedPathWithoutQuery
                                 parameters:(NSDictionary *)unencodedParameters
                                       host:(NSString *)host
                                     scheme:(NSString *)scheme
                              requestMethod:(NSString *)method
                               dataEncoding:(TDOAuthContentType)dataEncoding
                               headerValues:(NSDictionary *)headerValues
{
    if (!host || !unencodedPathWithoutQuery || !scheme || !method) {
        return nil;
    }

    // We don't use pcen as we don't want to percent encode eg. /, this is perhaps
    // not the most all encompassing solution, but in practice it seems to work
    // everywhere and means that programmer error is *much* less likely.
    NSString *encodedPathWithoutQuery = [unencodedPathWithoutQuery stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];

    NSURL *url;
    NSMutableURLRequest *rq;

    if ([method isEqualToString:@"GET"] || [method isEqualToString:@"DELETE"] || [method isEqualToString:@"HEAD"] || (([method isEqualToString:@"POST"] || [method isEqualToString:@"PUT"]) && dataEncoding == TDOAuthContentTypeUrlEncodedQuery))
    {
        NSMutableString *path = [self setParameters:unencodedParameters];
        if (path && unencodedParameters) {
            [path insertString:@"?" atIndex:0];
            [path insertString:encodedPathWithoutQuery atIndex:0];
        } else {
            path = encodedPathWithoutQuery.mutableCopy;
        }

        url = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://%@%@", scheme, host, path]];
        rq = [self requestWithHeaderValues:headerValues url:url method:method];
    }
    else
    {
        url = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@://%@%@", scheme, host, encodedPathWithoutQuery]];

        if ((dataEncoding == TDOAuthContentTypeUrlEncodedForm) || (unencodedParameters == nil))
        {
            NSMutableString *postbody = [self setParameters:unencodedParameters];
            rq = [self requestWithHeaderValues:headerValues url:url method:method];

            if (postbody.length) {
                [rq setHTTPBody:[postbody dataUsingEncoding:NSUTF8StringEncoding]];
                [rq setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
                [rq setValue:[NSString stringWithFormat:@"%lu", (unsigned long)rq.HTTPBody.length] forHTTPHeaderField:@"Content-Length"];
            }
        }
        else if (dataEncoding == TDOAuthContentTypeJsonObject)
        {
            NSError *error;
            NSData *postbody = [NSJSONSerialization dataWithJSONObject:unencodedParameters options:0 error:&error];
            if (error || !postbody) {
                NSLog(@"Got an error encoding JSON: %@", error);
            } else {
                rq = [self requestWithHeaderValues:headerValues url:url method:method];

                if (postbody.length) {
                    [rq setHTTPBody:postbody];
                    [rq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
                    [rq setValue:[NSString stringWithFormat:@"%lu", (unsigned long)rq.HTTPBody.length] forHTTPHeaderField:@"Content-Length"];
                }
            }
        }
        else // invalid type
        {
            return nil;
        }
    }

    return rq;
}

// METHOD ADAPTED FROM LEGACY OAUTH1 CLIENT
// unencodedParameters are encoded and assigned to self->params, returns encoded queryString
+ (NSMutableString *)setParameters:(NSDictionary *)unencodedParameters {
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
    return queryString;
}

// METHOD ADAPTED FROM LEGACY OAUTH1 CLIENT
+ (NSMutableURLRequest *)requestWithHeaderValues:(NSDictionary *)headerValues url:(NSURL *)url method:(NSString *)method {
    NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:url
                                                      cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                  timeoutInterval:TDOAuthURLRequestTimeout];

    [rq setValue:OMGUserAgent() forHTTPHeaderField:@"User-Agent"];
    [rq setValue:@"gzip" forHTTPHeaderField:@"Accept-Encoding"];
    if (headerValues) { // nil is allowed
        for (NSString* key in headerValues) {
            id value = headerValues[key];
            if ([value isKindOfClass:NSString.class]) {
                [rq setValue:value forHTTPHeaderField:key];
            }
        }
    }

    rq.HTTPMethod = method;
    return rq;
}

//MARK: - Legacy Test Support

+ (int)utcTimeOffset
{
    return 0;
}

+ (void)setUtcTimeOffset:(int)offset
{
    return;
}

@end
