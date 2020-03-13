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

@interface TDOQueryItem : NSObject
@property(nonatomic, strong) NSString *name;
@property(nonatomic, strong) NSString *value;

+ (instancetype)itemWithName:(NSString *)name value:(NSString *)value;
@end

@implementation TDOQueryItem

+ (instancetype)itemWithName:(NSString *)name value:(NSString *)value
{
    TDOQueryItem *item = [TDOQueryItem new];
    if (item) {
        item.name = name;
        item.value = value;
    }
    return item;
}

@end

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

+ (NSURLRequest *)URLRequestForGETURLComponents:(NSURLComponents *)urlComponents
                                    consumerKey:(NSString *)consumerKey
                                 consumerSecret:(NSString *)consumerSecret
                                    accessToken:(NSString *)accessToken
                                    tokenSecret:(NSString *)tokenSecret
{
    NSMutableArray<TDOQueryItem *> *queryItems = nil;

    if (urlComponents.queryItems != nil) {
        queryItems = [NSMutableArray new];
        for (NSURLQueryItem *item in urlComponents.queryItems) {
            TDOQueryItem *queryItem = [TDOQueryItem itemWithName:item.name value:item.value];
            [queryItems addObject:queryItem];
        }
    }

    return [self URLRequestForPath:urlComponents.path
                        queryItems:queryItems
                              host:urlComponents.host
                       consumerKey:consumerKey
                    consumerSecret:consumerSecret
                       accessToken:accessToken
                       tokenSecret:tokenSecret
                            scheme:urlComponents.scheme
                     requestMethod:@"GET"
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
                    signatureMethod:(TDOAuthSignatureMethod)signatureMethod;
{
    NSMutableArray<TDOQueryItem *> *queryItems = nil;

    if (unencodedParameters != nil) {
        queryItems = [NSMutableArray new];
        for (NSString *key in unencodedParameters.allKeys) {
            TDOQueryItem *queryItem = [TDOQueryItem itemWithName:key value:unencodedParameters[key]];
            [queryItems addObject:queryItem];
        }
    }

    return [self URLRequestForPath:unencodedPathWithoutQuery
                        queryItems:[queryItems copy]
                              host:host
                       consumerKey:consumerKey
                    consumerSecret:consumerSecret
                       accessToken:accessToken
                       tokenSecret:tokenSecret
                            scheme:scheme
                     requestMethod:method
                      dataEncoding:dataEncoding
                      headerValues:headerValues
                   signatureMethod:signatureMethod];
}

+ (NSURLRequest *)URLRequestForPath:(NSString *)unencodedPathWithoutQuery
                         queryItems:(NSArray<TDOQueryItem *> *)queryItems
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
    NSURLRequest *request = [self generateURLRequestForPath:unencodedPathWithoutQuery
                                                 queryItems:queryItems
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
                                 queryItems:(NSArray<TDOQueryItem *> *)queryItems
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
    NSString *encodedPathWithoutQuery = [unencodedPathWithoutQuery stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLPathAllowedCharacterSet];

    NSURL *url;
    NSMutableURLRequest *rq;

    if ([method isEqualToString:@"GET"] || [method isEqualToString:@"DELETE"] || [method isEqualToString:@"HEAD"] || (([method isEqualToString:@"POST"] || [method isEqualToString:@"PUT"]) && dataEncoding == TDOAuthContentTypeUrlEncodedQuery))
    {
        NSMutableString *path = [self setParameters:queryItems];
        if (path && queryItems) {
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

        if ((dataEncoding == TDOAuthContentTypeUrlEncodedForm) || (queryItems == nil))
        {
            NSMutableString *postbody = [self setParameters:queryItems];
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
            // This falls back to dictionary as not sure what's the proper action here.
            NSMutableDictionary *unencodedParameters = [NSMutableDictionary new];
            for (TDOQueryItem *queryItem in queryItems) {
                unencodedParameters[queryItem.name] = queryItem.value;
            }
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
+ (NSMutableString *)setParameters:(NSArray<TDOQueryItem *> *)unencodedParameters {
    NSMutableString *queryString = [NSMutableString string];
    NSMutableArray<TDOQueryItem *> *encodedParameters = [NSMutableArray new];
    for (TDOQueryItem *queryItem in unencodedParameters) {
        NSString *enkey = TDPCEN(queryItem.name);
        NSString *envalue = TDPCEN(queryItem.value);
        [encodedParameters addObject:[TDOQueryItem itemWithName:enkey value:envalue]];
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
