/*
 Copyright 2011 TweetDeck Inc. All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY TWEETDECK INC. ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 EVENT SHALL TWEETDECK INC. OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
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

import Foundation
import OMGHTTPURLRQ

// MARK: From TDOAuth.h

// TDOAuthSignatureMethod is declared as a public enum

@objc public enum TDOAuthContentType : Int, @unchecked Sendable {
    case urlEncodedForm = 0
    case jsonObject = 1
    case urlEncodedQuery = 2
}

// MARK: -

// Objective-C macro, converted into a Swift function.
func TDPCEN(_ s: String) -> String? {
    return s.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~"))
}

let TDOAuthURLRequestTimeout = 30.0

// MARK: -

internal class TDOQueryItem : NSObject {
    var name: String
    var rawValue: Any
    var stringValue: String?

    init(name: String, rawValue: Any) {
        self.name = name
        self.rawValue = rawValue
        self.stringValue = Self.getStringValue(by: rawValue)
    }

    private class func getStringValue(by rawValue: Any) -> String? {
        var formattedValue: String?
        switch rawValue {
        case let losslessString as CustomStringConvertible:
            formattedValue = losslessString.description
        case let nsObject as NSObjectProtocol:
            formattedValue = nsObject.description
        case let arrayValue as Array<CustomStringConvertible>:
            formattedValue = String(describing: arrayValue)
        case let arrayValue as Array<NSObjectProtocol>:
            formattedValue = String(describing: arrayValue)
        case let dictionaryValue as Dictionary<AnyHashable, Any>:
            formattedValue = String(describing: dictionaryValue)
        default:
            /// `value` is not a valid type - skipping
            assertionFailure("TDOAuth: failed to casting the parameter: \(rawValue)")
        }
        return formattedValue
    }

    class func getItems(from dictionary: [AnyHashable: Any]?) -> [TDOQueryItem]? {
        guard let dic = dictionary else { return nil }
        var queryItems = [TDOQueryItem]()

        for (key, value) in dic {
            guard let key = key as? String else { continue }
            if Self.getStringValue(by: value) == nil {
                /// `value` is not a valid type - skipping
                assertionFailure("TDOAuth: failed to casting the parameter: \(value) for the key: \(key)")
                continue
            }
            let queryItem = TDOQueryItem(name: key, rawValue: value)
            queryItems.append(queryItem)
        }

        return queryItems
    }
}

// MARK: -

/**
  This OAuth implementation doesn't cover the whole spec (eg. it’s HMAC only).
  But you'll find it works with almost all the OAuth implementations you need
  to interact with in the wild. How ace is that?!
*/
@objc open class TDOAuth : NSObject {

    /**
      @p unencodeParameters may be nil. Objects in the dictionary must be strings.
      You are contracted to consume the NSURLRequest *immediately*. Don't put the
      queryParameters in the path as a query string! Path MUST start with a slash!
      Don't percent encode anything! This will submit via HTTP. If you need HTTPS refer
      to the next selector.
    */
    @available(*, deprecated, message: "Please move your code to using the OAuth1<HMACSigner> APIs.  You can find more detail in the README of this SDK.  Those are the appropriate APIs moving forward.  This API will be removed in a future release.")
    @objc(URLRequestForPath:GETParameters:host:consumerKey:consumerSecret:accessToken:tokenSecret:)
    open class func urlRequest(forPath unencodedPath_WITHOUT_Query: String?,
                               getParameters unencodedParameters: [AnyHashable : Any]?,
                               host: String?,
                               consumerKey: String?,
                               consumerSecret: String?,
                               accessToken: String?,
                               tokenSecret: String?) -> URLRequest! {
        return TDOAuth.urlRequest(forPath: unencodedPath_WITHOUT_Query,
                               parameters:unencodedParameters,
                                     host:host,
                              consumerKey:consumerKey,
                           consumerSecret:consumerSecret,
                              accessToken:accessToken,
                              tokenSecret:tokenSecret,
                                   scheme:"http",
                            requestMethod:"GET",
                             dataEncoding:.urlEncodedForm,
                             headerValues:nil,
                          signatureMethod:.hmacSha1)
    }

    /**
      Some services insist on HTTPS. Or maybe you don't want the data to be sniffed.
      You can pass @"https" via the scheme parameter.
    */
    @available(*, deprecated, message: "Please move your code to using the OAuth1<HMACSigner> APIs.  You can find more detail in the README of this SDK.  Those are the appropriate APIs moving forward.  This API will be removed in a future release.")
    @objc(URLRequestForPath:GETParameters:scheme:host:consumerKey:consumerSecret:accessToken:tokenSecret:)
    open class func urlRequest(forPath unencodedPath_WITHOUT_Query: String?,
                               getParameters unencodedParameters: [AnyHashable : Any]?,
                               scheme: String?,
                               host: String?,
                               consumerKey: String?,
                               consumerSecret: String?,
                               accessToken: String?,
                               tokenSecret: String?) -> URLRequest! {
        return TDOAuth.urlRequest( forPath:unencodedPath_WITHOUT_Query,
                               parameters:unencodedParameters,
                                     host:host,
                              consumerKey:consumerKey,
                           consumerSecret:consumerSecret,
                              accessToken:accessToken,
                              tokenSecret:tokenSecret,
                                   scheme:scheme,
                            requestMethod:"GET",
                             dataEncoding:.urlEncodedForm,
                             headerValues:nil,
                          signatureMethod:.hmacSha1)
    }

    /**
      We always POST with HTTPS. This is because at least half the time the user's
      data is at least somewhat private, but also because apparently some carriers
      mangle POST requests and break them. We saw this in France for example.
      READ THE DOCUMENTATION FOR GET AS IT APPLIES HERE TOO!
    */
    @available(*, deprecated, message: "Please move your code to using the OAuth1<HMACSigner> APIs.  You can find more detail in the README of this SDK.  Those are the appropriate APIs moving forward.  This API will be removed in a future release.")
    @objc(URLRequestForPath:POSTParameters:host:consumerKey:consumerSecret:accessToken:tokenSecret:)
    open class func urlRequest(forPath unencodedPath: String?,
                               postParameters unencodedParameters: [AnyHashable : Any]?,
                               host: String?,
                               consumerKey: String?,
                               consumerSecret: String?,
                               accessToken: String?,
                               tokenSecret: String?) -> URLRequest! {
        return TDOAuth.urlRequest(forPath:unencodedPath,
                               parameters:unencodedParameters,
                                     host:host,
                              consumerKey:consumerKey,
                           consumerSecret:consumerSecret,
                              accessToken:accessToken,
                              tokenSecret:tokenSecret,
                                   scheme:"https",
                            requestMethod:"POST",
                                  dataEncoding:.urlEncodedForm,
                             headerValues:nil,
                                  signatureMethod:.hmacSha1)
    }

    /**
      Allow to pass NSURLComponents. READ THE DOCUMENTATION IN PREVIOUS GET METHODS!
     */
    @available(*, deprecated, message: "Please move your code to using the OAuth1<HMACSigner> APIs.  You can find more detail in the README of this SDK.  Those are the appropriate APIs moving forward.  This API will be removed in a future release.")
    @objc(URLRequestForGETURLComponents:consumerKey:consumerSecret:accessToken:tokenSecret:)
    open class func urlRequest(forGetUrlComponents urlComponents: URLComponents,
                               consumerKey: String?,
                               consumerSecret: String?,
                               accessToken: String?,
                               tokenSecret: String?) -> URLRequest! {

        var queryItems = [TDOQueryItem]()
        if let items = urlComponents.queryItems {
            items.forEach { item in
                if let value = item.value {
                    let queryItem = TDOQueryItem(name: item.name, rawValue: value)
                    queryItems.append(queryItem)
                }
            }
        }

        return TDOAuth.urlRequest(forPath:urlComponents.path,
                                  queryItems:queryItems,
                                  host:urlComponents.host,
                           consumerKey:consumerKey,
                        consumerSecret:consumerSecret,
                           accessToken:accessToken,
                           tokenSecret:tokenSecret,
                                scheme:urlComponents.scheme,
                         requestMethod:"GET",
                          dataEncoding:.urlEncodedForm,
                          headerValues:nil,
                       signatureMethod:.hmacSha1)
    }

    /**
     This method allows the caller to specify particular values for many different parameters such
     as scheme, method, header values and alternate signature hash algorithms.

     @p scheme may be any string value, generally "http" or "https".
     @p requestMethod may be any string value. There is no validation, so remember that all
     currently-defined HTTP methods are uppercase and the RFC specifies that the method
     is case-sensitive.
     @p dataEncoding allows for the transmission of data as either URL-encoded form data,
     query string or JSON by passing the value TDOAuthContentTypeUrlEncodedForm,
     TDOAuthContentTypeUrlEncodedQuery or TDOAuthContentTypeJsonObject.
     This parameter is ignored for the requestMethod "GET".
     @p headerValues accepts a hash of key-value pairs (both must be strings) that specify
     HTTP header values to be included in the resulting URL Request. For example, the argument
     value @{@"Accept": @"application/json"} will include the header to indicate the server
     should respond with JSON. Other values are acceptable, depending on the server, but be
     careful. Values you supply will override the defaults which are set for User-Agent
     (set to "app-bundle-name/version" your app resources), Accept-Encoding (set to "gzip")
     and the calculated Authentication header. Attempting to specify the latter will be fatal.
     You should also avoid passing in values for the Content-Type and Content-Length header fields.
     @p signatureMethod accepts an enum and should normally be set to TDOAuthSignatureMethodHmacSha1.
     You have the option of using HMAC-SHA256 by setting this parameter to
     TDOAuthSignatureMethodHmacSha256; this is not included in the RFC for OAuth 1.0a, so most servers
     will not support it.
    */
    @available(*, deprecated, message: "Please move your code to using the OAuth1<HMACSigner> APIs.  You can find more detail in the README of this SDK.  Those are the appropriate APIs moving forward.  This API will be removed in a future release.")
    @objc(URLRequestForPath:parameters:host:consumerKey:consumerSecret:accessToken:tokenSecret:scheme:requestMethod:dataEncoding:headerValues:signatureMethod:)
    open class func urlRequest(forPath unencodedPathWithoutQuery: String?,
                               parameters unencodedParameters: [AnyHashable : Any]?,
                               host: String?,
                               consumerKey: String?,
                               consumerSecret: String?,
                               accessToken: String?,
                               tokenSecret: String?,
                               scheme: String?,
                               requestMethod method: String?,
                               dataEncoding: TDOAuthContentType,
                               headerValues: [AnyHashable : Any]?,
                               signatureMethod: TDOAuthSignatureMethod) -> URLRequest! {

        return self.urlRequest(forPath: unencodedPathWithoutQuery,
                               queryItems: TDOQueryItem.getItems(from: unencodedParameters) ?? [],
                               host: host,
                               consumerKey: consumerKey,
                               consumerSecret: consumerSecret,
                               accessToken: accessToken,
                               tokenSecret: tokenSecret,
                               scheme: scheme,
                               requestMethod: method,
                               dataEncoding: dataEncoding,
                               headerValues: headerValues,
                               signatureMethod: signatureMethod)
    }

    internal class func urlRequest(forPath unencodedPathWithoutQuery: String?,
                             queryItems: [TDOQueryItem],
                                   host: String?,
                            consumerKey: String?,
                         consumerSecret: String?,
                            accessToken: String?,
                            tokenSecret: String?,
                                 scheme: String?,
                          requestMethod method: String?,
                           dataEncoding: TDOAuthContentType,
                           headerValues: [AnyHashable : Any]?,
                        signatureMethod: TDOAuthSignatureMethod) -> URLRequest?
    {
        let request = self.generateURLRequest(forPath:unencodedPathWithoutQuery,
                             queryItems:queryItems,
                                   host:host,
                                 scheme:scheme,
                          requestMethod:method,
                           dataEncoding:dataEncoding,
                           headerValues:headerValues)
        if let request = request {
            return TDOAuthCompat.signRequest(request,
                                             consumerKey: consumerKey ?? "",
                                             consumerSecret: consumerSecret ?? "",
                                             accessToken: accessToken,
                                             tokenSecret: tokenSecret,
                                             signatureMethod: signatureMethod)
        }
        else {
            return request
        }
    }

    // METHOD ADAPTED FROM LEGACY OAUTH1 CLIENT
    internal class func generateURLRequest(forPath unencodedPathWithoutQuery: String?,
                                     queryItems: [TDOQueryItem],
                                           host: String?,
                                         scheme: String?,
                                  requestMethod method: String?,
                                   dataEncoding: TDOAuthContentType,
                                       headerValues: [AnyHashable:Any]?) -> URLRequest?
    {
        guard let host = host, let unencodedPathWithoutQuery = unencodedPathWithoutQuery, let scheme = scheme, let method = method else {
            return nil
        }

        // We don't use pcen as we don't want to percent encode eg. /, this is perhaps
        // not the most all encompassing solution, but in practice it seems to work
        // everywhere and means that programmer error is *much* less likely.
        guard let encodedPathWithoutQuery = unencodedPathWithoutQuery.addingPercentEncoding(withAllowedCharacters: CharacterSet.urlPathAllowed ) else {
            return nil
        }

        var url : URL? = nil
        var rq : URLRequest? = nil

        if method == "GET" || method == "DELETE" || method == "HEAD" ||
            ((method == "POST" || method == "PUT") && dataEncoding == .urlEncodedQuery)
        {
            var path = self.setParameters(queryItems)
            if (!path.isEmpty && !queryItems.isEmpty) {
                path.insert("?", at: String.Index(utf16Offset: 0, in: path))
                path.insert(contentsOf: encodedPathWithoutQuery, at: String.Index(utf16Offset: 0, in: path))
            } else {
                path = String(encodedPathWithoutQuery)
            }

            url = URL(string: String(format:"%@://%@%@", scheme, host, path))
            rq = self.request(withHeaderValues: headerValues, url: url, method: method)
        }
        else
        {
            url = URL(string: String(format:"%@://%@%@", scheme, host, encodedPathWithoutQuery))

            if (dataEncoding == .urlEncodedForm) || (queryItems.isEmpty)
            {
                let postbody = self.setParameters(queryItems)
                rq = self.request(withHeaderValues:headerValues, url:url, method:method)

                if !postbody.isEmpty {
                    if let data = postbody.data(using: .utf8) {
                        rq?.httpBody = data
                        rq?.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
                        rq?.setValue(String(format:"%lu", data.count), forHTTPHeaderField: "Content-Length")
                    }
                    // In the else scenario (where we have no data), the user will not receive a URLRequest.
                }
            }
            else if (dataEncoding == .jsonObject)
            {
                // This falls back to dictionary as not sure what's the proper action here.
                var unencodedParameters = [String: Any]()
                for queryItem in queryItems {
                    unencodedParameters[queryItem.name] = queryItem.rawValue
                }
                do {
                    let postbody = try JSONSerialization.data(withJSONObject: unencodedParameters)

                    rq = self.request(withHeaderValues: headerValues, url: url, method: method)
                    if !postbody.isEmpty {
                        rq?.httpBody = postbody
                        rq?.setValue("application/json", forHTTPHeaderField: "Content-Type")
                        rq?.setValue(String(format: "%lu", postbody.count), forHTTPHeaderField: "Content-Length")
                    }
                }
                catch {
                    NSLog("Got an error encoding JSON: %@", error.localizedDescription)
                }
            }
            else // invalid type
            {
                return nil
            }
        }

        return rq
    }

    // METHOD ADAPTED FROM LEGACY OAUTH1 CLIENT
    // unencodedParameters are encoded and assigned to self->params, returns encoded queryString
    internal class func setParameters( _ unencodedParameters:[TDOQueryItem]) -> String
    {
        var queryString = String("")
        var encodedParameters = [TDOQueryItem]()
        for queryItem in unencodedParameters {
            if let enkey = TDPCEN(queryItem.name),
                let stringValue = queryItem.stringValue,
                let envalue = TDPCEN(stringValue) {
                if queryString.count > 0 {
                    queryString.append("&")
                }
                encodedParameters.append(TDOQueryItem(name: enkey, rawValue: envalue))
                queryString.append(enkey)
                queryString.append("=")
                queryString.append(envalue)
            }
        }
        return queryString
    }

    // METHOD ADAPTED FROM LEGACY OAUTH1 CLIENT
    internal class func request(withHeaderValues headerValues:[AnyHashable:Any]?, url:URL?, method:String) -> Foundation.URLRequest! {
        var rq : URLRequest? = nil
        if let url = url {
            rq = Foundation.URLRequest(url: url, cachePolicy: .reloadIgnoringCacheData, timeoutInterval: TDOAuthURLRequestTimeout)
            rq?.setValue(OMGUserAgent(), forHTTPHeaderField: "User-Agent")
            rq?.setValue("gzip", forHTTPHeaderField: "Accept-Encoding")

            // It's Ok if headerValues = nil
            if let keys = headerValues?.keys {
                for key in keys {
                    if let key = key as? String {
                        let value = headerValues?[key]
                        if let value = value as? String {
                            rq?.setValue(value, forHTTPHeaderField: key)
                        }
                    }
                }
            }
            rq?.httpMethod = method
        }
        return rq
    }

    /**

     OAuth requires the UTC timestamp we send to be accurate. The user's device
     may not be, and often isn't. To work around this you should set this to the
     UTC timestamp that you get back in HTTP headers from OAuth servers.
     */
    open class func utcTimeOffset() -> Int32 {
        return 0
    }

    open class func setUtcTimeOffset(_ offset: Int32) {
       return
    }
}
