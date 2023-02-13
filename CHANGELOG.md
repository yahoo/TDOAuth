# Changelog

## 1.6.4
- Fix SPM dependency. OMGHTTPURLRQUserAgent dependency must explicitly called out or "Test" will not build/link due to missing symbol.

## 1.6.3
- Fix dropping collection values in GET calls

## 1.6.2
- Some parameters are dropped because insufficient type casting on TDOQueryItem.
- Encoding JSON object's httpBody failure
- Add tests for TDOQueryItem to make sure the type casting is correct.

## 1.6.1
- Fix dropped non-string parameters types

## 1.6.0
- SPM now works correctly if using the older Obj-C interface.
- Next release will be a major release, removing the original Obj-C API's.

## 1.5.0
- Add support for Swift Package Manager (SPM)

## 1.4.3
- Character escaping logic compliance with RFC 5849 [PR](https://github.com/yahoo/TDOAuth/pull/36)

## 1.4.2
- Fix bug when URL path ends with a trailing slash
- accessToken and accessSecret at optional in the HMAC initializer

## 1.4.1

- Fix modular headers issue

## 1.4.0

- Complete re-write into Swift
- Pure Swift-native APIs
- Support for arbitrary hash algorithm
- No longer makes assumptions about NSURLRequests (doesn't generate them for you)
- Backwards-compatible and optional Objective-C bridging layer
