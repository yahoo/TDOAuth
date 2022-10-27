// Copyright 2022, Yahoo Inc.
// Licensed under the terms of the MIT license. See LICENSE file in https://github.com/yahoo/TDOAuth for terms.

import XCTest
@testable import TDOAuth

class TestTDOQueryItem: XCTestCase {

    static var paramDictionary: [AnyHashable: Any] {
        return [
            "key_string": "value_string",
            "key_positive_int": Int(808),
            "key_negative_int": Int(-394),
            "key_double": Double(3.141592653589793),
            "key_float": Float(3.1415925),
            "key_dictionary": [
                "dic_string": "dictionary",
                "dic_number": Int(761)
            ],
            "key_array": ["array1", "array2", "array3"],
            "key_bool": true
        ]
    }

    func testStringParam() {
        guard let queryItems = TDOQueryItem.getItems(from: Self.paramDictionary) else {
            assertionFailure("TDOQueryItem: parse parameters failed.")
            return
        }
        XCTAssert(queryItems.count == 8)

        if let stringItem = queryItems.first(where: { $0.name == "key_string" }) {
            XCTAssert(stringItem.stringValue == "value_string")
            XCTAssert(stringItem.rawValue as? String == "value_string")
        } else {
            assertionFailure("TDOQueryItem: parse string item failed.")
        }

        if let positiveIntItem = queryItems.first(where: { $0.name == "key_positive_int" }) {
            XCTAssert(positiveIntItem.stringValue == "808")
            XCTAssert(positiveIntItem.rawValue as? Int == Int(808))
        } else {
            assertionFailure("TDOQueryItem: parse positive int item failed.")
        }

        if let negativeIntItem = queryItems.first(where: { $0.name == "key_negative_int" }) {
            XCTAssert(negativeIntItem.stringValue == "-394")
            XCTAssert(negativeIntItem.rawValue as? Int == Int(-394))
        } else {
            assertionFailure("TDOQueryItem: parse negative int item failed.")
        }

        if let doubleItem = queryItems.first(where: { $0.name == "key_double" }) {
            XCTAssert(doubleItem.stringValue == "3.141592653589793")
            XCTAssert(doubleItem.rawValue as? Double == Double(3.141592653589793))
        } else {
            assertionFailure("TDOQueryItem: parse double item failed.")
        }

        if let floatItem = queryItems.first(where: { $0.name == "key_float" }) {
            XCTAssert(floatItem.stringValue == "3.1415925")
            XCTAssert(floatItem.rawValue as? Float == Float(3.1415925))
        } else {
            assertionFailure("TDOQueryItem: parse float item failed.")
        }

        if let dictionaryItem = queryItems.first(where: { $0.name == "key_dictionary" }) {
            XCTAssert(dictionaryItem.stringValue == "{\n    \"dic_number\" = 761;\n    \"dic_string\" = dictionary;\n}")
            XCTAssert((dictionaryItem.rawValue as? Dictionary<String, Any>)?["dic_string"] as? String == "dictionary")
            XCTAssert((dictionaryItem.rawValue as? Dictionary<String, Any>)?["dic_number"] as? Int == 761)
        } else {
            assertionFailure("TDOQueryItem: parse dictionary item failed.")
        }

        if let arrayItem = queryItems.first(where: { $0.name == "key_array" }) {
            XCTAssert(arrayItem.stringValue == "(\n    array1,\n    array2,\n    array3\n)")
            XCTAssert((arrayItem.rawValue as? Array)?[0] == "array1")
            XCTAssert((arrayItem.rawValue as? Array)?[1] == "array2")
            XCTAssert((arrayItem.rawValue as? Array)?[2] == "array3")
        } else {
            assertionFailure("TDOQueryItem: parse array item failed.")
        }

        if let boolItem = queryItems.first(where: { $0.name == "key_bool" }) {
            XCTAssert(boolItem.stringValue == "true")
            XCTAssert(boolItem.rawValue as? Bool == true)
        } else {
            assertionFailure("TDOQueryItem: parse bool item failed.")
        }
    }

}
