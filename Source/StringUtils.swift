//
//  StringUtils.swift
//  Pods
//
//  Created by Adam Kaplan on 1/25/19.
//

import Foundation

let urlSafeCharacters: CharacterSet = CharacterSet(charactersIn: "^!*'();:@&=+$,/?%#[]{}\"`<>\\| ").inverted

extension String {

    func addingUrlSafePercentEncoding() -> String {
        return self.addingPercentEncoding(withAllowedCharacters: urlSafeCharacters) ?? ""
    }

}
