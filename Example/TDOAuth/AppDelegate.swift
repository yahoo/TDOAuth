// Copyright 2020, Verizon Media.
// Licensed under the terms of the MIT license. See LICENSE file in https://github.com/yahoo/TDOAuth for terms.

import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    #if swift(>=4.2)
    typealias LaunchOptionsKey = UIApplication.LaunchOptionsKey
    #else
    typealias LaunchOptionsKey = UIApplicationLaunchOptionsKey
    #endif

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [LaunchOptionsKey: Any]?) -> Bool {
        // Override point for customization after application launch.
        return true
    }

}

