//
//  AppDelegate.swift
//  TDOAuth
//
//  Created by Adam Kaplan on 01/05/2019.
//  Copyright (c) 2019 Adam Kaplan. All rights reserved.
//

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

