#
# Be sure to run `pod lib lint TDOAuth.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'TDOAuth'
  s.version          = '1.3.0'
  s.summary          = 'Elegant, simple and compliant OAuth 1.x solution.'

  s.description      = <<-DESC
  TDOAuth is a simple, compliant OAuth 1.x solution for signing network requests.
                       DESC

  s.homepage         = 'https://github.com/Adam Kaplan/TDOAuth'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Adam Kaplan' => 'adamkaplan@yahoo-inc.com', 'Max Howell' => 'mxcl@me.com' }
  s.source           = { :git => 'https://github.com/Yahoo/TDOAuth.git', :tag => s.version.to_s }

  s.ios.deployment_target = '8.0'
  s.tvos.deployment_target = '11.0'
  s.watchos.deployment_target = '3.0'
  s.osx.deployment_target = '10.10'

  s.swift_version = '4.0'

  s.source_files = 'Source/*.{swift,h,m}'

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  s.dependency 'OMGHTTPURLRQ/UserAgent'
end
