#
# Be sure to run `pod lib lint TDOAuth.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'TDOAuth'
  s.version          = '1.4.2'
  s.summary          = 'Elegant, simple and compliant OAuth 1.x solution.'

  s.description      = <<-DESC
  TDOAuth is a simple, compliant OAuth 1.x solution for signing network requests.
                       DESC

  s.homepage         = 'https://github.com/yahoo/TDOAuth'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Adam Kaplan' => 'adamkaplan@verizonmedia.com', 'Max Howell' => 'mxcl@me.com' }
  s.source           = { :git => 'https://github.com/yahoo/TDOAuth.git', :tag => s.version.to_s }

  s.ios.deployment_target = '9.3'
  s.tvos.deployment_target = '11.0'
  s.watchos.deployment_target = '3.0'
  s.osx.deployment_target = '10.10'

  s.swift_versions = [ '4.0', '4.2', '5.0' ]

  s.default_subspec = 'ObjC'

  s.subspec 'Swift' do |ss|
    ss.source_files = 'Source/*.swift'
    ss.dependency 'OMGHTTPURLRQ/UserAgent'
  end

  s.subspec 'ObjC' do |ss|
    ss.dependency 'TDOAuth/Swift'
    ss.source_files = 'Source/compat/*.{swift,h,m}'
  end
end
