Pod::Spec.new do |s|
  s.name = 'TDOAuth'
  s.version = '1.0.4'
  s.requires_arc = true
  s.source_files = '*.{m,h}'
  s.source = { :git => "https://github.com/tweetdeck/#{s.name}.git", :tag => s.version }
  s.license = { :type => 'MIT', :text => 'OHAI CocoaPods linter!' }
  s.summary = 'Elegant, simple and tiny OAuth 1.x solution'

  s.ios.deployment_target = '5.0'
  s.osx.deployment_target = '10.7'

  s.dependency 'OMGHTTPURLRQ/UserAgent'
  s.homepage = 'https://github.com/tweetdeck/TDOAuth'

  s.social_media_url = 'https://twitter.com/mxcl'
  s.authors  = { 'Max Howell' => 'mxcl@me.com' }
end
