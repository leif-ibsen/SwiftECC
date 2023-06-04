Pod::Spec.new do |s|
  s.name         = "SwiftECC"
  s.version      = "0.1.0" # specify the version here
  s.summary      = "A short description of SwiftECC." # specify a short description here

  s.description  = <<-DESC
                   A longer description of SwiftECC.
                   DESC

  s.homepage     = "https://www.example.com" # replace with the package's homepage
  s.license      = { :type => 'MIT', :file => 'LICENSE' } # specify the license here
  s.author       = { "Your Name" => "your_email@example.com" } # replace with the author's name and email
  s.platform     = :ios, '13.0' # specify the minimum iOS version
  s.source       = { :git => "https://github.com/username/SwiftECC.git", :tag => s.version.to_s }

  s.swift_version = '5.7'
  s.source_files  = "Sources/SwiftECC/**/*.swift"
  
  s.dependency 'BigInt'
  s.dependency 'ASN1'
  
end