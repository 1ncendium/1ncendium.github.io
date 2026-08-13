# frozen_string_literal: true

source "https://rubygems.org"

gem "jekyll-theme-chirpy", "~> 7.2", ">= 7.2.4"

gem "html-proofer", "~> 5.0", group: :test

# Ruby 3.4+ moved these out of the default stdlib, and some distros (e.g. Arch)
# package them separately. Jekyll requires them without declaring them.
gem "base64"
gem "bigdecimal"
gem "csv"
gem "erb"
gem "logger"

platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.2.0", :platforms => [:mingw, :x64_mingw, :mswin]
