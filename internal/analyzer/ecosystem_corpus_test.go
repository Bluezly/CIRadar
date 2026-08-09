package analyzer

import (
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestExtendedEcosystemFailureCorpus(t *testing.T) {
	tests := []struct {
		name string
		repository string
		log string
		category model.Category
		provider string
		errorFamily string
	}{
		{name: `eco-ruby-bundler-gem-not-found`, repository: `rubygems/rubygems`, log: `Could not find gem 'rack (= 99.0.0)' in any of the gem sources listed in your Gemfile.`, category: model.CategoryCodeFailure, provider: `Bundler`, errorFamily: `gem-not-found`},
		{name: `eco-ruby-bundler-version-conflict`, repository: `rubygems/rubygems`, log: `Bundler could not find compatible versions for gem "rack":`, category: model.CategoryCodeFailure, provider: `Bundler`, errorFamily: `gem-version-conflict`},
		{name: `eco-ruby-bundler-ruby-version`, repository: `rubygems/rubygems`, log: `Your Ruby version is 3.1.4, but your Gemfile specified 3.3.0`, category: model.CategoryCodeFailure, provider: `Bundler`, errorFamily: `ruby-version-mismatch`},
		{name: `eco-ruby-bundler-native-extension`, repository: `rubygems/rubygems`, log: `Gem::Ext::BuildError: ERROR: Failed to build gem native extension.`, category: model.CategoryCodeFailure, provider: `RubyGems`, errorFamily: `gem-native-extension-failed`},
		{name: `eco-ruby-bundler-gemfile-missing`, repository: `rubygems/rubygems`, log: `Could not locate Gemfile or .bundle/ directory`, category: model.CategoryCodeFailure, provider: `Bundler`, errorFamily: `gemfile-not-found`},
		{name: `eco-ruby-bundler-lock-platform`, repository: `rubygems/rubygems`, log: `Your bundle only supports platforms ["x86_64-darwin-22"] but your local platform is x86_64-linux.`, category: model.CategoryToolchainFailure, provider: `Bundler`, errorFamily: `lockfile-platform-mismatch`},
		{name: `eco-ruby-bundler-frozen-lock`, repository: `rubygems/rubygems`, log: `You are trying to install in deployment mode after changing your Gemfile. Run bundle install elsewhere and add the updated Gemfile.lock.`, category: model.CategoryCodeFailure, provider: `Bundler`, errorFamily: `frozen-lockfile-changed`},
		{name: `eco-ruby-rubygems-source-network`, repository: `rubygems/rubygems`, log: `Could not fetch specs from https://rubygems.org/ due to underlying error <SocketError: Failed to open TCP connection>`, category: model.CategoryNetworkFailure, provider: `RubyGems`, errorFamily: `registry-connectivity`},
		{name: `eco-ruby-rubygems-cert`, repository: `rubygems/rubygems`, log: `Could not verify the SSL certificate for https://rubygems.org/quick/Marshal.4.8/rake.gemspec.rz. certificate verify failed`, category: model.CategoryNetworkFailure, provider: `RubyGems`, errorFamily: `certificate-verification-failed`},
		{name: `eco-ruby-ruby-load-error`, repository: `ruby/ruby`, log: `app.rb:1:in ` + "`" + `require` + "`" + `: cannot load such file -- missing_gem (LoadError)`, category: model.CategoryCodeFailure, provider: `Ruby`, errorFamily: `load-error`},
		{name: `eco-ruby-ruby-name-error`, repository: `ruby/ruby`, log: `NameError: uninitialized constant MyApp::Widget`, category: model.CategoryCodeFailure, provider: `Ruby`, errorFamily: `name-error`},
		{name: `eco-ruby-ruby-no-method`, repository: `ruby/ruby`, log: `NoMethodError: undefined method ` + "`" + `call' for nil:NilClass`, category: model.CategoryCodeFailure, provider: `Ruby`, errorFamily: `no-method-error`},
		{name: `eco-ruby-ruby-syntax-error`, repository: `ruby/ruby`, log: `app.rb:14: syntax error, unexpected end-of-input, expecting ` + "`" + `end` + "`" + ``, category: model.CategoryCodeFailure, provider: `Ruby`, errorFamily: `syntax-error`},
		{name: `eco-ruby-ruby-argument-error`, repository: `ruby/ruby`, log: `ArgumentError: wrong number of arguments (given 2, expected 1)`, category: model.CategoryCodeFailure, provider: `Ruby`, errorFamily: `argument-error`},
		{name: `eco-ruby-ruby-frozen-error`, repository: `ruby/ruby`, log: `FrozenError: can't modify frozen String: "hello"`, category: model.CategoryCodeFailure, provider: `Ruby`, errorFamily: `frozen-object-mutation`},
		{name: `eco-ruby-ruby-system-stack`, repository: `ruby/ruby`, log: `SystemStackError: stack level too deep`, category: model.CategoryResourceExhaustion, provider: `Ruby`, errorFamily: `stack-overflow`},
		{name: `eco-ruby-ruby-oom`, repository: `ruby/ruby`, log: `failed to allocate memory (NoMemoryError)`, category: model.CategoryResourceExhaustion, provider: `Ruby`, errorFamily: `memory-exhaustion`},
		{name: `eco-ruby-rspec-failure`, repository: `rspec/rspec`, log: `Finished in 0.10 seconds
12 examples, 1 failure
Failed examples:
rspec ./spec/a_spec.rb:4`, category: model.CategoryCodeFailure, provider: `RSpec`, errorFamily: `expectation-failure`},
		{name: `eco-ruby-rspec-load-error`, repository: `rspec/rspec`, log: `An error occurred while loading ./spec/user_spec.rb. Failure/Error: require "app"
LoadError: cannot load such file -- app`, category: model.CategoryCodeFailure, provider: `RSpec`, errorFamily: `spec-load-error`},
		{name: `eco-ruby-rspec-zero-examples`, repository: `rspec/rspec`, log: `No examples found.
Finished in 0.0002 seconds
0 examples, 0 failures`, category: model.CategoryCodeFailure, provider: `RSpec`, errorFamily: `no-tests-found`},
		{name: `eco-ruby-rubocop-offenses`, repository: `rubocop/rubocop`, log: `1 file inspected, 3 offenses detected, 2 offenses autocorrectable`, category: model.CategoryCodeFailure, provider: `RuboCop`, errorFamily: `lint-offenses`},
		{name: `eco-ruby-rubocop-config`, repository: `rubocop/rubocop`, log: `Error: unrecognized cop or department Style/FooBar`, category: model.CategoryCodeFailure, provider: `RuboCop`, errorFamily: `invalid-configuration`},
		{name: `eco-ruby-rails-pending-migration`, repository: `rails/rails`, log: `ActiveRecord::PendingMigrationError: Migrations are pending. To resolve this issue, run: bin/rails db:migrate`, category: model.CategoryCodeFailure, provider: `Rails ActiveRecord`, errorFamily: `pending-migration`},
		{name: `eco-ruby-rails-db-config`, repository: `rails/rails`, log: `Cannot load database configuration: No such file - config/database.yml`, category: model.CategoryCodeFailure, provider: `Rails`, errorFamily: `database-config-missing`},
		{name: `eco-ruby-rails-secret-key`, repository: `rails/rails`, log: `ArgumentError: Missing ` + "`" + `secret_key_base` + "`" + ` for production environment`, category: model.CategoryCodeFailure, provider: `Rails`, errorFamily: `secret-key-base-missing`},
		{name: `eco-ruby-rake-task-missing`, repository: `ruby/rake`, log: `rake aborted!
Don't know how to build task 'db:seed:prod'`, category: model.CategoryCodeFailure, provider: `Rake`, errorFamily: `task-not-found`},
		{name: `eco-ruby-rake-aborted`, repository: `ruby/rake`, log: `rake aborted!
RuntimeError: build failed`, category: model.CategoryCodeFailure, provider: `Rake`, errorFamily: `task-aborted`},
		{name: `eco-ruby-rails-aborted`, repository: `rails/rails`, log: `rails aborted!
RuntimeError: database seed failed`, category: model.CategoryCodeFailure, provider: `Rails`, errorFamily: `rails-task-aborted`},
		{name: `eco-ruby-ruby-bad-interpreter`, repository: `rbenv/rbenv`, log: `/usr/local/bin/bundle: /usr/bin/ruby: bad interpreter: No such file or directory`, category: model.CategoryToolchainFailure, provider: `Ruby`, errorFamily: `ruby-interpreter-missing`},
		{name: `eco-ruby-ruby-openssl-missing`, repository: `ruby/ruby`, log: `LoadError: cannot load such file -- openssl`, category: model.CategoryToolchainFailure, provider: `Ruby`, errorFamily: `openssl-extension-missing`},
		{name: `eco-ruby-ruby-psych-missing`, repository: `ruby/ruby`, log: `LoadError: cannot load such file -- psych`, category: model.CategoryToolchainFailure, provider: `Ruby`, errorFamily: `yaml-extension-missing`},
		{name: `eco-ruby-rails-zeitwerk`, repository: `fxn/zeitwerk`, log: `Zeitwerk::NameError: expected file app/models/vat.rb to define constant Vat, but didn't`, category: model.CategoryCodeFailure, provider: `Rails Zeitwerk`, errorFamily: `autoload-name-mismatch`},
		{name: `eco-ruby-rails-record-not-unique`, repository: `rails/rails`, log: `ActiveRecord::RecordNotUnique: PG::UniqueViolation: ERROR: duplicate key value violates unique constraint`, category: model.CategoryCodeFailure, provider: `Rails ActiveRecord`, errorFamily: `unique-constraint`},
		{name: `eco-ruby-rails-connection-not-established`, repository: `rails/rails`, log: `ActiveRecord::ConnectionNotEstablished: connection to server at "db" (172.18.0.2), port 5432 failed: Connection refused`, category: model.CategoryNetworkFailure, provider: `Rails ActiveRecord`, errorFamily: `connection-failed`},
		{name: `eco-rust-cargo-version-select`, repository: `rust-lang/cargo`, log: `error: failed to select a version for the requirement ` + "`" + `tonic-build = "^0.6"` + "`" + ``, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `version-selection-failed`},
		{name: `eco-rust-cargo-custom-build`, repository: `rust-lang/cargo`, log: `error: failed to run custom build command for ` + "`" + `openssl-sys v0.9.103` + "`" + ``, category: model.CategoryToolchainFailure, provider: `Cargo`, errorFamily: `custom-build-command-failed`},
		{name: `eco-rust-cargo-linking-cc`, repository: `rust-lang/rust`, log: `error: linking with ` + "`" + `cc` + "`" + ` failed: exit status: 1`, category: model.CategoryToolchainFailure, provider: `Rust linker`, errorFamily: `linker-failed`},
		{name: `eco-rust-cargo-undefined-symbol`, repository: `rust-lang/rust`, log: `rust-lld: error: undefined symbol: decl1::decl1`, category: model.CategoryCodeFailure, provider: `Rust linker`, errorFamily: `undefined-symbol`},
		{name: `eco-rust-cargo-target-missing`, repository: `rust-lang/rust`, log: `error[E0463]: can't find crate for ` + "`" + `std` + "`" + `
= note: the ` + "`" + `wasm32-unknown-unknown` + "`" + ` target may not be installed`, category: model.CategoryToolchainFailure, provider: `Rustup`, errorFamily: `target-not-installed`},
		{name: `eco-rust-cargo-lock-needs-update`, repository: `rust-lang/cargo`, log: `error: the lock file /workspace/Cargo.lock needs to be updated but --locked was passed to prevent this`, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `lockfile-needs-update`},
		{name: `eco-rust-cargo-offline-missing`, repository: `rust-lang/cargo`, log: `error: no matching package named ` + "`" + `foo` + "`" + ` found
location searched: crates.io index
required by package app
As a reminder, you're using offline mode`, category: model.CategoryDependencyRegistry, provider: `Cargo`, errorFamily: `offline-package-missing`},
		{name: `eco-rust-cargo-crates-network`, repository: `rust-lang/cargo`, log: `warning: spurious network error: [28] Timeout was reached while downloading from https://index.crates.io/config.json`, category: model.CategoryNetworkFailure, provider: `crates.io`, errorFamily: `registry-connectivity`},
		{name: `eco-rust-cargo-registry-auth`, repository: `rust-lang/cargo`, log: `error: no token found for ` + "`" + `my-registry` + "`" + `, please run ` + "`" + `cargo login --registry my-registry` + "`" + ``, category: model.CategoryCodeFailure, provider: `Cargo registry`, errorFamily: `registry-authentication-failed`},
		{name: `eco-rust-cargo-yanked`, repository: `rust-lang/cargo`, log: `error: failed to select a version for ` + "`" + `time` + "`" + `. version 0.3.20 is yanked`, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `yanked-version`},
		{name: `eco-rust-cargo-checksum`, repository: `rust-lang/cargo`, log: `error: failed to verify the checksum of ` + "`" + `serde v1.0.0` + "`" + ``, category: model.CategoryDependencyRegistry, provider: `Cargo registry`, errorFamily: `checksum-mismatch`},
		{name: `eco-rust-cargo-patch-resolution`, repository: `rust-lang/cargo`, log: `error: patch for ` + "`" + `serde` + "`" + ` in ` + "`" + `https://github.com/rust-lang/crates.io-index` + "`" + ` failed to resolve`, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `patch-resolution-failed`},
		{name: `eco-rust-cargo-feature-missing`, repository: `rust-lang/cargo`, log: `package ` + "`" + `app` + "`" + ` depends on ` + "`" + `tokio` + "`" + `, with features: ` + "`" + `invalid-feature` + "`" + ` but ` + "`" + `tokio` + "`" + ` does not have these features.`, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `feature-not-found`},
		{name: `eco-rust-cargo-package-id`, repository: `rust-lang/cargo`, log: `error: package ID specification ` + "`" + `missing-crate` + "`" + ` did not match any packages`, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `package-id-not-found`},
		{name: `eco-rust-cargo-workspace-member`, repository: `rust-lang/cargo`, log: `error: failed to load manifest for workspace member ` + "`" + `/workspace/missing` + "`" + ``, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `workspace-member-invalid`},
		{name: `eco-rust-cargo-manifest-parse`, repository: `rust-lang/cargo`, log: `error: failed to parse manifest at ` + "`" + `/workspace/Cargo.toml` + "`" + `
Caused by: TOML parse error at line 4`, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `manifest-parse-error`},
		{name: `eco-rust-cargo-virtual-manifest`, repository: `rust-lang/cargo`, log: `error: this virtual manifest specifies a ` + "`" + `dependencies` + "`" + ` section, which is not allowed`, category: model.CategoryCodeFailure, provider: `Cargo`, errorFamily: `virtual-manifest-command-invalid`},
		{name: `eco-rust-rustup-toolchain-missing`, repository: `rust-lang/rustup`, log: `error: toolchain ` + "`" + `nightly-2026-01-01-x86_64-unknown-linux-gnu` + "`" + ` is not installed`, category: model.CategoryToolchainFailure, provider: `Rustup`, errorFamily: `toolchain-not-installed`},
		{name: `eco-rust-rustup-download`, repository: `rust-lang/rustup`, log: `error: component download failed for rustc-x86_64-unknown-linux-gnu: could not download file from https://static.rust-lang.org/dist/foo.tar.xz`, category: model.CategoryNetworkFailure, provider: `Rustup`, errorFamily: `toolchain-download-failed`},
		{name: `eco-rust-rustup-component-unavailable`, repository: `rust-lang/rustup`, log: `error: component ` + "`" + `rustfmt` + "`" + ` for target ` + "`" + `x86_64-unknown-linux-gnu` + "`" + ` is unavailable for download for channel nightly`, category: model.CategoryToolchainFailure, provider: `Rustup`, errorFamily: `component-unavailable`},
		{name: `eco-rust-clippy-deny-warning`, repository: `rust-lang/rust-clippy`, log: `error: this ` + "`" + `if` + "`" + ` statement can be collapsed
= note: ` + "`" + `-D clippy::collapsible-if` + "`" + ` implied by ` + "`" + `-D warnings` + "`" + ``, category: model.CategoryCodeFailure, provider: `Clippy`, errorFamily: `lint-denied`},
		{name: `eco-rust-rustfmt-check`, repository: `rust-lang/rustfmt`, log: `Diff in /workspace/src/main.rs:1:
-fn main(){
+fn main() {`, category: model.CategoryCodeFailure, provider: `rustfmt`, errorFamily: `formatting-diff`},
		{name: `eco-rust-rust-panic`, repository: `rust-lang/rust`, log: `thread 'main' panicked at src/main.rs:10:5:
index out of bounds`, category: model.CategoryCodeFailure, provider: `Rust`, errorFamily: `runtime-panic`},
		{name: `eco-rust-rust-stack-overflow`, repository: `rust-lang/rust`, log: `thread 'main' has overflowed its stack
fatal runtime error: stack overflow`, category: model.CategoryResourceExhaustion, provider: `Rust`, errorFamily: `stack-overflow`},
		{name: `eco-rust-rust-oom`, repository: `rust-lang/rust`, log: `memory allocation of 1048576 bytes failed`, category: model.CategoryResourceExhaustion, provider: `Rust`, errorFamily: `memory-exhaustion`},
		{name: `eco-rust-proc-macro-panic`, repository: `rust-lang/rust`, log: `error: proc macro panicked
help: message: invalid input`, category: model.CategoryCodeFailure, provider: `Rust proc-macro`, errorFamily: `proc-macro-panicked`},
		{name: `eco-rust-rust-feature-stable`, repository: `rust-lang/rust`, log: `error[E0554]: ` + "`" + `#![feature]` + "`" + ` may not be used on the stable release channel`, category: model.CategoryCodeFailure, provider: `Rust`, errorFamily: `unstable-feature-on-stable`},
		{name: `eco-rust-rust-edition`, repository: `rust-lang/cargo`, log: `error: this version of Cargo is older than the ` + "`" + `2024` + "`" + ` edition, and only supports ` + "`" + `2015` + "`" + `, ` + "`" + `2018` + "`" + `, and ` + "`" + `2021` + "`" + ` editions.`, category: model.CategoryToolchainFailure, provider: `Rust`, errorFamily: `edition-unsupported`},
		{name: `eco-rust-rust-pkgconfig`, repository: `rust-lang/cargo`, log: `The system library ` + "`" + `libudev` + "`" + ` required by crate ` + "`" + `libudev-sys` + "`" + ` was not found. The file ` + "`" + `libudev.pc` + "`" + ` needs to be installed.`, category: model.CategoryToolchainFailure, provider: `Rust native dependency`, errorFamily: `pkg-config-failed`},
		{name: `eco-rust-rust-bindgen-libclang`, repository: `rust-lang/rust-bindgen`, log: `Unable to find libclang: couldn't find any valid shared libraries matching: ['libclang.so']`, category: model.CategoryToolchainFailure, provider: `bindgen`, errorFamily: `libclang-missing`},
		{name: `eco-php-composer-resolution`, repository: `composer/composer`, log: `Your requirements could not be resolved to an installable set of packages.
Problem 1 - Root composer.json requires foo/bar ^2.0`, category: model.CategoryCodeFailure, provider: `Composer`, errorFamily: `dependency-resolution-failed`},
		{name: `eco-php-composer-package-not-found`, repository: `composer/composer`, log: `The requested package vendor/missing could not be found in any version, there may be a typo in the package name.`, category: model.CategoryCodeFailure, provider: `Composer`, errorFamily: `package-not-found`},
		{name: `eco-php-composer-platform-php`, repository: `composer/composer`, log: `vendor/pkg 2.0 requires php >=8.3 -> your php version (8.1.27) does not satisfy that requirement.`, category: model.CategoryToolchainFailure, provider: `Composer`, errorFamily: `php-version-incompatible`},
		{name: `eco-php-composer-platform-ext`, repository: `composer/composer`, log: `Root composer.json requires PHP extension ext-intl * but it is missing from your system. Install or enable PHP's intl extension.`, category: model.CategoryToolchainFailure, provider: `Composer`, errorFamily: `php-extension-missing`},
		{name: `eco-php-composer-lock-outdated`, repository: `composer/composer`, log: `Warning: The lock file is not up to date with the latest changes in composer.json.`, category: model.CategoryCodeFailure, provider: `Composer`, errorFamily: `lockfile-out-of-date`},
		{name: `eco-php-composer-lock-missing`, repository: `composer/composer`, log: `No composer.lock file present. Updating dependencies to latest instead of installing from lock file.`, category: model.CategoryCodeFailure, provider: `Composer`, errorFamily: `lockfile-missing`},
		{name: `eco-php-composer-github-rate`, repository: `composer/composer`, log: `Could not authenticate against github.com. API rate limit exhausted.`, category: model.CategoryDependencyRegistry, provider: `Composer/GitHub`, errorFamily: `github-rate-limit`},
		{name: `eco-php-composer-network`, repository: `composer/composer`, log: `curl error 28 while downloading https://repo.packagist.org/packages.json: Connection timed out`, category: model.CategoryDependencyRegistry, provider: `Packagist`, errorFamily: `registry-connectivity`},
		{name: `eco-php-composer-dist-checksum`, repository: `composer/composer`, log: `The checksum verification of the file failed (downloaded from https://example.com/pkg.zip)`, category: model.CategoryDependencyRegistry, provider: `Composer`, errorFamily: `checksum-mismatch`},
		{name: `eco-php-composer-security-block`, repository: `composer/composer`, log: `found vendor/package[1.0.0] but these were not loaded, because they are affected by security advisories.`, category: model.CategoryCodeFailure, provider: `Composer`, errorFamily: `security-advisory-block`},
		{name: `eco-php-php-fatal`, repository: `php/php-src`, log: `PHP Fatal error: Uncaught Error: Call to undefined function foo() in /app/index.php:4`, category: model.CategoryCodeFailure, provider: `PHP`, errorFamily: `fatal-error`},
		{name: `eco-php-php-parse`, repository: `php/php-src`, log: `PHP Parse error: syntax error, unexpected token "}" in /app/index.php on line 7`, category: model.CategoryCodeFailure, provider: `PHP`, errorFamily: `parse-error`},
		{name: `eco-php-php-type-error`, repository: `php/php-src`, log: `PHP Fatal error: Uncaught TypeError: foo(): Argument #1 must be of type string, int given`, category: model.CategoryCodeFailure, provider: `PHP`, errorFamily: `type-error`},
		{name: `eco-php-php-memory`, repository: `php/php-src`, log: `PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes)`, category: model.CategoryResourceExhaustion, provider: `PHP`, errorFamily: `memory-exhaustion`},
		{name: `eco-php-php-extension-load`, repository: `php/php-src`, log: `PHP Warning: PHP Startup: Unable to load dynamic library 'pdo_mysql' (cannot open shared object file)`, category: model.CategoryToolchainFailure, provider: `PHP`, errorFamily: `extension-load-failed`},
		{name: `eco-php-phpunit-failures`, repository: `sebastianbergmann/phpunit`, log: `FAILURES!
Tests: 42, Assertions: 80, Failures: 2.`, category: model.CategoryCodeFailure, provider: `PHPUnit`, errorFamily: `test-failure`},
		{name: `eco-php-phpunit-errors`, repository: `sebastianbergmann/phpunit`, log: `ERRORS!
Tests: 10, Assertions: 8, Errors: 1.`, category: model.CategoryCodeFailure, provider: `PHPUnit`, errorFamily: `test-error`},
		{name: `eco-php-laravel-key`, repository: `laravel/framework`, log: `Illuminate\Encryption\MissingAppKeyException: No application encryption key has been specified.`, category: model.CategoryCodeFailure, provider: `Laravel`, errorFamily: `app-key-missing`},
		{name: `eco-php-laravel-class-not-found`, repository: `laravel/framework`, log: `Illuminate\Contracts\Container\BindingResolutionException: Target class [App\Services\Foo] does not exist.`, category: model.CategoryCodeFailure, provider: `Laravel/PHP`, errorFamily: `class-not-found`},
		{name: `eco-php-artisan-command-missing`, repository: `laravel/framework`, log: `There are no commands defined in the "foo" namespace.`, category: model.CategoryCodeFailure, provider: `Laravel Artisan`, errorFamily: `command-not-found`},
		{name: `eco-dart-pub-version-solving`, repository: `dart-lang/i18n`, log: `Because app depends on flutter_localizations from sdk which depends on intl 0.19.0, intl 0.19.0 is required. So, because app depends on intl ^0.20.0, version solving failed.`, category: model.CategoryCodeFailure, provider: `Dart Pub`, errorFamily: `version-solving-failed`},
		{name: `eco-dart-pub-sdk-version`, repository: `dart-lang/pub-dev`, log: `The current Flutter SDK version is 3.13.0-0.3.pre.
Because app requires Flutter SDK version >=3.13.0, version solving failed.`, category: model.CategoryToolchainFailure, provider: `Dart Pub`, errorFamily: `sdk-version-incompatible`},
		{name: `eco-dart-pub-package-not-found`, repository: `dart-lang/pub`, log: `Because app depends on missing_pkg any which doesn't exist (could not find package missing_pkg at https://pub.dev), version solving failed.`, category: model.CategoryDependencyRegistry, provider: `pub.dev`, errorFamily: `package-not-found`},
		{name: `eco-dart-pub-network`, repository: `dart-lang/pub`, log: `Got socket error trying to find package http at https://pub.dev. SocketException: Failed host lookup: pub.dev`, category: model.CategoryDependencyRegistry, provider: `pub.dev`, errorFamily: `registry-connectivity`},
		{name: `eco-dart-dart-analyzer-error`, repository: `dart-lang/sdk`, log: `error • Undefined name 'foo'. • lib/main.dart:4:3 • undefined_identifier`, category: model.CategoryCodeFailure, provider: `Dart analyzer`, errorFamily: `analyzer-error`},
		{name: `eco-dart-dart-compile-error`, repository: `dart-lang/sdk`, log: `lib/main.dart:4:10: Error: The method 'foo' isn't defined for the class 'App'.`, category: model.CategoryCodeFailure, provider: `Dart`, errorFamily: `compile-error`},
		{name: `eco-dart-flutter-plugin-missing`, repository: `flutter/flutter`, log: `Error: Plugin project :camera_android not found. Please update settings.gradle.`, category: model.CategoryCodeFailure, provider: `Flutter`, errorFamily: `plugin-not-found`},
		{name: `eco-dart-flutter-cocoapods-missing`, repository: `flutter/flutter`, log: `Warning: CocoaPods not installed. Skipping pod install. CocoaPods is used to retrieve the iOS platform side's plugin code.`, category: model.CategoryToolchainFailure, provider: `Flutter iOS`, errorFamily: `cocoapods-not-installed`},
		{name: `eco-dart-flutter-pods-outdated`, repository: `flutter/flutter`, log: `Error: CocoaPods's specs repository is too out-of-date to satisfy dependencies.`, category: model.CategoryDependencyRegistry, provider: `CocoaPods`, errorFamily: `specs-repository-outdated`},
		{name: `eco-dart-flutter-gradle-failed`, repository: `flutter/flutter`, log: `Error: Gradle task assembleDebug failed with exit code 1`, category: model.CategoryCodeFailure, provider: `Flutter Android`, errorFamily: `gradle-task-failed`},
		{name: `eco-dart-flutter-android-sdk`, repository: `flutter/flutter`, log: `Android SDK not found. Define location with sdk.dir in the local.properties file or with an ANDROID_HOME environment variable.`, category: model.CategoryToolchainFailure, provider: `Flutter Android`, errorFamily: `android-sdk-missing`},
		{name: `eco-dart-flutter-license`, repository: `flutter/flutter`, log: `You have not accepted the license agreements of the following SDK components: [Android SDK Platform 35].`, category: model.CategoryToolchainFailure, provider: `Android SDK`, errorFamily: `android-license-not-accepted`},
		{name: `eco-dart-flutter-doctor-xcode`, repository: `flutter/flutter`, log: `Xcode installation is incomplete; a full installation is necessary for iOS development.`, category: model.CategoryToolchainFailure, provider: `Flutter iOS`, errorFamily: `xcode-incomplete`},
		{name: `eco-dart-flutter-test-failure`, repository: `flutter/flutter`, log: `Expected: <true>
  Actual: <false>
Some tests failed.`, category: model.CategoryCodeFailure, provider: `Flutter test`, errorFamily: `test-failure`},
		{name: `eco-beam-mix-deps-unavailable`, repository: `elixir-lang/elixir`, log: `Unchecked dependencies for environment test:
* plug (Hex package)
  the dependency is not available, run "mix deps.get"`, category: model.CategoryCodeFailure, provider: `Mix`, errorFamily: `dependency-unavailable`},
		{name: `eco-beam-mix-deps-diverged`, repository: `elixir-lang/elixir`, log: `Unchecked dependencies for environment dev:
* foo (../foo)
  the dependency foo is diverged`, category: model.CategoryCodeFailure, provider: `Mix`, errorFamily: `dependency-diverged`},
		{name: `eco-beam-mix-compile-error`, repository: `elixir-lang/elixir`, log: `** (CompileError) lib/app.ex:12: undefined function foo/0`, category: model.CategoryCodeFailure, provider: `Elixir`, errorFamily: `compile-error`},
		{name: `eco-beam-elixir-function-clause`, repository: `elixir-lang/elixir`, log: `** (FunctionClauseError) no function clause matching in App.run/1`, category: model.CategoryCodeFailure, provider: `Elixir`, errorFamily: `function-clause-error`},
		{name: `eco-beam-elixir-match-error`, repository: `elixir-lang/elixir`, log: `** (MatchError) no match of right hand side value: {:error, :enoent}`, category: model.CategoryCodeFailure, provider: `Elixir`, errorFamily: `match-error`},
		{name: `eco-beam-elixir-undefined-function`, repository: `elixir-lang/elixir`, log: `** (UndefinedFunctionError) function Foo.bar/0 is undefined (module Foo is not available)`, category: model.CategoryCodeFailure, provider: `Elixir`, errorFamily: `undefined-function`},
		{name: `eco-beam-hex-package-missing`, repository: `hexpm/hex`, log: `No package with name missing_pkg (from: mix.exs) in registry`, category: model.CategoryDependencyRegistry, provider: `Hex`, errorFamily: `package-not-found`},
		{name: `eco-beam-hex-auth`, repository: `hexpm/hex`, log: `** (Mix) Invalid API key`, category: model.CategoryCodeFailure, provider: `Hex`, errorFamily: `authentication-failed`},
		{name: `eco-beam-hex-network`, repository: `hexpm/hex`, log: `Failed to fetch record for plug from registry (using cache instead)
{:failed_connect, [{:to_address, {'repo.hex.pm', 443}}, {:inet, [:inet], :nxdomain}]}`, category: model.CategoryDependencyRegistry, provider: `Hex`, errorFamily: `registry-connectivity`},
		{name: `eco-beam-mix-test-failure`, repository: `elixir-lang/elixir`, log: `Finished in 0.1 seconds
10 tests, 1 failure`, category: model.CategoryCodeFailure, provider: `ExUnit`, errorFamily: `test-failure`},
		{name: `eco-beam-erlang-undef`, repository: `erlang/otp`, log: `exception error: undefined function foo:bar/0`, category: model.CategoryCodeFailure, provider: `Erlang`, errorFamily: `undefined-function`},
		{name: `eco-beam-erlang-badmatch`, repository: `erlang/otp`, log: `exception error: no match of right hand side value {error,enoent}`, category: model.CategoryCodeFailure, provider: `Erlang`, errorFamily: `badmatch`},
		{name: `eco-beam-rebar-package-missing`, repository: `erlang/rebar3`, log: `===> Package missing_dep not found in any repo`, category: model.CategoryDependencyRegistry, provider: `rebar3`, errorFamily: `package-not-found`},
		{name: `eco-beam-rebar-compile`, repository: `erlang/rebar3`, log: `===> Compiling app
src/app.erl:10: syntax error before: end`, category: model.CategoryCodeFailure, provider: `rebar3`, errorFamily: `compile-error`},
		{name: `eco-cpp-gcc-header-missing`, repository: `gcc-mirror/gcc`, log: `src/main.c:2:10: fatal error: openssl/ssl.h: No such file or directory
compilation terminated.`, category: model.CategoryToolchainFailure, provider: `C/C++ compiler`, errorFamily: `header-not-found`},
		{name: `eco-cpp-clang-header-missing`, repository: `llvm/llvm-project`, log: `src/main.cc:2:10: fatal error: 'fmt/core.h' file not found`, category: model.CategoryToolchainFailure, provider: `Clang`, errorFamily: `header-not-found`},
		{name: `eco-cpp-cpp-undefined-reference`, repository: `llvm/llvm-project`, log: `main.o: in function ` + "`" + `main': undefined reference to ` + "`" + `foo()'`, category: model.CategoryCodeFailure, provider: `C/C++ linker`, errorFamily: `undefined-reference`},
		{name: `eco-cpp-cpp-multiple-definition`, repository: `gcc-mirror/gcc`, log: `ld: foo.o: multiple definition of ` + "`" + `global'; bar.o:first defined here`, category: model.CategoryCodeFailure, provider: `C/C++ linker`, errorFamily: `multiple-definition`},
		{name: `eco-cpp-cpp-ld-library-missing`, repository: `llvm/llvm-project`, log: `ld: cannot find -lssl: No such file or directory`, category: model.CategoryToolchainFailure, provider: `C/C++ linker`, errorFamily: `library-not-found`},
		{name: `eco-cpp-cpp-compiler-killed`, repository: `gcc-mirror/gcc`, log: `g++: fatal error: Killed signal terminated program cc1plus
compilation terminated.`, category: model.CategoryResourceExhaustion, provider: `C/C++ compiler`, errorFamily: `compiler-killed`},
		{name: `eco-cpp-cpp-internal-compiler`, repository: `gcc-mirror/gcc`, log: `internal compiler error: Segmentation fault`, category: model.CategoryToolchainFailure, provider: `C/C++ compiler`, errorFamily: `internal-compiler-error`},
		{name: `eco-cpp-cpp-werror`, repository: `gcc-mirror/gcc`, log: `cc1: all warnings being treated as errors`, category: model.CategoryCodeFailure, provider: `C/C++ compiler`, errorFamily: `warnings-as-errors`},
		{name: `eco-cpp-cmake-source-missing`, repository: `Kitware/CMake`, log: `CMake Error at CMakeLists.txt:12 (add_executable):
  Cannot find source file:
    src/missing.cpp`, category: model.CategoryCodeFailure, provider: `CMake`, errorFamily: `source-file-missing`},
		{name: `eco-cpp-cmake-package-missing`, repository: `Kitware/CMake`, log: `Could not find a package configuration file provided by "Boost" with any of the following names: BoostConfig.cmake`, category: model.CategoryToolchainFailure, provider: `CMake`, errorFamily: `package-not-found`},
		{name: `eco-cpp-cmake-generator`, repository: `Kitware/CMake`, log: `CMake Error: Could not create named generator Ninja`, category: model.CategoryToolchainFailure, provider: `CMake`, errorFamily: `generator-unavailable`},
		{name: `eco-cpp-cmake-compiler-missing`, repository: `Kitware/CMake`, log: `No CMAKE_CXX_COMPILER could be found.`, category: model.CategoryCodeFailure, provider: `CMake`, errorFamily: `compiler-not-found`},
		{name: `eco-cpp-cmake-cache-source-mismatch`, repository: `Kitware/CMake`, log: `CMake Error: The current CMakeCache.txt directory /tmp/build is different than the directory /home/user/build where CMakeCache.txt was created.`, category: model.CategoryCodeFailure, provider: `CMake`, errorFamily: `cache-source-mismatch`},
		{name: `eco-cpp-ninja-subcommand`, repository: `ninja-build/ninja`, log: `ninja: build stopped: subcommand failed.`, category: model.CategoryCodeFailure, provider: `Ninja`, errorFamily: `subcommand-failed`},
		{name: `eco-cpp-ninja-file-missing`, repository: `ninja-build/ninja`, log: `ninja: error: loading 'build.ninja': No such file or directory`, category: model.CategoryCodeFailure, provider: `Ninja`, errorFamily: `build-file-missing`},
		{name: `eco-cpp-make-target-missing`, repository: `mirror/make`, log: `make: *** No rule to make target 'generated.h', needed by 'app'. Stop.`, category: model.CategoryCodeFailure, provider: `Make`, errorFamily: `target-not-found`},
		{name: `eco-cpp-make-command-not-found`, repository: `mirror/make`, log: `make: protoc: Command not found
make: *** [Makefile:10: gen] Error 127`, category: model.CategoryToolchainFailure, provider: `Make`, errorFamily: `command-not-found`},
		{name: `eco-cpp-meson-dependency`, repository: `mesonbuild/meson`, log: `meson.build:12:0: ERROR: Dependency "libfoo" not found, tried pkgconfig and cmake`, category: model.CategoryToolchainFailure, provider: `Meson`, errorFamily: `dependency-not-found`},
		{name: `eco-cpp-meson-compiler`, repository: `mesonbuild/meson`, log: `meson.build:1:0: ERROR: Unknown compiler(s): [['cc'], ['gcc'], ['clang']]`, category: model.CategoryToolchainFailure, provider: `Meson`, errorFamily: `compiler-not-found`},
		{name: `eco-cpp-autoconf-command-missing`, repository: `autotools-mirror/autoconf`, log: `configure: error: no acceptable C compiler found in $PATH`, category: model.CategoryToolchainFailure, provider: `Autotools`, errorFamily: `required-command-missing`},
		{name: `eco-cpp-pkgconfig-package-missing`, repository: `pkgconf/pkgconf`, log: `Package libxml-2.0 was not found in the pkg-config search path.
No package 'libxml-2.0' found`, category: model.CategoryToolchainFailure, provider: `pkg-config`, errorFamily: `package-not-found`},
		{name: `eco-cpp-asan-heap-buffer`, repository: `google/sanitizers`, log: `ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018`, category: model.CategoryCodeFailure, provider: `AddressSanitizer`, errorFamily: `heap-buffer-overflow`},
		{name: `eco-cpp-asan-use-after-free`, repository: `google/sanitizers`, log: `ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000040`, category: model.CategoryCodeFailure, provider: `AddressSanitizer`, errorFamily: `heap-use-after-free`},
		{name: `eco-cpp-ubsan-runtime`, repository: `llvm/llvm-project`, log: `runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type int`, category: model.CategoryCodeFailure, provider: `UndefinedBehaviorSanitizer`, errorFamily: `undefined-behavior`},
		{name: `eco-cpp-tsan-race`, repository: `google/sanitizers`, log: `WARNING: ThreadSanitizer: data race (pid=1234)`, category: model.CategoryConcurrencyConflict, provider: `ThreadSanitizer`, errorFamily: `data-race`},
		{name: `eco-swift-swift-compile`, repository: `swiftlang/swift`, log: `Sources/App/main.swift:4:5: error: cannot find 'foo' in scope`, category: model.CategoryCodeFailure, provider: `Swift compiler`, errorFamily: `compile-error`},
		{name: `eco-swift-swift-link`, repository: `swiftlang/swift`, log: `clang: error: linker command failed with exit code 1 (use -v to see invocation)`, category: model.CategoryCodeFailure, provider: `Swift linker`, errorFamily: `linker-failed`},
		{name: `eco-swift-swift-module-missing`, repository: `swiftlang/swift`, log: `App.swift:2:8: error: no such module 'Alamofire'`, category: model.CategoryToolchainFailure, provider: `Swift compiler`, errorFamily: `module-not-found`},
		{name: `eco-swift-spm-resolve`, repository: `swiftlang/swift-package-manager`, log: `error: Dependencies could not be resolved because no versions of package foo match the requirement 9.0.0..<10.0.0`, category: model.CategoryDependencyRegistry, provider: `Swift Package Manager`, errorFamily: `dependency-resolution-failed`},
		{name: `eco-swift-spm-checkout`, repository: `swiftlang/swift-package-manager`, log: `error: Failed to clone repository https://github.com/example/foo.git:
Cloning into bare repository... fatal: unable to access: Could not resolve host`, category: model.CategoryNetworkFailure, provider: `Swift Package Manager`, errorFamily: `repository-fetch-failed`},
		{name: `eco-swift-spm-tools-version`, repository: `swiftlang/swift-package-manager`, log: `package at /workspace is using Swift tools version 6.2.0 but the installed version is 6.0.0`, category: model.CategoryToolchainFailure, provider: `Swift Package Manager`, errorFamily: `tools-version-incompatible`},
		{name: `eco-swift-xcode-signing`, repository: `apple/swift`, log: `Signing for "App" requires a development team. Select a development team in the Signing & Capabilities editor.`, category: model.CategoryCodeFailure, provider: `Xcode`, errorFamily: `signing-identity-missing`},
		{name: `eco-swift-xcode-profile`, repository: `fastlane/fastlane`, log: `error: No profiles for 'com.example.app' were found: Xcode couldn't find any iOS App Development provisioning profiles matching 'com.example.app'.`, category: model.CategoryCodeFailure, provider: `Xcode`, errorFamily: `provisioning-profile-missing`},
		{name: `eco-swift-xcode-destination`, repository: `fastlane/fastlane`, log: `xcodebuild: error: Unable to find a destination matching the provided destination specifier: { platform:iOS Simulator, name:iPhone 99 }`, category: model.CategoryToolchainFailure, provider: `Xcode`, errorFamily: `destination-unavailable`},
		{name: `eco-swift-xcode-test-failed`, repository: `apple/swift`, log: `** TEST FAILED **
Test Suite 'AppTests' failed at 2026-08-09`, category: model.CategoryCodeFailure, provider: `XCTest`, errorFamily: `test-failure`},
		{name: `eco-swift-cocoapods-spec-missing`, repository: `CocoaPods/CocoaPods`, log: `[!] Unable to find a specification for ` + "`" + `React-Core` + "`" + ` depended upon by ` + "`" + `RNPermissions` + "`" + ``, category: model.CategoryDependencyRegistry, provider: `CocoaPods`, errorFamily: `podspec-not-found`},
		{name: `eco-swift-cocoapods-repo-outdated`, repository: `CocoaPods/CocoaPods`, log: `[!] CocoaPods could not find compatible versions for pod "FirebaseCore": None of your spec sources contain a spec satisfying the dependency`, category: model.CategoryDependencyRegistry, provider: `CocoaPods`, errorFamily: `specs-repository-outdated`},
		{name: `eco-swift-cocoapods-lock-conflict`, repository: `CocoaPods/CocoaPods`, log: `CocoaPods could not find compatible versions for pod "Firebase/CoreOnly":
 In snapshot (Podfile.lock): 10.0.0
 In Podfile: 11.0.0`, category: model.CategoryCodeFailure, provider: `CocoaPods`, errorFamily: `pod-version-conflict`},
		{name: `eco-swift-cocoapods-podfile`, repository: `CocoaPods/CocoaPods`, log: `[!] Invalid ` + "`" + `Podfile` + "`" + ` file: undefined method ` + "`" + `use_native_modules!` + "`" + ` for #<Pod::Podfile>`, category: model.CategoryCodeFailure, provider: `CocoaPods`, errorFamily: `podfile-invalid`},
		{name: `eco-swift-cocoapods-sandbox`, repository: `CocoaPods/CocoaPods`, log: `error: The sandbox is not in sync with the Podfile.lock. Run 'pod install' or update your CocoaPods installation.`, category: model.CategoryCodeFailure, provider: `CocoaPods`, errorFamily: `sandbox-out-of-sync`},
		{name: `eco-swift-xcode-modulemap`, repository: `CocoaPods/CocoaPods`, log: `fatal error: module map file '/Pods/Headers/Public/Foo/Foo.modulemap' not found`, category: model.CategoryToolchainFailure, provider: `Xcode/Clang`, errorFamily: `modulemap-missing`},
		{name: `eco-swift-xcode-architecture`, repository: `apple/swift`, log: `ld: building for iOS Simulator, but linking in object file built for iOS, file foo.a for architecture arm64`, category: model.CategoryToolchainFailure, provider: `Xcode`, errorFamily: `architecture-mismatch`},
		{name: `eco-jvm-kotlin-unresolved`, repository: `JetBrains/kotlin`, log: `e: /workspace/src/Main.kt: (4, 5): Unresolved reference: missingFoo`, category: model.CategoryCodeFailure, provider: `Kotlin compiler`, errorFamily: `unresolved-reference`},
		{name: `eco-jvm-kotlin-type-mismatch`, repository: `JetBrains/kotlin`, log: `e: /workspace/src/Main.kt: (8, 12): Type mismatch: inferred type is Int but String was expected`, category: model.CategoryCodeFailure, provider: `Kotlin compiler`, errorFamily: `type-mismatch`},
		{name: `eco-jvm-kotlin-metadata-version`, repository: `JetBrains/kotlin`, log: `Module was compiled with an incompatible version of Kotlin. The binary version of its metadata is 2.1.0, expected version is 1.9.0.`, category: model.CategoryToolchainFailure, provider: `Kotlin compiler`, errorFamily: `metadata-version-incompatible`},
		{name: `eco-jvm-kapt-error`, repository: `JetBrains/kotlin`, log: `Execution failed for task :app:kaptDebugKotlin. > A failure occurred while executing KaptWithoutKotlincTask`, category: model.CategoryCodeFailure, provider: `KAPT`, errorFamily: `annotation-processor-failed`},
		{name: `eco-jvm-scala-not-found`, repository: `sbt/sbt`, log: `[error] /src/Main.scala:10:34: not found: value write`, category: model.CategoryCodeFailure, provider: `Scala compiler`, errorFamily: `symbol-not-found`},
		{name: `eco-jvm-scala-type-mismatch`, repository: `scala/scala3`, log: `[error] Main.scala:8:20: type mismatch; found: Int required: String`, category: model.CategoryCodeFailure, provider: `Scala compiler`, errorFamily: `type-mismatch`},
		{name: `eco-jvm-sbt-resolution`, repository: `sbt/sbt`, log: `[error] sbt.librarymanagement.ResolveException: Error downloading com.example:missing_2.13:1.0.0`, category: model.CategoryDependencyRegistry, provider: `sbt/Coursier`, errorFamily: `unresolved-dependency`},
		{name: `eco-jvm-sbt-eviction`, repository: `sbt/sbt`, log: `[error] found version conflict(s) in library dependencies; some are suspected to be binary incompatible:`, category: model.CategoryCodeFailure, provider: `sbt`, errorFamily: `version-conflict`},
		{name: `eco-jvm-sbt-java-home`, repository: `sbt/sbt`, log: `JAVA_HOME is set to an invalid directory: /opt/jdk-missing`, category: model.CategoryToolchainFailure, provider: `sbt`, errorFamily: `java-home-invalid`},
		{name: `eco-jvm-gradle-task-missing`, repository: `gradle/gradle`, log: `Task 'publishFoo' not found in root project 'app'.`, category: model.CategoryCodeFailure, provider: `Gradle`, errorFamily: `task-not-found`},
		{name: `eco-jvm-gradle-daemon-disappeared`, repository: `gradle/gradle`, log: `Gradle build daemon disappeared unexpectedly (it may have been killed or may have crashed)`, category: model.CategoryRunnerFailure, provider: `Gradle`, errorFamily: `daemon-disappeared`},
		{name: `eco-jvm-gradle-disk-cache`, repository: `gradle/gradle`, log: `Could not write to file hash cache. java.io.IOException: No space left on device`, category: model.CategoryResourceExhaustion, provider: `Gradle`, errorFamily: `disk-space-exhausted`},
		{name: `eco-jvm-maven-dependency-not-found`, repository: `apache/maven`, log: `Could not find artifact com.example:missing:jar:1.0.0 in central (https://repo.maven.apache.org/maven2)`, category: model.CategoryDependencyRegistry, provider: `Maven`, errorFamily: `artifact-not-found`},
		{name: `eco-jvm-maven-plugin-not-found`, repository: `apache/maven`, log: `No plugin found for prefix 'foo' in the current project and in the plugin groups`, category: model.CategoryDependencyRegistry, provider: `Maven`, errorFamily: `plugin-not-found`},
		{name: `eco-jvm-maven-enforcer`, repository: `apache/maven-enforcer`, log: `[ERROR] Failed to execute goal org.apache.maven.plugins:maven-enforcer-plugin:enforce: Some Enforcer rules have failed.`, category: model.CategoryCodeFailure, provider: `Maven Enforcer`, errorFamily: `enforcer-rule-failed`},
		{name: `eco-jvm-junit-failure`, repository: `junit-team/junit5`, log: `Tests run: 10, Failures: 1, Errors: 0, Skipped: 0`, category: model.CategoryCodeFailure, provider: `JUnit`, errorFamily: `test-failure`},
		{name: `eco-dotnet-dotnet-sdk-missing`, repository: `dotnet/sdk`, log: `A compatible installed .NET SDK for global.json version [8.0.400] was not found.`, category: model.CategoryToolchainFailure, provider: `.NET SDK`, errorFamily: `sdk-not-found`},
		{name: `eco-dotnet-dotnet-targeting-pack`, repository: `dotnet/sdk`, log: `error NETSDK1127: The targeting pack Microsoft.NETCore.App 9.0.0 is not installed.`, category: model.CategoryToolchainFailure, provider: `.NET SDK`, errorFamily: `targeting-pack-missing`},
		{name: `eco-dotnet-dotnet-workload`, repository: `dotnet/sdk`, log: `error NETSDK1147: To build this project, the following workloads must be installed: wasm-tools`, category: model.CategoryToolchainFailure, provider: `.NET SDK`, errorFamily: `workload-missing`},
		{name: `eco-dotnet-dotnet-restore-nuget`, repository: `NuGet/NuGet.Client`, log: `error NU1101: Unable to find package Missing.Package. No packages exist with this id in source(s): nuget.org`, category: model.CategoryCodeFailure, provider: `NuGet`, errorFamily: `package-not-found`},
		{name: `eco-dotnet-dotnet-version-conflict`, repository: `NuGet/NuGet.Client`, log: `error NU1605: Warning As Error: Detected package downgrade: Newtonsoft.Json from 13.0.3 to 12.0.1`, category: model.CategoryCodeFailure, provider: `NuGet`, errorFamily: `version-conflict`},
		{name: `eco-dotnet-dotnet-csharp-error`, repository: `dotnet/roslyn`, log: `Program.cs(4,9): error CS0103: The name 'foo' does not exist in the current context`, category: model.CategoryCodeFailure, provider: `C# compiler`, errorFamily: `compile-error`},
		{name: `eco-dotnet-dotnet-fsharp-error`, repository: `dotnet/fsharp`, log: `Program.fs(4,5): error FS0039: The value or constructor 'foo' is not defined.`, category: model.CategoryCodeFailure, provider: `F# compiler`, errorFamily: `compile-error`},
		{name: `eco-dotnet-dotnet-test-fail`, repository: `microsoft/vstest`, log: `Failed!  - Failed: 1, Passed: 9, Skipped: 0, Total: 10`, category: model.CategoryCodeFailure, provider: `.NET test`, errorFamily: `test-failure`},
		{name: `eco-dotnet-msbuild-project-missing`, repository: `dotnet/msbuild`, log: `MSBUILD : error MSB1009: Project file does not exist. Switch: app.csproj`, category: model.CategoryCodeFailure, provider: `MSBuild`, errorFamily: `project-not-found`},
		{name: `eco-dotnet-msbuild-sdk-resolver`, repository: `dotnet/msbuild`, log: `error MSB4236: The SDK 'Microsoft.NET.Sdk.Web' specified could not be found.`, category: model.CategoryToolchainFailure, provider: `MSBuild`, errorFamily: `sdk-resolver-failed`},
		{name: `eco-other-cabal-resolve`, repository: `haskell/cabal`, log: `cabal: Could not resolve dependencies:
[__0] trying: app-0.1.0.0
[__1] next goal: aeson`, category: model.CategoryDependencyRegistry, provider: `Cabal`, errorFamily: `dependency-resolution-failed`},
		{name: `eco-other-cabal-package-missing`, repository: `haskell/cabal`, log: `cabal: Unknown package "missing-package".`, category: model.CategoryDependencyRegistry, provider: `Hackage`, errorFamily: `package-not-found`},
		{name: `eco-other-ghc-compile`, repository: `ghc/ghc`, log: `src/Main.hs:4:3: error:
    Variable not in scope: foo :: IO ()`, category: model.CategoryCodeFailure, provider: `GHC`, errorFamily: `compile-error`},
		{name: `eco-other-stack-ghc-missing`, repository: `commercialhaskell/stack`, log: `Error: No setup information found for ghc-9.8.2 on your platform.`, category: model.CategoryToolchainFailure, provider: `Stack`, errorFamily: `ghc-not-installed`},
		{name: `eco-other-stack-resolver`, repository: `commercialhaskell/stack`, log: `Unable to load snapshot: No information found for resolver lts-99.0`, category: model.CategoryDependencyRegistry, provider: `Stack`, errorFamily: `resolver-failed`},
		{name: `eco-other-opam-no-solution`, repository: `ocaml/opam`, log: `[ERROR] No solution found, exiting`, category: model.CategoryCodeFailure, provider: `opam`, errorFamily: `no-solution`},
		{name: `eco-other-opam-package-missing`, repository: `ocaml/opam`, log: `[ERROR] No package named missing_pkg found.`, category: model.CategoryDependencyRegistry, provider: `opam`, errorFamily: `package-not-found`},
		{name: `eco-other-dune-library-missing`, repository: `ocaml/dune`, log: `File "src/dune", line 4, characters 12-20:
Error: Library "foo" not found.`, category: model.CategoryToolchainFailure, provider: `Dune`, errorFamily: `library-not-found`},
		{name: `eco-other-dune-module-missing`, repository: `ocaml/dune`, log: `File "main.ml", line 3, characters 2-10:
Error: Unbound module Foo`, category: model.CategoryCodeFailure, provider: `Dune/OCaml`, errorFamily: `module-not-found`},
		{name: `eco-other-r-package-missing`, repository: `r-lib/actions`, log: `Error in library(foo) : there is no package called ‘foo’`, category: model.CategoryCodeFailure, provider: `R`, errorFamily: `package-not-found`},
		{name: `eco-other-r-dependency-solve`, repository: `r-lib/actions`, log: `Error: Cannot install packages:
* highcharter: Can't install dependency rjson
* rjson: Needs R >= 4.0.0`, category: model.CategoryDependencyRegistry, provider: `R pak`, errorFamily: `dependency-resolution-failed`},
		{name: `eco-other-r-configure-failed`, repository: `r-lib/textshaping`, log: `ERROR: configuration failed for package ‘textshaping’`, category: model.CategoryToolchainFailure, provider: `R package build`, errorFamily: `configuration-failed`},
		{name: `eco-other-r-header-missing`, repository: `r-lib/textshaping`, log: `fatal error: hb-ft.h: No such file or directory
compilation terminated.`, category: model.CategoryToolchainFailure, provider: `R package build`, errorFamily: `header-not-found`},
		{name: `eco-other-r-check-error`, repository: `r-lib/actions`, log: `Status: 1 ERROR, 2 WARNINGs, 1 NOTE`, category: model.CategoryCodeFailure, provider: `R CMD check`, errorFamily: `check-errors`},
		{name: `eco-other-testthat-fail`, repository: `r-lib/testthat`, log: `══ Failed tests ══
Failure (test-api.R:12:3): endpoint works`, category: model.CategoryCodeFailure, provider: `testthat`, errorFamily: `test-failure`},
		{name: `eco-other-luarocks-not-found`, repository: `luarocks/luarocks`, log: `Error: No results matching query were found for Lua 5.4.`, category: model.CategoryDependencyRegistry, provider: `LuaRocks`, errorFamily: `rock-not-found`},
		{name: `eco-other-lua-module-missing`, repository: `lua/lua`, log: `lua: main.lua:1: module 'socket' not found:`, category: model.CategoryCodeFailure, provider: `Lua`, errorFamily: `module-not-found`},
		{name: `eco-other-lua-syntax`, repository: `lua/lua`, log: `lua: main.lua:4: 'end' expected near <eof>`, category: model.CategoryCodeFailure, provider: `Lua`, errorFamily: `syntax-error`},
		{name: `eco-other-perl-module-missing`, repository: `Perl/perl5`, log: `Can't locate Foo/Bar.pm in @INC (you may need to install the Foo::Bar module)`, category: model.CategoryCodeFailure, provider: `Perl`, errorFamily: `module-not-found`},
		{name: `eco-other-perl-syntax`, repository: `Perl/perl5`, log: `syntax error at script.pl line 12, near "if ("`, category: model.CategoryCodeFailure, provider: `Perl`, errorFamily: `syntax-error`},
		{name: `eco-other-cpanm-fail`, repository: `miyagawa/cpanminus`, log: `! Installing Foo::Bar failed. See /root/.cpanm/work/build.log for details.`, category: model.CategoryDependencyRegistry, provider: `cpanm`, errorFamily: `distribution-install-failed`},
		{name: `eco-other-zig-compile`, repository: `ziglang/zig`, log: `src/main.zig:4:9: error: use of undeclared identifier 'foo'`, category: model.CategoryCodeFailure, provider: `Zig`, errorFamily: `compile-error`},
		{name: `eco-other-zig-lib-missing`, repository: `ziglang/zig`, log: `error: unable to find dynamic system library 'ssl' using strategy 'paths_first'. searched paths: none`, category: model.CategoryToolchainFailure, provider: `Zig`, errorFamily: `library-not-found`},
		{name: `eco-other-zig-cache`, repository: `ziglang/zig`, log: `error: unable to load build manifest from cache: InvalidFormat`, category: model.CategoryCacheFailure, provider: `Zig`, errorFamily: `cache-corrupt`},
		{name: `eco-other-bazel-package-missing`, repository: `bazelbuild/bazel`, log: `ERROR: no such package 'java/com/google/common/base': BUILD file not found in any of the following directories.`, category: model.CategoryCodeFailure, provider: `Bazel`, errorFamily: `package-not-found`},
		{name: `eco-other-bazel-target-missing`, repository: `bazelbuild/bazel`, log: `ERROR: no such target '//app:missing': target 'missing' not declared in package 'app'`, category: model.CategoryCodeFailure, provider: `Bazel`, errorFamily: `target-not-found`},
		{name: `eco-other-bazel-jdk`, repository: `bazelbuild/bazel`, log: `ERROR: no such package '@local_jdk//': Expected directory at /nonexistent but it does not exist.`, category: model.CategoryToolchainFailure, provider: `Bazel`, errorFamily: `local-jdk-missing`},
		{name: `eco-other-bazel-repo-fetch`, repository: `bazelbuild/bazel`, log: `ERROR: An error occurred during the fetch of repository 'foo': java.io.IOException: Error downloading [https://example.com/foo.tar.gz] to /cache: Read timed out`, category: model.CategoryNetworkFailure, provider: `Bazel`, errorFamily: `repository-fetch-failed`},
		{name: `eco-other-bazel-sandbox`, repository: `bazelbuild/bazel`, log: `ERROR: /workspace/BUILD:10:1: action failed: linux-sandbox failed: error executing command`, category: model.CategoryToolchainFailure, provider: `Bazel`, errorFamily: `sandbox-failure`},
		{name: `eco-other-nix-hash-mismatch`, repository: `NixOS/nixpkgs`, log: `error: hash mismatch in fixed-output derivation '/nix/store/x.drv':
 specified: sha256-aaa=
 got: sha256-bbb=`, category: model.CategoryCodeFailure, provider: `Nix`, errorFamily: `hash-mismatch`},
		{name: `eco-other-nix-builder-failed`, repository: `NixOS/nixpkgs`, log: `error: builder for '/nix/store/abc-package.drv' failed with exit code 2;`, category: model.CategoryCodeFailure, provider: `Nix`, errorFamily: `builder-failed`},
		{name: `eco-other-nix-eval-undefined`, repository: `NixOS/nix`, log: `error: undefined variable 'pkgsx'`, category: model.CategoryCodeFailure, provider: `Nix`, errorFamily: `undefined-variable`},
		{name: `eco-other-nix-flake-lock`, repository: `NixOS/nix`, log: `error: unable to download https://api.github.com/repos/NixOS/nixpkgs/commits/main: Could not resolve host`, category: model.CategoryNetworkFailure, provider: `Nix flakes`, errorFamily: `flake-fetch-failed`},
		{name: `eco-other-shell-command-not-found`, repository: `git/git`, log: `bash: line 4: protoc: command not found`, category: model.CategoryToolchainFailure, provider: `Shell`, errorFamily: `command-not-found`},
		{name: `eco-other-shell-unbound`, repository: `git/git`, log: `script.sh: line 12: VERSION: unbound variable`, category: model.CategoryCodeFailure, provider: `Shell`, errorFamily: `unbound-variable`},
		{name: `eco-other-shell-syntax`, repository: `git/git`, log: `script.sh: line 4: syntax error near unexpected token ` + "`" + `fi'`, category: model.CategoryCodeFailure, provider: `Shell`, errorFamily: `syntax-error`},
		{name: `eco-other-powershell-cmdlet`, repository: `PowerShell/PowerShell`, log: `The term 'dotnetx' is not recognized as the name of a cmdlet, function, script file, or operable program.`, category: model.CategoryToolchainFailure, provider: `PowerShell`, errorFamily: `command-not-found`},
		{name: `eco-other-powershell-parser`, repository: `PowerShell/PowerShell`, log: `ParserError: Unexpected token 'else' in expression or statement.`, category: model.CategoryCodeFailure, provider: `PowerShell`, errorFamily: `parser-error`},
		{name: `eco-extra-python-wheel-build`, repository: `pypa/pip`, log: `ERROR: Failed building wheel for cryptography`, category: model.CategoryToolchainFailure, provider: `pip`, errorFamily: `wheel-build-failed`},
		{name: `eco-extra-python-build-backend`, repository: `pypa/pip`, log: `error: subprocess-exited-with-error
× Getting requirements to build wheel did not run successfully.`, category: model.CategoryToolchainFailure, provider: `pip`, errorFamily: `build-backend-failed`},
		{name: `eco-extra-python-resolution-impossible`, repository: `pypa/pip`, log: `ERROR: Cannot install foo==1.0 and bar==2.0 because these package versions have conflicting dependencies.
ERROR: ResolutionImpossible`, category: model.CategoryCodeFailure, provider: `pip`, errorFamily: `resolution-impossible`},
		{name: `eco-extra-python-requires-python`, repository: `pypa/pip`, log: `ERROR: Package pkg requires a different Python: 3.10.14 not in '<3.10,>=3.8'`, category: model.CategoryToolchainFailure, provider: `pip`, errorFamily: `python-version-incompatible`},
		{name: `eco-extra-python-no-matching`, repository: `pypa/pip`, log: `ERROR: Could not find a version that satisfies the requirement missing_pkg==9.9.9
ERROR: No matching distribution found for missing_pkg==9.9.9`, category: model.CategoryDependencyRegistry, provider: `PyPI`, errorFamily: `no-matching-distribution`},
		{name: `eco-extra-pytest-collection`, repository: `pytest-dev/pytest`, log: `ERROR collecting tests/test_api.py
ImportError while importing test module
Interrupted: 1 error during collection`, category: model.CategoryCodeFailure, provider: `pytest`, errorFamily: `collection-error`},
		{name: `eco-extra-pytest-failures`, repository: `pytest-dev/pytest`, log: `================= 2 failed, 40 passed in 3.22s =================`, category: model.CategoryCodeFailure, provider: `pytest`, errorFamily: `test-failure`},
		{name: `eco-extra-pytest-timeout`, repository: `pytest-dev/pytest`, log: `E Failed: Timeout >5.0s`, category: model.CategoryTestFlake, provider: `pytest-timeout`, errorFamily: `test-timeout`},
		{name: `eco-extra-mypy-errors`, repository: `python/mypy`, log: `app.py:10: error: Incompatible return value type [return-value]
Found 1 error in 1 file`, category: model.CategoryCodeFailure, provider: `mypy`, errorFamily: `type-check-failed`},
		{name: `eco-extra-ruff-errors`, repository: `astral-sh/ruff`, log: `app.py:4:1: F401 ` + "`" + `os` + "`" + ` imported but unused
Found 1 error.`, category: model.CategoryCodeFailure, provider: `Ruff`, errorFamily: `lint-failed`},
		{name: `eco-extra-black-check`, repository: `psf/black`, log: `would reformat /workspace/app.py
Oh no! 💥 💔 💥
1 file would be reformatted.`, category: model.CategoryCodeFailure, provider: `Black`, errorFamily: `formatting-diff`},
		{name: `eco-extra-poetry-solve`, repository: `python-poetry/poetry`, log: `Because app depends on foo (^2.0) which doesn't match any versions, version solving failed.
SolverProblemError`, category: model.CategoryCodeFailure, provider: `Poetry`, errorFamily: `version-solving-failed`},
		{name: `eco-extra-uv-solve`, repository: `astral-sh/uv`, log: `× No solution found when resolving dependencies:
╰─▶ Because foo==1.0 depends on bar<2 and you require bar>=2, your requirements are unsatisfiable.`, category: model.CategoryCodeFailure, provider: `uv`, errorFamily: `resolution-impossible`},
		{name: `eco-extra-conda-unsat`, repository: `conda/conda`, log: `LibMambaUnsatisfiableError: Encountered problems while solving: package foo requires python <3.10`, category: model.CategoryCodeFailure, provider: `Conda`, errorFamily: `unsatisfiable`},
		{name: `eco-extra-node-syntax`, repository: `nodejs/node`, log: `SyntaxError: Unexpected token '}'`, category: model.CategoryCodeFailure, provider: `Node.js`, errorFamily: `syntax-error`},
		{name: `eco-extra-node-module-missing`, repository: `nodejs/node`, log: `Error: Cannot find module 'express'
code: 'MODULE_NOT_FOUND'`, category: model.CategoryCodeFailure, provider: `Node.js`, errorFamily: `module-not-found`},
		{name: `eco-extra-jest-fail`, repository: `jestjs/jest`, log: `Test Suites: 1 failed, 8 passed, 9 total
Tests: 2 failed, 40 passed, 42 total`, category: model.CategoryCodeFailure, provider: `Jest`, errorFamily: `test-failure`},
		{name: `eco-extra-vitest-fail`, repository: `vitest-dev/vitest`, log: `Test Files  1 failed | 8 passed (9)
Tests  2 failed | 40 passed (42)`, category: model.CategoryCodeFailure, provider: `Vitest`, errorFamily: `test-failure`},
		{name: `eco-extra-eslint-errors`, repository: `eslint/eslint`, log: `✖ 3 problems (3 errors, 0 warnings)`, category: model.CategoryCodeFailure, provider: `ESLint`, errorFamily: `lint-failed`},
		{name: `eco-extra-prettier-check`, repository: `prettier/prettier`, log: `Checking formatting...
[warn] src/app.ts
[warn] Code style issues found in the above file. Run Prettier with --write to fix.`, category: model.CategoryCodeFailure, provider: `Prettier`, errorFamily: `formatting-diff`},
		{name: `eco-extra-android-manifest-merge`, repository: `google/android-gradle-plugin`, log: `Manifest merger failed : uses-sdk:minSdkVersion 21 cannot be smaller than version 24 declared in library`, category: model.CategoryCodeFailure, provider: `Android Gradle Plugin`, errorFamily: `manifest-merge-failed`},
		{name: `eco-extra-android-aapt`, repository: `google/android-gradle-plugin`, log: `Android resource linking failed
ERROR: app/src/main/res/layout/main.xml:12: AAPT: error: resource color/missing not found.`, category: model.CategoryCodeFailure, provider: `Android AAPT2`, errorFamily: `resource-link-failed`},
		{name: `eco-extra-android-sdk-package`, repository: `android/nowinandroid`, log: `Failed to find target with hash string 'android-35' in: /opt/android-sdk`, category: model.CategoryToolchainFailure, provider: `Android SDK`, errorFamily: `sdk-package-missing`},
		{name: `eco-extra-android-ndk`, repository: `android/nowinandroid`, log: `No version of NDK matched the requested version 27.0.12077973. Versions available locally: 26.1.10909125`, category: model.CategoryToolchainFailure, provider: `Android NDK`, errorFamily: `ndk-missing`},
		{name: `eco-extra-github-rate`, repository: `cli/cli`, log: `API rate limit exceeded for 203.0.113.1.`, category: model.CategoryResourceExhaustion, provider: `GitHub API`, errorFamily: `rate-limit-exceeded`},
		{name: `eco-extra-github-branch-protection`, repository: `git/git`, log: `remote: error: GH006: Protected branch update failed for refs/heads/main.`, category: model.CategoryCodeFailure, provider: `GitHub`, errorFamily: `branch-protection-rejected`},
		{name: `eco-extra-github-secret-scanning`, repository: `github/docs`, log: `remote: error: GH013: Repository rule violations found for refs/heads/main.
- Push cannot contain secrets`, category: model.CategoryCodeFailure, provider: `GitHub Push Protection`, errorFamily: `secret-detected`},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: tt.repository, Log: tt.log}, Context{})
			if r.Category != tt.category {
				t.Fatalf("got category=%s provider=%q family=%q rules=%v", r.Category, r.Provider, r.ErrorFamily, r.MatchedRules)
			}
			matched := false
			for _, id := range r.MatchedRules {
				if id == tt.name { matched = true; break }
			}
			if !matched { t.Fatalf("expected rule %s to match, got %v", tt.name, r.MatchedRules) }
		})
	}
}
