package analyzer

import (
	"strings"
	"testing"

	"ciradar/internal/model"
)

func TestNPMExternal(t *testing.T) {
	a := New("test")
	r := a.Analyze(model.AnalysisInput{Repository: "acme/app", Log: "npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/react failed"}, Context{})
	if r.Category != model.CategoryDependencyRegistry {
		t.Fatalf("category=%s", r.Category)
	}
	if r.Provider != "npm" {
		t.Fatalf("provider=%s", r.Provider)
	}
}

func TestRedaction(t *testing.T) {
	r := NewRedactor().Redact("Authorization: Bearer abcdefghijklmnop token=hello")
	if r == "Authorization: Bearer abcdefghijklmnop token=hello" {
		t.Fatal("not redacted")
	}
}

func TestCodeFailure(t *testing.T) {
	a := New("test")
	r := a.Analyze(model.AnalysisInput{Log: "main.go:12:3: undefined: thing"}, Context{})
	if r.Category != model.CategoryCodeFailure {
		t.Fatalf("category=%s", r.Category)
	}
	if r.Confidence != model.ConfidenceLikelyCode {
		t.Fatalf("confidence=%s score=%d", r.Confidence, r.Score)
	}
}

func TestEnvironmentExtractionWithGitHubTimestamps(t *testing.T) {
	log := "2026-08-03T01:11:02Z Image: ubuntu-24.04\n2026-08-03T01:11:02Z Version: 20260727.1\n2026-08-03T01:11:03Z Node.js version: 22.17.0\n"
	env := ExtractEnvironment(log)
	if env.RunnerOS != "ubuntu-24.04" || env.RunnerImage != "20260727.1" || env.ToolVersions["node"] != "22.17.0" {
		t.Fatalf("env=%+v", env)
	}
}

func TestRedactionEnvironmentSecrets(t *testing.T) {
	input := "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890ABCD\nMY_API_TOKEN=top-secret-value\n"
	redacted := NewRedactor().Redact(input)
	if strings.Contains(redacted, "abcdefghijklmnopqrstuvwxyz1234567890ABCD") || strings.Contains(redacted, "top-secret-value") {
		t.Fatalf("environment secret was not redacted: %s", redacted)
	}
}

func TestRealWorldRegressionCases(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want model.Category
	}{
		{"pip dns beats no distribution", "WARNING: Retrying after NameResolutionError: Failed to resolve pypi.org\nERROR: No matching distribution found for numpy", model.CategoryNetworkFailure},
		{"artifact intermediary", "Error: Failed to FinalizeArtifact: Failed request: (403) Forbidden: Error from intermediary with HTTP status code 403", model.CategoryNetworkFailure},
		{"artifact malformed response", "Error: Failed to CreateArtifact: Unexpected token '<', <!DOCTYPE is not valid JSON", model.CategoryNetworkFailure},
		{"artifact leaf certificate", "Create Artifact Container failed: unable to verify the first certificate; UNABLE_TO_VERIFY_LEAF_SIGNATURE", model.CategoryNetworkFailure},
		{"artifact service 503", "Status Code: 503\nStatus Message: Service Unavailable\nUnable to get ContainersItems from pipelines.actions.githubusercontent.com", model.CategoryNetworkFailure},
		{"artifact bad request", "Unexpected response. Unable to upload chunk\nStatus Code: 400\nStatus Message: Bad Request", model.CategoryCodeFailure},
		{"socket disconnected", "Client network socket disconnected before secure TLS connection was established", model.CategoryNetworkFailure},
		{"connection refused", "connect ECONNREFUSED 20.253.95.3:443", model.CategoryNetworkFailure},
		{"unknown no logs", "Run actions/setup-node@v4\nThe process completed with exit code 1", model.CategoryUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New("test").Analyze(model.AnalysisInput{Log: tt.log}, Context{})
			if r.Category != tt.want {
				t.Fatalf("category=%s want=%s evidence=%+v", r.Category, tt.want, r.Evidence)
			}
		})
	}
}

func TestHoldoutRegressionCases(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want model.Category
	}{
		{"sumdb 500", `reading https://sum.golang.org/lookup/mod: 500 Internal Server Error`, model.CategoryDependencyRegistry},
		{"git sideband disconnect", "fetch-pack: unexpected disconnect while reading sideband packet\nfatal: early EOF", model.CategoryNetworkFailure},
		{"test timeout", "panic: test timed out after 45m0s\n--- FAIL: TestTerminalSignal", model.CategoryTestFlake},
		{"bad oauth token", "rpc error: code = Unauthenticated desc = oauth: bad access token", model.CategoryCodeFailure},
		{"x509 expected test", "expected result: SUCCESS actual result: x509: certificate signed by unknown authority", model.CategoryCodeFailure},
		{"tls policy", "handshake failed: remote error: tls: insufficient security level", model.CategoryCodeFailure},
		{"repo missing", "remote: Repository not found.\nfatal: repository not found", model.CategoryCodeFailure},
		{"local socket timeout test", "Post https://127.0.0.1:1234: context deadline exceeded (Client.Timeout exceeded while awaiting headers) (likely due to hang)", model.CategoryTestFlake},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New("test").Analyze(model.AnalysisInput{Log: tt.log}, Context{})
			if r.Category != tt.want {
				t.Fatalf("category=%s want=%s evidence=%+v", r.Category, tt.want, r.Evidence)
			}
		})
	}
}

func TestDotNetAndContainerRegressionCases(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want model.Category
	}{
		{"nuget 429", "error NU1301: Unable to load the service index for source https://api.nuget.org/v3/index.json. Response status code does not indicate success: 429 (Too Many Requests).", model.CategoryDependencyRegistry},
		{"nuget package missing", "error NU1101: Unable to find package Acme.Missing. No packages exist with this id in source(s): nuget.org", model.CategoryCodeFailure},
		{"nuget refused", "error NU1301: Unable to load the service index. No connection could be made because the target machine actively refused it.", model.CategoryNetworkFailure},
		{"nuget bad source", "error NU5000: Invalid package source path: /missing", model.CategoryCodeFailure},
		{"nuget signature", "error NU3028: Package signature validation failed. UntrustedRoot: self-signed certificate", model.CategoryCodeFailure},
		{"container pull eof", "Attempting next endpoint for pull after error: unexpected EOF", model.CategoryDependencyRegistry},
		{"container auth", "pull failed: no basic auth credentials", model.CategoryCodeFailure},
		{"container manifest capability", "docker exporter does not currently support exporting manifest lists", model.CategoryCodeFailure},
		{"container internal panic", "panic: runtime error: invalid memory address or nil pointer dereference", model.CategoryCodeFailure},
		{"explicit flaky test", "This test is flaky and succeeds on rerun.", model.CategoryTestFlake},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New("test").Analyze(model.AnalysisInput{Log: tt.log}, Context{})
			if r.Category != tt.want {
				t.Fatalf("category=%s want=%s evidence=%+v", r.Category, tt.want, r.Evidence)
			}
		})
	}
}

func TestComposerAndBazelRegressionCases(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want model.Category
	}{
		{"composer partial transfer", "curl error 18: Transferred a partial file", model.CategoryNetworkFailure},
		{"java pkix tls", "SSLHandshakeException: PKIX path building failed: unable to find valid certification path to requested target", model.CategoryNetworkFailure},
		{"composer conflict", "Your requirements could not be resolved to an installable set of packages. Root composer.json requires pkg dev-main but it does not match the constraint.", model.CategoryCodeFailure},
		{"composer extension", "Root composer.json requires PHP extension ext-zip * but it is missing from your system.", model.CategoryCodeFailure},
		{"composer security", "package was not loaded, because it is affected by security advisories. Set block-insecure to false.", model.CategoryCodeFailure},
		{"composer repository priority", "packages from path repo have higher repository priority and the lower priority repo is not installable", model.CategoryCodeFailure},
		{"bazel cache reset", "Remote Cache: Error uploading results: UNAVAILABLE: io exception; Connection reset", model.CategoryNetworkFailure},
		{"bazel cache channel", "Remote cache upload failed: java.nio.channels.ClosedChannelException", model.CategoryCacheFailure},
		{"bazel repo undefined", "Repository 'utils' is not defined", model.CategoryCodeFailure},
		{"bazel checksum", "Cannot fetch a file without a checksum in ENFORCE mode. Use --lockfile_mode=update", model.CategoryCodeFailure},
		{"bazel jdk", "java.lang.NoSuchFieldError: Class com.sun.tools.javac.code.TypeTag does not have member field UNKNOWN", model.CategoryCodeFailure},
		{"bazel pipe deadlock", "Waiting for build events upload: BinaryFormatFileTransport; execution_log_compact_file and build_event_binary_file both point to named pipes", model.CategoryCodeFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New("test").Analyze(model.AnalysisInput{Log: tt.log}, Context{})
			if r.Category != tt.want {
				t.Fatalf("category=%s want=%s evidence=%+v", r.Category, tt.want, r.Evidence)
			}
		})
	}
}

func TestTerraformRegressionCases(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want model.Category
	}{
		{"registry timeout", `Failed to query available provider packages: registry.terraform.io: Client.Timeout exceeded while awaiting headers`, model.CategoryDependencyRegistry},
		{"registry dns", `registry.terraform.io: dial tcp: lookup registry.terraform.io: no such host`, model.CategoryNetworkFailure},
		{"invalid registry metadata", `registry response includes invalid version string "v2.5.3-alpha1"`, model.CategoryDependencyRegistry},
		{"locked provider mismatch", `locked provider registry.terraform.io/hashicorp/aws 4.60.0 does not match configured version constraint 5.77.0`, model.CategoryCodeFailure},
		{"provider source missing", `provider registry registry.terraform.io does not have a provider named registry.terraform.io/hashicorp/foo`, model.CategoryCodeFailure},
		{"state lock contention", `Error acquiring the state lock: ConditionalCheckFailedException: The conditional request failed`, model.CategoryConcurrencyConflict},
		{"backend not implemented", `Error acquiring the state lock: api error NotImplemented: A header you provided implies functionality that is not implemented`, model.CategoryCodeFailure},
		{"shared cache conflict", `Failed to install provider from shared cache: failed to create directory: Cannot create a file when that file already exists`, model.CategoryCodeFailure},
		{"filesystem mirror path", `cannot search $HOME/.terraform.d/providers: lstat $HOME/.terraform.d/providers: no such file or directory`, model.CategoryCodeFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New("test").Analyze(model.AnalysisInput{Log: tt.log}, Context{})
			if r.Category != tt.want {
				t.Fatalf("category=%s want=%s evidence=%+v", r.Category, tt.want, r.Evidence)
			}
		})
	}
}

func TestCloudAndNativeBuildRegressionCases(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want model.Category
	}{
		{"aws missing oidc permission", "Credentials could not be loaded, please check your action inputs: Could not load credentials from any providers\npermissions:\n  contents: read", model.CategoryCodeFailure},
		{"aws invalid token", "InvalidClientTokenId: The security token included in the request is invalid", model.CategoryCodeFailure},
		{"aws assume role denied", "not authorized to perform: sts:AssumeRole on resource", model.CategoryCodeFailure},
		{"aws endpoint dns", "getaddrinfo ENOTFOUND sts.cn-north-1.amazonaws.com", model.CategoryNetworkFailure},
		{"gcp invalid jwt", "invalid_grant: Invalid JWT Signature", model.CategoryCodeFailure},
		{"gcp dns", "getaddrinfo ENOTFOUND oauth2.googleapis.com", model.CategoryNetworkFailure},
		{"vcpkg hash", "vcpkg downloads\\node.7z: error: download had an unexpected hash\nExpected hash: abc\nActual hash: def", model.CategoryCodeFailure},
		{"vcpkg 404", "vcpkg_download_distfile.cmake: failed: status code 404", model.CategoryCodeFailure},
		{"cmake compiler", "No CMAKE_CXX_COMPILER could be found", model.CategoryCodeFailure},
		{"vcpkg baseline", "Cannot resolve a minimum constraint for dependency missing; dependency was not found in the baseline", model.CategoryCodeFailure},
		{"vcpkg challenge", "vcpkg archive download returned an Anubis bot protection challenge page instead of the requested archive", model.CategoryDependencyRegistry},
		{"generic aws credentials remains unknown", "Credentials could not be loaded, please check your action inputs: Could not load credentials from any providers", model.CategoryUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New("test").Analyze(model.AnalysisInput{Log: tt.log}, Context{})
			if r.Category != tt.want {
				t.Fatalf("category=%s want=%s evidence=%+v", r.Category, tt.want, r.Evidence)
			}
		})
	}
}

func TestRubyBundlerRegressionCases(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want model.Category
	}{
		{"rubygems no route", `Bundler::HTTPError Could not fetch specs from https://rubygems.org/ due to underlying error <Errno::EHOSTUNREACH: Failed to open TCP connection to rubygems.org:443 (No route to host)>`, model.CategoryNetworkFailure},
		{"rubygems unexpected eof", `Could not fetch specs from https://rubygems.org/ due to underlying error <SSL_connect returned=1 state=error: unexpected eof while reading>`, model.CategoryNetworkFailure},
		{"bundler dependency conflict", `Bundler could not find compatible versions for gem "ruby": Could not find gem 'ruby (>= 2.0)' in any of the sources`, model.CategoryCodeFailure},
		{"ruby version mismatch", `Your Ruby version is 2.1.7, but your Gemfile specified 2.3.0`, model.CategoryCodeFailure},
		{"locked gem missing", `Your bundle is locked to activesupport (4.2.7.1), but that version could not be found in any of the sources listed in your Gemfile`, model.CategoryCodeFailure},
		{"permission", `Bundler::PermissionError: There was an error while trying to write to /usr/gem/cache`, model.CategoryCodeFailure},
		{"native extension", `Gem::Ext::BuildError: ERROR: Failed to build gem native extension.`, model.CategoryCodeFailure},
		{"activated conflict", `You have already activated set 1.0.1, but your Gemfile requires set 1.0.3. (Gem::LoadError)`, model.CategoryCodeFailure},
		{"rubygems 503", `Bundler::HTTPError: Could not fetch specs from https://rubygems.org/ Net::HTTPFatalError: 503 Service Unavailable`, model.CategoryDependencyRegistry},
		{"rubygems checksum", `Bundler::SecurityError: The checksum for rack-3.0.8.gem does not match the checksum provided by the server`, model.CategoryCacheFailure},
		{"gemfile missing", `Could not locate Gemfile or .bundle/ directory`, model.CategoryCodeFailure},
		{"internal no method", `Bundler::FriendlyErrors: undefined method 'full_name' for nil:NilClass`, model.CategoryToolchainFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New("test").Analyze(model.AnalysisInput{Log: tt.log}, Context{})
			if r.Category != tt.want {
				t.Fatalf("category=%s want=%s evidence=%+v", r.Category, tt.want, r.Evidence)
			}
		})
	}
}

func TestToolchainInternalFailure(t *testing.T) {
	r := New("test").Analyze(model.AnalysisInput{Log: "ERROR: Fatal Internal error [id=1]. Please report as a bug."}, Context{})
	if r.Category != model.CategoryToolchainFailure {
		t.Fatalf("category=%s want=%s evidence=%+v", r.Category, model.CategoryToolchainFailure, r.Evidence)
	}
	if r.Confidence == model.ConfidenceLikelyCode {
		t.Fatalf("internal tool failure must not blame code: %+v", r)
	}
}

func TestBrowserAndGitLFSRegressionCases(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want model.Category
	}{
		{"playwright no xserver", `Looks like you launched a headed browser without having a XServer running. use 'xvfb-run'`, model.CategoryCodeFailure},
		{"playwright timeout", `Error: page.goto: Test timeout of 60000ms exceeded.`, model.CategoryTestFlake},
		{"playwright target closed", `Target page, context or browser has been closed`, model.CategoryTestFlake},
		{"worker killed", `worker-0 process did not exit within 2000ms after stop, force-killed it`, model.CategoryTestFlake},
		{"cypress tab", `We detected that the electron tab running Cypress tests closed unexpectedly.`, model.CategoryTestFlake},
		{"cypress permission", `EACCES: permission denied, open '/home/.cache/Cypress/15/binary_state.json'`, model.CategoryCodeFailure},
		{"sigill", `Command was killed with SIGILL (Invalid machine instruction)`, model.CategoryCodeFailure},
		{"lfs proxy", `batch response: Proxy authentication required`, model.CategoryCodeFailure},
		{"lfs protocol", `batch request: missing protocol: "https:owner/repo.git/info/lfs"`, model.CategoryCodeFailure},
		{"lfs cert", `Error reading client cert file "/none/cert.pem": open /none/cert.pem: no such file or directory`, model.CategoryCodeFailure},
		{"lfs eof", `Post "https://host/repo.git/info/lfs/locks/verify": EOF`, model.CategoryNetworkFailure},
		{"lfs ssh", `could not get connection for batch request: pure SSH connection unavailable (#0)`, model.CategoryNetworkFailure},
		{"lfs auth", `Authentication required: Authorization error: https://host/repo.git/info/lfs/objects/batch`, model.CategoryCodeFailure},
		{"lfs locks", `Authentication required: You must have push access to verify locks`, model.CategoryCodeFailure},
		{"lfs repo", `Err: https://packagecloud.io/github/git-lfs/ubuntu resolute Release 404 Not Found`, model.CategoryCodeFailure},
		{"repo signature", `OpenPGP signature verification failed: https://packagecloud.io/github/git-lfs/debian trixie InRelease Policy rejected signature because SHA1 is not considered secure`, model.CategoryDependencyRegistry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New("test").Analyze(model.AnalysisInput{Log: tt.log}, Context{})
			if r.Category != tt.want {
				t.Fatalf("category=%s want=%s evidence=%+v", r.Category, tt.want, r.Evidence)
			}
		})
	}
}

func TestToolchainAttributionIsDistinct(t *testing.T) {
	r := New("test").Analyze(model.AnalysisInput{Log: "ERROR: Fatal Internal error [id=1]. Please report as a bug."}, Context{})
	if r.Attribution != model.AttributionToolchain {
		t.Fatalf("attribution=%s confidence=%s score=%d", r.Attribution, r.Confidence, r.Score)
	}
}

func TestChangedDependencyCreatesCompetingEvidence(t *testing.T) {
	r := New("test").Analyze(model.AnalysisInput{
		Repository:          "acme/app",
		Log:                 "npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/react failed",
		ChangeInfoAvailable: true,
		DependencyChanged:   true,
		WorkflowChanged:     true,
	}, Context{})
	if r.NegativeScore > -30 {
		t.Fatalf("negative score=%d evidence=%+v", r.NegativeScore, r.Evidence)
	}
	if r.Attribution != model.AttributionMixed {
		t.Fatalf("attribution=%s score=%d +%d %d", r.Attribution, r.Score, r.PositiveScore, r.NegativeScore)
	}
}

func TestScoreBreakdownAndCompetingSignals(t *testing.T) {
	log := "npm ERR! code ECONNRESET\nnpm ERR! network request to https://registry.npmjs.org/a failed\nerror TS2322: Type 'string' is not assignable to type 'number'"
	r := New("test").Analyze(model.AnalysisInput{Log: log}, Context{})
	if r.Attribution != model.AttributionMixed {
		t.Fatalf("attribution=%s evidence=%+v", r.Attribution, r.Evidence)
	}
	if !r.CompetingSignals {
		t.Fatal("expected competing signals")
	}
	total := 0
	for _, e := range r.Evidence {
		total += e.Weight
	}
	if total != r.RawScore {
		t.Fatalf("evidence sum=%d raw=%d", total, r.RawScore)
	}
	if r.Score < 0 || r.Score > 100 {
		t.Fatalf("score=%d", r.Score)
	}
}

func TestCompareEnvironmentIncludesArchitectureActionsAndContainers(t *testing.T) {
	previous := model.Environment{RunnerArch: "X64", ActionVersions: []string{"actions/checkout@v4"}, ContainerRefs: []string{"postgres:16"}}
	current := model.Environment{RunnerArch: "ARM64", ActionVersions: []string{"actions/checkout@v5"}, ContainerRefs: []string{"postgres:17"}}
	changes := CompareEnvironment(previous, current)
	joined := strings.Join(changes, "\n")
	for _, expected := range []string{"runner architecture", "actions:", "containers:"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in %v", expected, changes)
		}
	}
}

func TestFingerprintUsesHMACKey(t *testing.T) {
	in := model.AnalysisInput{TenantID: "alpha", Repository: "acme/api", Log: "npm ERR! code ECONNRESET"}
	a := New("key-a").Analyze(in, Context{})
	b := New("key-b").Analyze(in, Context{})
	again := New("key-a").Analyze(in, Context{})
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("different HMAC keys produced the same shared fingerprint")
	}
	if a.Fingerprint != again.Fingerprint {
		t.Fatal("same HMAC key did not produce a stable fingerprint")
	}
	in.Repository = "acme/web"
	otherRepo := New("key-a").Analyze(in, Context{})
	if a.Fingerprint != otherRepo.Fingerprint {
		t.Fatal("shared fingerprint changed across repositories")
	}
	if a.PrivateFingerprint == otherRepo.PrivateFingerprint {
		t.Fatal("private fingerprint did not include repository scope")
	}
}

func TestRedactorCustomAndHighEntropy(t *testing.T) {
	r := NewRedactorWithPatterns([]string{`INTERNAL-[A-Z0-9]{12}`}, true)
	input := "custom=INTERNAL-ABCDEF123456 access_token=Zp9kL2mN7qR4sT8vW1xY5aB6cD0eF3gH9jK2lM4nP7qR8sT1"
	got := r.Redact(input)
	if strings.Contains(got, "INTERNAL-ABCDEF123456") || strings.Contains(got, "Zp9kL2mN7qR4") {
		t.Fatalf("secret was not redacted: %s", got)
	}
}

func TestRedactorDoesNotEraseOrdinaryIdentifier(t *testing.T) {
	r := NewRedactorWithPatterns(nil, true)
	input := "package github.com/example/ordinary-project-name-with-many-characters"
	if got := r.Redact(input); got != input {
		t.Fatalf("ordinary text changed: %s", got)
	}
}
