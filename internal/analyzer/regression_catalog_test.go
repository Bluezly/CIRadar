package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestBuiltinRuleCountAndUniqueness(t *testing.T) {
	rules := BuiltinRules()
	if len(rules) != 1223 {
		t.Fatalf("builtin rule count=%d want=1223", len(rules))
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if _, ok := seen[rule.ID]; ok {
			t.Fatalf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
}

func TestRepresentativeDiagnoses(t *testing.T) {
	tests := []struct {
		name        string
		log         string
		category    model.Category
		provider    string
		errorFamily string
	}{
		{name: "openclaw stale release dependency", log: `Error: plugin-npm-release-check rejected stale required release dependencies:\n- @openclaw/codex@2026.7.2: @openai/codex must match npm latest for release; found "0.146.1", latest is "0.147.0".`, category: model.CategoryCodeFailure, provider: "OpenClaw release check", errorFamily: "stale-release-dependency"},
		{name: "hosted runner acquisition", log: "The job was not acquired by Runner because hosted capacity is temporarily unavailable", category: model.CategoryRunnerFailure, provider: "hosted CI runner", errorFamily: "hosted-runner-acquisition-failed"},
		{name: "python syntax", log: "File \"agent/agent_init.py\", line 2047\n    compression_micro_compact_defrag_tokens = max(\n                                               ^\nSyntaxError: '(' was never closed", category: model.CategoryCodeFailure, provider: "Python", errorFamily: "syntax-unclosed-delimiter"},
		{name: "go assertion", log: "--- FAIL: TestSetBs_SingleDb (0.01s)\nError Trace: localstorage_test.go:193\nError: Not equal:\nexpected: 3\nactual  : 2\nTest: TestSetBs_SingleDb", category: model.CategoryCodeFailure, provider: "Go test/testify", errorFamily: "assertion-expected-actual"},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: tt.log}, Context{})
			if r.Category != tt.category || r.Provider != tt.provider || r.ErrorFamily != tt.errorFamily {
				t.Fatalf("got category=%s provider=%q family=%q rules=%v", r.Category, r.Provider, r.ErrorFamily, r.MatchedRules)
			}
		})
	}
}

func TestCrossProjectRegressionCases(t *testing.T) {
	tests := []struct {
		name        string
		repository  string
		log         string
		category    model.Category
		provider    string
		errorFamily string
	}{
		{name: "actions setup-node missing node headers", repository: "actions/setup-node", log: "gyp ERR! build error\n../src/addon.cc:1:10: fatal error: node.h: No such file or directory\ncompilation terminated.", category: model.CategoryToolchainFailure, provider: "node-gyp", errorFamily: "node-headers-missing"},
		{name: "node-gyp missing Visual Studio", repository: "nodejs/node-gyp", log: "gyp ERR! find VS could not use PowerShell to find Visual Studio 2017 or newer\ngyp ERR! find VS Could not find any Visual Studio installation to use", category: model.CategoryToolchainFailure, provider: "node-gyp", errorFamily: "native-toolchain-unavailable"},
		{name: "supabase postgres scram", repository: "supabase/cli", log: "database connection failed: SASL authentication failed: invalid SCRAM server-final-message", category: model.CategoryCodeFailure, provider: "PostgreSQL", errorFamily: "scram-authentication-failure"},
		{name: "postgres password authentication", repository: "postgres/postgres", log: `FATAL: password authentication failed for user "ci_runner"`, category: model.CategoryCodeFailure, provider: "PostgreSQL", errorFamily: "scram-authentication-failure"},
		{name: "gradle invalid heap", repository: "gradle/gradle-build-action", log: "Invalid maximum heap size: -Xmx999999g\nError: Could not create the Java Virtual Machine.\nError: A fatal exception has occurred. Program will exit.", category: model.CategoryToolchainFailure, provider: "JVM", errorFamily: "invalid-jvm-option"},
		{name: "gradle unsupported vm option", repository: "gradle/gradle", log: "Unrecognized VM option 'UseConcMarkSweepGC'\nError: Could not create the Java Virtual Machine.", category: model.CategoryToolchainFailure, provider: "JVM", errorFamily: "invalid-jvm-option"},
		{name: "audio whisper cache bad request", repository: "bnosac/audio.whisper", log: "Failed to restore cache: Cache service responded with 400 Bad Request", category: model.CategoryCacheFailure, provider: "GitHub Actions Cache", errorFamily: "cache-service-request-rejected"},
		{name: "github cache service unavailable", repository: "actions/cache", log: "Failed to save cache: Cache service responded with 503 Service Unavailable", category: model.CategoryProviderIncident, provider: "GitHub Actions Cache", errorFamily: "cache-service-unavailable"},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: tt.repository, Log: tt.log}, Context{})
			if r.Category != tt.category || r.Provider != tt.provider || r.ErrorFamily != tt.errorFamily {
				t.Fatalf("got category=%s provider=%q family=%q rules=%v", r.Category, r.Provider, r.ErrorFamily, r.MatchedRules)
			}
		})
	}
}

func TestRealWorldFailureSignatures(t *testing.T) {
	tests := []struct {
		name        string
		repository  string
		log         string
		category    model.Category
		provider    string
		errorFamily string
	}{
		{name: "staticcheck deprecated api", repository: "Bluezly/CIRadar", log: "Error: internal/sso/sso.go:728:7: curve.IsOnCurve has been deprecated since Go 1.21: this is a low-level unsafe API. For ECDH, use the crypto/ecdh package. (SA1019)", category: model.CategoryCodeFailure, provider: "Staticcheck", errorFamily: "deprecated-api"},
		{name: "staticcheck generic diagnostic", repository: "golang/example", log: "pkg/cache/cache.go:44:2: this value of err is never used (SA4006)", category: model.CategoryCodeFailure, provider: "Staticcheck", errorFamily: "static-analysis-failure"},
		{name: "pnpm outdated lockfile", repository: "pnpm/pnpm", log: "ERR_PNPM_OUTDATED_LOCKFILE Cannot install with frozen-lockfile because pnpm-lock.yaml is not up to date with package.json", category: model.CategoryCodeFailure, provider: "pnpm", errorFamily: "outdated-lockfile"},
		{name: "corepack signing key", repository: "pnpm/pnpm", log: "Error: Cannot find matching keyid: {\"signatures\":[],\"keys\":[]}", category: model.CategoryToolchainFailure, provider: "Corepack", errorFamily: "signature-key-mismatch"},
		{name: "npm peer conflict", repository: "npm/cli", log: "npm ERR! code ERESOLVE\nnpm ERR! ERESOLVE unable to resolve dependency tree\nnpm ERR! Could not resolve dependency: peer react@18 from pkg@1.0.0", category: model.CategoryCodeFailure, provider: "npm", errorFamily: "peer-dependency-conflict"},
		{name: "node require esm", repository: "nestjs/nest", log: "Error [ERR_REQUIRE_ESM]: require() of ES Module /app/node_modules/brace-expansion/index.js from /app/node_modules/minimatch/index.js not supported.", category: model.CategoryCodeFailure, provider: "Node.js", errorFamily: "commonjs-esm-mismatch"},
		{name: "git dubious ownership", repository: "actions/runner-images", log: "fatal: detected dubious ownership in repository at '/__w/project/project'", category: model.CategoryCodeFailure, provider: "Git", errorFamily: "dubious-ownership"},
		{name: "git non fast forward", repository: "example/repo", log: "! [rejected] main -> main (non-fast-forward)\nerror: failed to push some refs to 'https://github.com/example/repo.git'", category: model.CategoryConcurrencyConflict, provider: "Git", errorFamily: "non-fast-forward"},
		{name: "github token permission", repository: "actions/configure-pages", log: "RequestError [HttpError]: Resource not accessible by integration\nstatus: 403", category: model.CategoryCodeFailure, provider: "GitHub Actions", errorFamily: "workflow-token-permission"},
		{name: "github oidc permission", repository: "example/deploy", log: "Error: Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable", category: model.CategoryCodeFailure, provider: "GitHub Actions OIDC", errorFamily: "id-token-permission-missing"},
		{name: "github artifact quota", repository: "actions/upload-artifact", log: "Error: Failed to CreateArtifact: Artifact storage quota has been hit. Unable to upload any new artifacts.", category: model.CategoryResourceExhaustion, provider: "GitHub Actions Artifacts", errorFamily: "storage-quota-exceeded"},
		{name: "github cache reserve", repository: "gradle/actions", log: "ReserveCacheError: Unable to reserve cache with key gradle-home-linux-build", category: model.CategoryCacheFailure, provider: "GitHub Actions Cache", errorFamily: "cache-reservation-failed"},
		{name: "gradle class version", repository: "GradleUp/shadow", log: "General error during semantic analysis: Unsupported class file major version 65", category: model.CategoryToolchainFailure, provider: "Gradle/JVM", errorFamily: "unsupported-class-version"},
		{name: "maven invalid target", repository: "georgewfraser/java-language-server", log: "[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.8.0:compile: Fatal error compiling: error: invalid target release: 18", category: model.CategoryToolchainFailure, provider: "Maven/Javac", errorFamily: "invalid-target-release"},
		{name: "cargo msrv", repository: "rust-lang/cargo", log: "error: rustc 1.72.0 is not supported by the following packages:\n  clap@4.5.4 requires rustc 1.74", category: model.CategoryToolchainFailure, provider: "Cargo/Rust", errorFamily: "rust-version-too-old"},
		{name: "rust linker missing", repository: "rust-lang/cargo", log: "error: linker `cc` not found\n  = note: No such file or directory (os error 2)", category: model.CategoryToolchainFailure, provider: "Rust", errorFamily: "native-linker-missing"},
		{name: "go missing sum", repository: "golang/go", log: "missing go.sum entry for module providing package golang.org/x/text/unicode/bidi; to add: go get golang.org/x/net/idna", category: model.CategoryCodeFailure, provider: "Go modules", errorFamily: "missing-go-sum-entry"},
		{name: "go mod readonly", repository: "golang/go", log: "go: updates to go.mod needed; disabled by -mod=readonly", category: model.CategoryCodeFailure, provider: "Go modules", errorFamily: "module-files-out-of-date"},
		{name: "go toolchain too old", repository: "example/go-project", log: "go: go.mod requires go >= 1.26.0 (running go 1.25.4; GOTOOLCHAIN=local)", category: model.CategoryToolchainFailure, provider: "Go toolchain", errorFamily: "go-version-too-old"},
		{name: "kubernetes webhook timeout", repository: "kubernetes/kubernetes", log: "Failed calling webhook, failing open webhook.stork.libopenstorage.org: failed calling webhook \"webhook.stork.libopenstorage.org\": Post \"https://stork-service.kube-system.svc:443/mutate?timeout=10s\": context deadline exceeded", category: model.CategoryNetworkFailure, provider: "Kubernetes admission webhook", errorFamily: "webhook-timeout"},
		{name: "nuget service index", repository: "openai/codex-universal", log: "/workspace/app.csproj : error NU1301: Unable to load the service index for source https://api.nuget.org/v3/index.json.", category: model.CategoryDependencyRegistry, provider: "NuGet", errorFamily: "service-index-unavailable"},
		{name: "terraform readonly lockfile", repository: "hashicorp/terraform", log: "Error while writing new dependency lock information to .terraform.lock.hcl:\ncannot create temporary file to update .terraform.lock.hcl: open .terraform.lock.hcl217706229: read-only file system.", category: model.CategoryCodeFailure, provider: "Terraform", errorFamily: "lockfile-read-only"},
		{name: "yarn frozen lockfile", repository: "yarnpkg/yarn", log: "error Your lockfile needs to be updated, but yarn was run with --frozen-lockfile.", category: model.CategoryCodeFailure, provider: "Yarn", errorFamily: "outdated-lockfile"},
		{name: "poetry lock mismatch", repository: "python-poetry/poetry", log: "Warning: poetry.lock is not consistent with pyproject.toml. You may be getting improper dependencies.", category: model.CategoryCodeFailure, provider: "Poetry", errorFamily: "lockfile-out-of-sync"},
		{name: "glibc version mismatch", repository: "verus-lang/verus", log: "/lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by ./verus)", category: model.CategoryToolchainFailure, provider: "glibc", errorFamily: "glibc-version-mismatch"},
		{name: "glibcxx version mismatch", repository: "pytorch/pytorch", log: "/usr/lib/x86_64-linux-gnu/libstdc++.so.6: version `GLIBCXX_3.4.30' not found (required by torch/lib/libtorch_python.so)", category: model.CategoryToolchainFailure, provider: "libstdc++", errorFamily: "libstdcxx-version-mismatch"},
		{name: "musl loader mismatch", repository: "openai/codex", log: "exec ./codex-x86_64-unknown-linux-musl: ENOENT: ld-musl-x86_64.so.1: No such file or directory", category: model.CategoryToolchainFailure, provider: "musl libc", errorFamily: "dynamic-loader-mismatch"},
		{name: "npm bad engine", repository: "release-it/release-it", log: "npm error code EBADENGINE\nnpm error engine Unsupported engine\nnpm error engine Not compatible with your version of node/npm: release-it@17.10.0", category: model.CategoryToolchainFailure, provider: "npm", errorFamily: "node-engine-incompatible"},
		{name: "yarn bad engine", repository: "yarnpkg/yarn", log: "error @yarnpkg/parsers@3.0.0-rc.49: The engine \"node\" is incompatible with this module. Expected version \" >=18.12.0\". Got \"16.15.1\"", category: model.CategoryToolchainFailure, provider: "Yarn", errorFamily: "node-engine-incompatible"},
		{name: "npm bad platform", repository: "npm/cli", log: "npm error code EBADPLATFORM\nnpm error notsup Unsupported platform for sass-embedded-all-unknown@1.93.3", category: model.CategoryToolchainFailure, provider: "npm", errorFamily: "unsupported-platform"},
		{name: "npm ci lock mismatch", repository: "nextcloud/maps", log: "npm error code EUSAGE\nnpm error `npm ci` can only install packages when your package.json and package-lock.json or npm-shrinkwrap.json are in sync.", category: model.CategoryCodeFailure, provider: "npm", errorFamily: "lockfile-out-of-sync"},
		{name: "node package path export", repository: "nodejs/node", log: "Error [ERR_PACKAGE_PATH_NOT_EXPORTED]: Package subpath './dist/v1.js' is not defined by \"exports\" in /app/node_modules/uuid/package.json", category: model.CategoryCodeFailure, provider: "Node.js", errorFamily: "package-subpath-not-exported"},
		{name: "typescript missing type definition", repository: "microsoft/TypeScript", log: "error TS2688: Cannot find type definition file for 'vite/client'.", category: model.CategoryCodeFailure, provider: "TypeScript", errorFamily: "missing-type-definition"},
		{name: "numpy abi mismatch", repository: "numpy/numpy", log: "ValueError: numpy.dtype size changed, may indicate binary incompatibility. Expected 96 from C header, got 88 from PyObject", category: model.CategoryToolchainFailure, provider: "Python/NumPy", errorFamily: "binary-abi-mismatch"},
		{name: "python shared library missing", repository: "opencv/opencv-python", log: "ImportError: libGL.so.1: cannot open shared object file: No such file or directory", category: model.CategoryToolchainFailure, provider: "Python native runtime", errorFamily: "shared-library-missing"},
		{name: "psycopg pg config missing", repository: "psycopg/psycopg2", log: "Error: pg_config executable not found.\npg_config is required to build psycopg2 from source.", category: model.CategoryToolchainFailure, provider: "psycopg2", errorFamily: "pg-config-missing"},
		{name: "jvm pkix repository trust", repository: "apache/maven", log: "sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target", category: model.CategoryNetworkFailure, provider: "JVM dependency repository", errorFamily: "certificate-trust-failure"},
		{name: "gradle cannot determine java version", repository: "gradle/gradle", log: "FAILURE: Build failed with an exception.\nCould not determine java version from '17.0.7'.", category: model.CategoryToolchainFailure, provider: "Gradle/JVM", errorFamily: "gradle-java-version-incompatible"},
		{name: "java main class missing", repository: "example/java-app", log: "Error: Could not find or load main class Main\nCaused by: java.lang.ClassNotFoundException: Main", category: model.CategoryCodeFailure, provider: "Java", errorFamily: "main-class-not-found"},
		{name: "docker exec format", repository: "docker/for-win", log: "exec /usr/local/bin/docker-entrypoint.sh: exec format error", category: model.CategoryToolchainFailure, provider: "Docker", errorFamily: "binary-architecture-mismatch"},
		{name: "docker registry x509", repository: "golang/go", log: "error pulling image configuration: download failed after attempts=6: x509: certificate signed by unknown authority", category: model.CategoryNetworkFailure, provider: "Docker registry", errorFamily: "certificate-trust-failure"},
		{name: "kubernetes cni sandbox", repository: "kubernetes/kubernetes", log: "Failed to create pod sandbox: rpc error: code = Unknown desc = failed to set up sandbox container network for pod app: networkPlugin cni failed to set up pod app_default network: dial tcp 10.233.0.1:443: connect: connection refused", category: model.CategoryNetworkFailure, provider: "Kubernetes CNI", errorFamily: "cni-setup-failure"},
		{name: "rust openssl missing", repository: "sfackler/rust-openssl", log: "Could not find directory of OpenSSL installation, and this `-sys` crate cannot proceed without this knowledge.\nopenssl-sys = 0.9.103", category: model.CategoryToolchainFailure, provider: "Rust openssl-sys", errorFamily: "openssl-development-files-missing"},
		{name: "github checkout credentials", repository: "actions/checkout", log: "Error: fatal: could not read Username for 'https://github.com': terminal prompts disabled", category: model.CategoryCodeFailure, provider: "GitHub Checkout", errorFamily: "git-credentials-missing"},
		{name: "github artifact path missing", repository: "actions/upload-artifact", log: "Error: No files were found with the provided path: /__w/_temp/release-assets. No artifacts will be uploaded.", category: model.CategoryCodeFailure, provider: "GitHub Actions Artifacts", errorFamily: "artifact-path-empty"},
	}
	a := New("test")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: tt.repository, Log: tt.log}, Context{})
			if r.Category != tt.category || r.Provider != tt.provider || r.ErrorFamily != tt.errorFamily {
				t.Fatalf("got category=%s provider=%q family=%q rules=%v", r.Category, r.Provider, r.ErrorFamily, r.MatchedRules)
			}
		})
	}
}

func TestDiagnosticMemoryIsTenantIsolatedAndAnalyzeRemainsStateless(t *testing.T) {
	a := New("test")
	log := "opaque proprietary failure token ZXQ-7781 with no public signature"
	seed := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if seed.Category != model.CategoryUnknown {
		t.Fatalf("seed category=%s", seed.Category)
	}
	a.RememberFeedback(seed, model.DiagnosisFeedback{TenantID: "alpha", AnalysisID: seed.ID, Verdict: "incorrect", ActualCategory: model.CategoryCodeFailure, ActualCause: model.AttributionCode, ActualProvider: "private-build", ActualErrorFamily: "tenant-confirmed"})
	stateless := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if stateless.Category != model.CategoryUnknown {
		t.Fatalf("Analyze must remain memory-free for benchmark determinism: %s", stateless.Category)
	}
	recalled := a.AnalyzeWithMemory(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if recalled.Category != model.CategoryCodeFailure || recalled.Provider != "private-build" || recalled.ErrorFamily != "tenant-confirmed" {
		t.Fatalf("recalled=%+v", recalled)
	}
	if !strings.Contains(recalled.DecisionReason, "tenant-isolated") {
		t.Fatalf("decision reason=%q", recalled.DecisionReason)
	}
	other := a.AnalyzeWithMemory(model.AnalysisInput{TenantID: "beta", Log: log}, Context{})
	if other.Category != model.CategoryUnknown {
		t.Fatalf("memory leaked across tenants: %+v", other)
	}
}

func TestDiagnosticMemoryExpires(t *testing.T) {
	a := New("test")
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	a.memory.now = func() time.Time { return now }
	a.memory.ttl = time.Minute
	log := "opaque tenant failure F00-BAR"
	seed := a.Analyze(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	a.RememberFeedback(seed, model.DiagnosisFeedback{Verdict: "incorrect", ActualCategory: model.CategoryCodeFailure, ActualCause: model.AttributionCode, ActualProvider: "internal", ActualErrorFamily: "known"})
	now = now.Add(2 * time.Minute)
	r := a.AnalyzeWithMemory(model.AnalysisInput{TenantID: "alpha", Log: log}, Context{})
	if r.Category != model.CategoryUnknown {
		t.Fatalf("expired memory still applied: %+v", r)
	}
}
