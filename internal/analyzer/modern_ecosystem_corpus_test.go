package analyzer

import (
	"testing"

	"github.com/Bluezly/CIRadar/internal/model"
)

func TestModernEcosystemCorpus(t *testing.T) {
	tests := []struct {
		id         string
		repository string
		log        string
	}{
		{id: `modern-clojure-compiler`, repository: `clojure/clojure`, log: `Syntax error compiling at (src/app/core.clj:12:3). Unable to resolve symbol: foo in this context`},
		{id: `modern-clojure-unresolved-symbol`, repository: `clojure/clojure`, log: `Syntax error compiling at (src/app.clj:4:1). Unable to resolve symbol: missing in this context`},
		{id: `modern-clojure-arity`, repository: `clojure/clojure`, log: `Execution error (ArityException) at app.core/run. Wrong number of args (2) passed to: app.core/foo`},
		{id: `modern-clojure-class-not-found`, repository: `clojure/clojure`, log: `Execution error (FileNotFoundException) at app.core/eval. Could not locate missing/core__init.class, missing/core.clj or missing/core.cljc on classpath.`},
		{id: `modern-lein-artifact-missing`, repository: `technomancy/leiningen`, log: `Could not find artifact com.example:missing:jar:1.0.0 in central`},
		{id: `modern-lein-transfer-failed`, repository: `technomancy/leiningen`, log: `Could not transfer artifact foo:bar:pom:1.0 from/to central: Read timed out`},
		{id: `modern-lein-test-failure`, repository: `technomancy/leiningen`, log: `lein test app.core-test
FAIL in (adds-values) (core_test.clj:8) expected: (= 4 (add 2 3))`},
		{id: `modern-lein-profile-missing`, repository: `technomancy/leiningen`, log: `Profile :ci not found in project.clj`},
		{id: `modern-groovy-compile`, repository: `apache/groovy`, log: `org.codehaus.groovy.control.MultipleCompilationErrorsException: startup failed:
src/App.groovy: 4: unable to resolve class Missing`},
		{id: `modern-groovy-missing-property`, repository: `apache/groovy`, log: `groovy.lang.MissingPropertyException: No such property: foo for class: App`},
		{id: `modern-groovy-missing-method`, repository: `apache/groovy`, log: `groovy.lang.MissingMethodException: No signature of method: App.foo() is applicable`},
		{id: `modern-spock-failure`, repository: `spockframework/spock`, log: `Condition not satisfied:
result == 42
|      |
41     false`},
		{id: `modern-gradle-groovy-dsl`, repository: `gradle/gradle`, log: `A problem occurred evaluating root project app. Could not find method foo() for arguments []`},
		{id: `modern-groovy-version`, repository: `apache/groovy`, log: `BUG! exception in phase semantic analysis in source unit build.gradle Unsupported class file major version 65`},
		{id: `modern-julia-unsatisfiable`, repository: `JuliaLang/Pkg.jl`, log: `ERROR: Unsatisfiable requirements detected for package Foo [12345678]:`},
		{id: `modern-julia-package-missing`, repository: `JuliaLang/Pkg.jl`, log: `ERROR: The following package names could not be resolved:
 * MissingPkg (not found in project, manifest or registry)`},
		{id: `modern-julia-loaderror`, repository: `JuliaLang/julia`, log: `ERROR: LoadError: UndefVarError: foo not defined
in expression starting at /workspace/src/app.jl:8`},
		{id: `modern-julia-methoderror`, repository: `JuliaLang/julia`, log: `ERROR: MethodError: no method matching foo(::Int64)`},
		{id: `modern-julia-precompile`, repository: `JuliaLang/Pkg.jl`, log: `ERROR: LoadError: Failed to precompile Example [7876af07-990d-54b4-ab0e-23690620f79a]`},
		{id: `modern-julia-artifact-download`, repository: `JuliaLang/Pkg.jl`, log: `ERROR: Unable to automatically download/install artifact OpenSSL from sources listed in Artifacts.toml`},
		{id: `modern-julia-test-failure`, repository: `JuliaLang/julia`, log: `Test Failed at /workspace/test/runtests.jl:10
  Expression: foo() == 1`},
		{id: `modern-julia-version`, repository: `JuliaLang/Pkg.jl`, log: `ERROR: Unsatisfiable requirements detected: package Foo requires julia version 1.11`},
		{id: `modern-deno-module-not-found`, repository: `denoland/deno`, log: `error: Module not found "npm:openai@4.12.4".`},
		{id: `modern-deno-import-error`, repository: `denoland/deno`, log: `error: Import "https://deno.land/x/missing/mod.ts" failed.`},
		{id: `modern-deno-cert`, repository: `denoland/deno`, log: `error sending request for url: invalid peer certificate: UnknownIssuer`},
		{id: `modern-deno-permission`, repository: `denoland/deno`, log: `NotCapable: Requires env access to "DATABASE_URL", run again with --allow-env`},
		{id: `modern-deno-typecheck`, repository: `denoland/deno`, log: `TS2322 [ERROR]: Type string is not assignable to type number.`},
		{id: `modern-deno-lock`, repository: `denoland/deno`, log: `error: Integrity check failed for remote specifier https://deno.land/x/foo/mod.ts`},
		{id: `modern-bun-resolve`, repository: `oven-sh/bun`, log: `error: Could not resolve: "axios/dist/node/axios.cjs". Maybe you need to "bun install"?`},
		{id: `modern-bun-lockfile`, repository: `oven-sh/bun`, log: `error: failed to parse bun.lock: unexpected token`},
		{id: `modern-bun-install-network`, repository: `oven-sh/bun`, log: `bun install v1.2.0
error: Failed to download package: ECONNRESET`},
		{id: `modern-bun-test-failure`, repository: `oven-sh/bun`, log: `bun test v1.2.0
1 pass
1 fail
error: expect(received).toBe(expected)`},
		{id: `modern-bun-panic`, repository: `oven-sh/bun`, log: `panic(main thread): Internal assertion failure
oh no: Bun has crashed. This indicates a bug in Bun, not your code.`},
		{id: `modern-bun-unsupported-os`, repository: `oven-sh/bun`, log: `error: Bun is not supported on this operating system`},
		{id: `modern-solc-parser`, repository: `ethereum/solidity`, log: `ParserError: Expected ";" but got "constant"
 --> src/App.sol:38:22:`},
		{id: `modern-solc-type`, repository: `ethereum/solidity`, log: `TypeError: Member "foo" not found or not visible after argument-dependent lookup in contract App.`},
		{id: `modern-solc-declaration`, repository: `ethereum/solidity`, log: `DeclarationError: Undeclared identifier.
 --> src/App.sol:9:3:`},
		{id: `modern-foundry-compiler`, repository: `foundry-rs/foundry`, log: `Compiler run failed:
Error (2314): Expected ";" but got "constant"`},
		{id: `modern-foundry-test-revert`, repository: `foundry-rs/foundry`, log: `[FAIL: EvmError: Revert] testTransfer() (gas: 12345)`},
		{id: `modern-foundry-test-assert`, repository: `foundry-rs/foundry`, log: `[FAIL: assertion failed: 1 != 2] testValue() (gas: 20234)`},
		{id: `modern-foundry-rpc`, repository: `foundry-rs/foundry`, log: `Error: error sending request for url (http://127.0.0.1:8545/): connection refused`},
		{id: `modern-foundry-fork-block`, repository: `foundry-rs/foundry`, log: `Error: failed to get block for block number 199999999`},
		{id: `modern-hardhat-compiler-download`, repository: `NomicFoundation/hardhat`, log: `Error HH502: Couldn't download compiler version list. Please check your internet connection and try again.`},
		{id: `modern-hardhat-config`, repository: `NomicFoundation/hardhat`, log: `Error HH8: There's one or more errors in your config file`},
		{id: `modern-hardhat-artifact`, repository: `NomicFoundation/hardhat`, log: `Error HH700: Artifact for contract "Greeter" not found.`},
		{id: `modern-hardhat-network`, repository: `NomicFoundation/hardhat`, log: `Error HH108: Cannot connect to the network localhost.`},
		{id: `modern-hardhat-revert`, repository: `NomicFoundation/hardhat`, log: `Error: VM Exception while processing transaction: reverted with reason string "NotOwner"`},
		{id: `modern-hardhat-insufficient-funds`, repository: `NomicFoundation/hardhat`, log: `ProviderError: insufficient funds for intrinsic transaction cost`},
		{id: `modern-prisma-p1000`, repository: `prisma/prisma`, log: `Error: P1000: Authentication failed against database server at db, the provided database credentials are not valid.`},
		{id: `modern-prisma-p1001`, repository: `prisma/prisma`, log: `Error: P1001: Can't reach database server at ` + "`" + `db` + "`" + `:` + "`" + `5432` + "`" + ``},
		{id: `modern-prisma-p1002`, repository: `prisma/prisma`, log: `Error: P1002: The database server at db:5432 was reached but timed out.`},
		{id: `modern-prisma-p1003`, repository: `prisma/prisma`, log: `Error: P1003: Database app_test does not exist on the database server at db:5432.`},
		{id: `modern-prisma-p1012`, repository: `prisma/prisma`, log: `Error code: P1012
error: Error validating field ` + "`" + `user` + "`" + ` in model ` + "`" + `Post` + "`" + ``},
		{id: `modern-prisma-p2002`, repository: `prisma/prisma`, log: `PrismaClientKnownRequestError: Unique constraint failed on the fields: (` + "`" + `email` + "`" + `)
code: P2002`},
		{id: `modern-prisma-p2003`, repository: `prisma/prisma`, log: `PrismaClientKnownRequestError: Foreign key constraint failed on the field: ` + "`" + `Post_authorId_fkey` + "`" + ` (index)
code: P2003`},
		{id: `modern-prisma-p2024`, repository: `prisma/prisma`, log: `Error P2024: Timed out fetching a new connection from the connection pool.`},
		{id: `modern-prisma-p2025`, repository: `prisma/prisma`, log: `PrismaClientKnownRequestError code: P2025 cause: No Profile record was found for a nested delete.`},
		{id: `modern-prisma-migration-failed`, repository: `prisma/prisma`, log: `Error: P3018
A migration failed to apply. New migrations cannot be applied before the error is recovered from.`},
		{id: `modern-vite-import`, repository: `vitejs/vite`, log: `[vite]: Rollup failed to resolve import "@shared/greet.ts" from "/workspace/src/main.ts".`},
		{id: `modern-vite-plugin-error`, repository: `vitejs/vite`, log: `[plugin:vite:import-analysis] Failed to resolve import "@/App.vue" from "src/main.ts".`},
		{id: `modern-vite-out-of-memory`, repository: `vitejs/vite`, log: `vite build
FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory`},
		{id: `modern-webpack-module`, repository: `webpack/webpack`, log: `Module not found: Error: Can't resolve 'react' in '/workspace/src'`},
		{id: `modern-webpack-loader`, repository: `webpack/webpack`, log: `Module not found: Error: Can't resolve 'babel-loader'`},
		{id: `modern-webpack-schema`, repository: `webpack/webpack`, log: `Invalid configuration object. Webpack has been initialized using a configuration object that does not match the API schema.`},
		{id: `modern-esbuild-resolve`, repository: `evanw/esbuild`, log: `✘ [ERROR] Could not resolve "ansi-styles"`},
		{id: `modern-esbuild-platform`, repository: `evanw/esbuild`, log: `✘ [ERROR] Could not resolve "fs"
The package "fs" wasn't found on the file system but is built into node. Are you trying to bundle for node?`},
		{id: `modern-rollup-entry`, repository: `rollup/rollup`, log: `RollupError: Could not resolve entry module "src/missing.ts".`},
		{id: `modern-rollup-export`, repository: `rollup/rollup`, log: `RollupError: "foo" is not exported by "src/lib.ts", imported by "src/main.ts".`},
		{id: `modern-next-page-not-found`, repository: `vercel/next.js`, log: `Failed to compile. Module not found: Can't resolve "@/components/Missing"
Next.js build worker exited with code: 1`},
		{id: `modern-next-prerender`, repository: `vercel/next.js`, log: `Error occurred prerendering page "/dashboard". Read more: https://nextjs.org/docs/messages/prerender-error`},
		{id: `modern-next-static-generation`, repository: `vercel/next.js`, log: `Static page generation for /reports is still timing out after 3 attempts.`},
		{id: `modern-nx-project-config`, repository: `nrwl/nx`, log: `NX   Unable to create project graph. Plugin nx/js threw an error while creating dependencies.`},
		{id: `modern-nx-task-failed`, repository: `nrwl/nx`, log: `NX   Running target build for project app failed`},
		{id: `modern-turbo-task-failed`, repository: `vercel/turborepo`, log: `ERROR  run failed: command exited (1)
Failed: app#build`},
		{id: `modern-turbo-lockfile`, repository: `vercel/turborepo`, log: `turbo 2.0
ERROR Failed to parse lockfile pnpm-lock.yaml`},
		{id: `modern-cuda-compiler-missing`, repository: `NVIDIA/cuda-samples`, log: `CMake Error: No CMAKE_CUDA_COMPILER could be found.`},
		{id: `modern-cuda-unsupported-gpu`, repository: `NVIDIA/cuda-samples`, log: `CUDA error: no kernel image is available for execution on the device`},
		{id: `modern-cuda-oom`, repository: `pytorch/pytorch`, log: `RuntimeError: CUDA out of memory. Tried to allocate 2.00 GiB.`},
		{id: `modern-cuda-driver`, repository: `NVIDIA/cuda-samples`, log: `CUDA driver version is insufficient for CUDA runtime version`},
		{id: `modern-cuda-device`, repository: `NVIDIA/cuda-samples`, log: `CUDA error at deviceQuery: no CUDA-capable device is detected`},
		{id: `modern-cuda-link`, repository: `NVIDIA/cuda-samples`, log: `/usr/bin/ld: cannot find -lcudart`},
		{id: `modern-fortran-module`, repository: `fortran-lang/fpm`, log: `Fatal Error: Cannot open module file ‘mpi.mod’ for reading: No such file or directory`},
		{id: `modern-fortran-symbol`, repository: `gcc-mirror/gcc`, log: `Error: Symbol ‘foo’ at (1) has no IMPLICIT type`},
		{id: `modern-fortran-rank`, repository: `gcc-mirror/gcc`, log: `Error: Rank mismatch in argument ‘a’ at (1) (rank-1 and scalar)`},
		{id: `modern-fortran-link`, repository: `gcc-mirror/gcc`, log: `undefined reference to ` + "`" + `__foo_MOD_bar'`},
		{id: `modern-fortran-fpm-dep`, repository: `fortran-lang/fpm`, log: `<ERROR> Error while fetching dependency foo for fpm package.`},
		{id: `modern-nim-undeclared`, repository: `nim-lang/Nim`, log: `app.nim(4, 1) Error: undeclared identifier: 'foo'`},
		{id: `modern-nim-type`, repository: `nim-lang/Nim`, log: `app.nim(8, 5) Error: type mismatch: got <string> but expected int`},
		{id: `modern-nim-package`, repository: `nim-lang/nimble`, log: `Error: Package missing_pkg not found in any nimble package list.`},
		{id: `modern-nim-c-compiler`, repository: `nim-lang/Nim`, log: `Error: execution of an external compiler program gcc failed with exit code 1`},
		{id: `modern-nim-test`, repository: `nim-lang/Nim`, log: `[FAILED] adds values
Check failed: add(2, 2) == 5`},
		{id: `modern-crystal-syntax`, repository: `crystal-lang/crystal`, log: `Syntax error in src/app.cr:4: unexpected token: EOF`},
		{id: `modern-crystal-undefined`, repository: `crystal-lang/crystal`, log: `Error: undefined method "foo" for Nil`},
		{id: `modern-crystal-type`, repository: `crystal-lang/crystal`, log: `Error: expected argument #1 to App#run to be String, not Int32`},
		{id: `modern-shards-resolve`, repository: `crystal-lang/shards`, log: `Unable to satisfy the following requirements: - ` + "`" + `foo ~> 2.0` + "`" + ` required by shard.yml`},
		{id: `modern-crystal-link`, repository: `crystal-lang/crystal`, log: `ld: library not found for -lgc
Error: execution of command with flags failed`},
		{id: `modern-selenium-session`, repository: `SeleniumHQ/selenium`, log: `selenium.common.exceptions.SessionNotCreatedException: This version of ChromeDriver only supports Chrome version 124`},
		{id: `modern-selenium-driver-missing`, repository: `SeleniumHQ/selenium`, log: `selenium.common.exceptions.NoSuchDriverException: Unable to obtain driver for chrome`},
		{id: `modern-selenium-element`, repository: `SeleniumHQ/selenium`, log: `selenium.common.exceptions.NoSuchElementException: no such element: Unable to locate element: {"using":"id","value":"submit"}`},
		{id: `modern-selenium-stale`, repository: `SeleniumHQ/selenium`, log: `selenium.common.exceptions.StaleElementReferenceException: stale element reference: stale element not found`},
		{id: `modern-webdriver-timeout`, repository: `SeleniumHQ/selenium`, log: `selenium.common.exceptions.TimeoutException: Message: Timed out waiting for element`},
		{id: `modern-webdriver-disconnected`, repository: `SeleniumHQ/selenium`, log: `WebDriverException: disconnected: not connected to DevTools`},
		{id: `modern-apt-package-missing`, repository: `Debian/apt`, log: `E: Unable to locate package libmissing-dev`},
		{id: `modern-apt-release-missing`, repository: `Debian/apt`, log: `E: The repository http://example.invalid stable Release does not have a Release file.`},
		{id: `modern-apt-lock`, repository: `Debian/apt`, log: `E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234`},
		{id: `modern-apk-package-missing`, repository: `alpinelinux/apk-tools`, log: `ERROR: unable to select packages:
  missing (no such package)`},
		{id: `modern-dnf-package-missing`, repository: `rpm-software-management/dnf`, log: `No match for argument: missing-devel
Error: Unable to find a match: missing-devel`},
		{id: `modern-brew-formula-missing`, repository: `Homebrew/brew`, log: `Error: No available formula with the name 'missing'.`},
		{id: `modern-brew-link`, repository: `Homebrew/brew`, log: `Error: Could not symlink bin/foo
Target /usr/local/bin/foo already exists.`},
		{id: `modern-brew-download`, repository: `Homebrew/brew`, log: `Error: Download failed: https://ghcr.io/v2/homebrew/core/foo/blobs/sha256:abc`},
		{id: `modern-helm-chart-missing`, repository: `helm/helm`, log: `Error: chart "missing" matching 1.0.0 not found in repo index.`},
		{id: `modern-helm-render`, repository: `helm/helm`, log: `Error: template: app/templates/deploy.yaml:12:18: executing "app/templates/deploy.yaml" at <.Values.image.tag>: nil pointer evaluating interface {}.tag`},
		{id: `modern-helm-values`, repository: `helm/helm`, log: `Error: template: app: wrong type for value; expected string; got interface {}`},
		{id: `modern-helm-kube-connect`, repository: `helm/helm`, log: `Error: Kubernetes cluster unreachable: Get "https://cluster:6443/version": dial tcp: i/o timeout`},
		{id: `modern-kustomize-resource`, repository: `kubernetes-sigs/kustomize`, log: `Error: accumulating resources: accumulation err=accumulating resources from deployment.yaml: no such file or directory`},
		{id: `modern-kustomize-cycle`, repository: `kubernetes-sigs/kustomize`, log: `Error: recursed accumulation of path ./base: cycle detected`},
		{id: `modern-flyway-checksum`, repository: `flyway/flyway`, log: `Validate failed: Migration checksum mismatch for migration version 1`},
		{id: `modern-flyway-failed-migration`, repository: `flyway/flyway`, log: `Schema history table contains a failed migration to version 3`},
		{id: `modern-liquibase-checksum`, repository: `liquibase/liquibase`, log: `Validation Failed: 1 changesets check sum
changelog.xml::1::dev was: 8:abc but is now: 8:def`},
		{id: `modern-liquibase-lock`, repository: `liquibase/liquibase`, log: `liquibase.exception.LockException: Could not acquire change log lock. Currently locked by runner`},
		{id: `modern-django-migration-conflict`, repository: `django/django`, log: `CommandError: Conflicting migrations detected; multiple leaf nodes in the migration graph: (0003_a, 0003_b in app).`},
		{id: `modern-django-app-missing`, repository: `django/django`, log: `ModuleNotFoundError: No module named app.settings
  File "/venv/site-packages/django/core/management/__init__.py", line 442`},
		{id: `modern-django-db-unavailable`, repository: `django/django`, log: `django.db.utils.OperationalError: connection to server at "db", port 5432 failed: Connection refused`},
		{id: `modern-alembic-revision-missing`, repository: `sqlalchemy/alembic`, log: `FAILED: Can't locate revision identified by 'abc123'`},
		{id: `modern-alembic-heads`, repository: `sqlalchemy/alembic`, log: `FAILED: Multiple head revisions are present for given argument head`},
		{id: `modern-sqlalchemy-pool-timeout`, repository: `sqlalchemy/sqlalchemy`, log: `sqlalchemy.exc.TimeoutError: QueuePool limit of size 5 overflow 10 reached, connection timed out`},
	}
	a := New("test")
	byID := make(map[string]Rule, len(a.rules))
	for _, rule := range a.rules {
		byID[rule.ID] = rule
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			rule, ok := byID[tt.id]
			if !ok {
				t.Fatalf("missing builtin rule %s", tt.id)
			}
			if !matchesRule(rule, tt.log) {
				t.Fatalf("rule %s did not match its corpus sample", tt.id)
			}
			r := a.Analyze(model.AnalysisInput{TenantID: "alpha", Repository: tt.repository, Log: tt.log}, Context{})
			if r.Category == model.CategoryUnknown {
				t.Fatalf("sample remained UNKNOWN rules=%v", r.MatchedRules)
			}
			found := false
			for _, id := range r.MatchedRules {
				if id == tt.id {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected %s in matches, got %v", tt.id, r.MatchedRules)
			}
		})
	}
}
