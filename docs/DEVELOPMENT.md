# Development and releases

## Local quality gates

Build and test with the Go version declared in `go.mod`:

```bash
test -z "$(gofmt -l .)"
go mod tidy
git diff --exit-code -- go.mod go.sum
go vet ./...
go test -race ./...
go test -cover ./...
go build ./cmd/airlock-certctl
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Release binaries receive their version through linker flags. A local build
prints `dev`:

```bash
./airlock-certctl build-info
```

## Live Gateway tests

The opt-in test suite validates the OpenAPI contract, typed reads, independent
sessions, atomic lifecycle behavior, concurrency rejection, optional frontend
TLS presentation, and restoration of the original configuration.

```bash
AIRLOCK_LIVE_TEST=1 \
AIRLOCK_HOST=gateway.example.com \
AIRLOCK_API_KEY='...' \
go test ./pkg/airlock -run '^TestLiveGateway' -count=1 -v
```

Optional frontend verification uses:

```bash
AIRLOCK_TEST_FQDN=www.example.com
AIRLOCK_TEST_VIRTUAL_HOST=www
AIRLOCK_TEST_SERVICE_ADDRESS=192.0.2.10:443
```

The lifecycle test changes and restores appliance configuration. Run it only
against an approved disposable test target and confirm the restored VIP after
completion.

## GitHub automation

The repository contains:

- `ci.yml`: formatting, module drift, vet, race tests, CLI build, and
  `govulncheck` on pushes and pull requests;
- `govulncheck.yml`: weekly and manually dispatched vulnerability scanning;
- `codeql.yml`: Go CodeQL on pushes, pull requests, weekly schedule, and manual
  dispatch;
- `dependency-review.yml`: dependency review on pull requests;
- `release.yml`: release validation and GoReleaser publishing from explicit
  semantic tags;
- `dependabot.yml`: grouped weekly updates for modules and Actions; and
- `scripts/check-workflow-actions.sh`: detection of stale workflow action
  references.

Private or internal repositories require GitHub Code Security/GHAS for CodeQL
and Dependency Review. After enabling it, set this repository variable:

```text
ENABLE_GITHUB_CODE_SECURITY=true
```

Without the variable, those two jobs are skipped for private/internal
repositories. CI and `govulncheck` continue to run without GHAS.

The vulnerability workflow deliberately invokes:

```bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

It does not use the older `golang/govulncheck-action@v1`, whose internal
checkout caused duplicate Authorization headers. The scanner may require a
newer toolchain than the application; workflows therefore use Go 1.25.x and
`GOTOOLCHAIN=auto` for the scanner without changing the project `go.mod`.

Confirm stale action references are absent with:

```bash
git grep -n 'golang/govulncheck-action@v1\|actions/checkout@v4\|actions/setup-go@v5' -- .github/workflows || true
./scripts/check-workflow-actions.sh
```

## Releases

Releases are created only from explicit semantic tags. The workflow never
creates or moves a tag:

```bash
git checkout main
git pull
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Accepted formats are `vMAJOR.MINOR.PATCH` and
`vMAJOR.MINOR.PATCH-PRERELEASE`. The workflow checks out the tagged commit,
repeats the release gates, and publishes Linux, macOS, and Windows archives
with checksums. A failed gate prevents publication.

Manual dispatch is a recovery path for an existing tag:

```bash
gh workflow run release.yml -f tag=v0.1.0 --ref main
```

GitHub Actions needs `Read and write permissions` under repository workflow
settings to create the release and upload assets.

See [Production readiness](../PRODUCTION_READINESS.md) for the complete release
and customer-delivery contract.
