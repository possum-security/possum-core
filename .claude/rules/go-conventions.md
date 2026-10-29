---
paths: ["**/*.go"]
---

# Go Code Conventions (`possum-core`)

## Code Style & Idioms
- Target Go version: `go 1.26.5` (module `github.com/amirmahdy/possum-core`).
- Keep packages cohesive and avoid cyclic imports; shared domain primitives (`ScanResult`, `Node`, `Edge`, `Severity`, `Status`, `Category`, `Scope`) reside in `pkg/model` and are aliased in `pkg/scanner` where appropriate.
- Always dereference AWS SDK pointer fields safely using `aws.ToString`, `aws.ToInt64`, `aws.ToBool`, etc., and construct pointers with `aws.String`, `aws.Int64`, etc.
- Exported types, constructors, and functions must have clear GoDoc comments starting with the symbol name.
- Enforce interface compliance at compile time where applicable (e.g., `var _ scanner.MetaScanner = (*EIPScanner)(nil)`).

## Error Handling & Wrapping
- Wrap errors with actionable context and the `%w` verb so callers can inspect the error chain with `errors.Is` / `errors.As`:
  ```go
  if err != nil {
      return nil, fmt.Errorf("failed to list access analyzers: %w", err)
  }
  ```
- When aggregating multiple concurrent errors (such as in `scanner.Engine`), wrap each with the scanner name (`fmt.Errorf("%s: %w", sc.Name(), err)`) and combine using `errors.Join(scanErrors...)` when `FailOnError` is enabled.
- Never silently ignore errors unless explicitly intended and documented (e.g., best-effort body peeking on HTTP requests).

## Context Propagation & Cancellation
- Pass `context.Context` as the first parameter (`ctx context.Context`) to all functions performing I/O, AWS SDK calls, rate-limiting waits, or long-running loops.
- Respect context cancellation and resource limits inside pagination and resource iteration loops using `scanner.ShouldStop(ctx, currentCount, maxAllowed)` and `scanner.GetResourceLimit(ctx)`.
- Never store `context.Context` inside a struct; pass it explicitly per `Scan(ctx)` or API call.

## Concurrency Safety
- All shared state accessed across goroutines (`Engine`, `AWSCache`, `ThrottledTransport`, `MemoryTelemetryRecorder`, `RuleCatalog`) must be protected with `sync.RWMutex`, `sync.Mutex`, `sync/atomic`, or `golang.org/x/sync/singleflight`.
- Singleton initialization (`GetSharedAWSCache`, `GetSharedAPITelemetry`, `GetDefaultCatalog`) must use `sync.Once`.
- Copy slices or maps before returning them from read-locked getters (`LastErrors`, `ListServices`, `GetRecentCalls`) to prevent data races in callers.
- Bound concurrent goroutine fan-out using buffered channel semaphores (`make(chan struct{}, maxWorkers)`) and `sync.WaitGroup`, ensuring semaphore acquisition selects on `<-ctx.Done()`.

## Dependency Hygiene
- Maintain a minimal dependency footprint. Allowed core dependencies are:
  - AWS SDK for Go v2 (`github.com/aws/aws-sdk-go-v2/...`)
  - CLI & config (`github.com/spf13/cobra`, `gopkg.in/yaml.v3`)
  - Concurrency & rate limiting (`golang.org/x/sync`, `golang.org/x/time`)
  - Testing (`github.com/stretchr/testify`)
- Do not introduce third-party logging, ORM, HTTP router, or utility libraries when the Go standard library (`net/http`, `encoding/json`, `crypto/sha256`, `embed`, `sync`, `errors`) suffices.
