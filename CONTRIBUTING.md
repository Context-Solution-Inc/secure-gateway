# Contributing

Thanks for your interest in improving the Secure Device Relay. This guide covers
the development workflow; the [build book](./docs/BUILD.md) has the full
toolchain, run, and test details, and the [architecture reference](./docs/ARCHITECTURE.md)
explains how the pieces fit together.

## Getting set up

1. Install the toolchain — Go (this repo's SDK lives at `~/.local/go-sdk/go/bin`;
   export it onto `PATH`), and for the client SDKs JDK 17 (the Gradle wrapper is
   bundled). See [build book → Toolchain](./docs/BUILD.md#toolchain).
2. Build and run the test suite to confirm a clean baseline:

   ```sh
   export PATH="$PATH:$HOME/.local/go-sdk/go/bin"
   make build
   make test
   ```

## Development workflow

- **Branch** off `main` with a descriptive name (e.g. `feat/…`, `fix/…`,
  `docs/…`). Do not commit directly to `main`.
- **Keep changes focused** — one logical change per pull request.
- **Match the surrounding code** in style, naming, and comment density.
- **Open a pull request** against `main` and fill in what changed and why. Drafts
  are welcome for work in progress.

## Before you push

Run the checks the CI enforces:

```sh
make vet           # static analysis
make test          # unit + integration tests
make race          # tests under the race detector
```

For SDK changes, also run the relevant Gradle tasks from `sdk/`
(`./gradlew build`, and `:java:e2eTest` for cross-platform changes) — see the
[build book → Client SDKs](./docs/BUILD.md#client-sdks).

### Things to be careful about

- **The client-visible contract is frozen** from M5 on: the wire envelope, close
  codes, JWT claims, E2EE interop vectors (`internal/e2ee/testdata/vectors.json`),
  and the SDK API. Changing any of these breaks existing clients — raise it for
  discussion first.
- **Crypto parity:** all three SDKs must reproduce `vectors.json` byte-for-byte.
  If you touch the E2EE path, run the vectors-conformance tests on every platform
  you can (see the [build book](./docs/BUILD.md#client-sdks)).
- **Never log plaintext or secrets.** The relay must only ever see ciphertext and
  routing metadata; there are tests that assert this.

## Reporting bugs and vulnerabilities

- **Functional bugs / feature requests:** open a GitHub issue.
- **Security vulnerabilities:** do **not** open a public issue — follow the
  [security policy](./SECURITY.md) (email security@contextsolutions.ca).

## License

By contributing you agree that your contributions are licensed under the
project's [MIT License](./LICENSE).
