# TODO

Potential improvements and ideas if this was a bigger, production-grade project:

- Use a more sophisticated log parser to improve performance and extensibility (e.g. [Lark](https://github.com/lark-parser/lark)).
- Unify overlapping logic from `BruteForceDetector` and `PortScanDetector` into a single generic detector (e.g. a `ClusterDetector`).
- Add GitHub Actions workflows to run tests and linters on every commit.
- Provide structured logging and more error handlers for easier debugging.
