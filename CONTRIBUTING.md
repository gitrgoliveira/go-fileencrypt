# Contributing

Thanks for your interest in contributing to go-fileencrypt! Please follow these guidelines.

- Open an issue to discuss significant changes before implementing them.
- Fork the repo and create a feature branch for your change.
- Run the project's checks locally before opening a PR:

```bash
make validate-all
go test ./... -v -race
staticcheck ./...
gosec ./...
```

- Write tests for new functionality and update documentation where applicable.
- Keep PRs small and focused; reference related issues in the PR description.

Maintainers will review PRs and request changes as needed. Thank you!
