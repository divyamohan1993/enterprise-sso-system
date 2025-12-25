# Contributing to Enterprise SSO System

Thank you for your interest in contributing! This document provides guidelines
for contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone <your-fork-url>`
3. Install dependencies: `npm install`
4. Generate configuration: `npm run autoconfig`
5. Build: `npm run build`
6. Run tests: `npm run test`

## Development Workflow

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `security/` - Security improvements

### Commit Messages

Use conventional commits:

```
feat: add new MFA verification endpoint
fix: correct password validation regex
docs: update README with new examples
security: upgrade dependencies for CVE-2024-xxxx
```

### Pull Request Process

1. Ensure all tests pass: `npm run test`
2. Ensure linting passes: `npm run lint`
3. Ensure TypeScript compiles: `npm run typecheck`
4. Update documentation if needed
5. Submit PR with clear description

## Code Style

- Use TypeScript strict mode
- Follow existing code patterns
- Add JSDoc comments for public APIs
- Write unit tests for new features

## Security

- Never commit secrets or credentials
- Report security vulnerabilities privately (see SECURITY.md)
- Use the autoconfig script for key generation
- Follow OWASP guidelines

## Testing

```bash
# Run all tests
npm run test

# Run with coverage
npm run test:cov

# Run in watch mode
npm run test:watch
```

## Questions?

Open an issue with the "question" label.
