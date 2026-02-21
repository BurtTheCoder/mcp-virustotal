# Contributing

Thank you for your interest in contributing to `mcp-virustotal`!

## Getting Started

1. Fork the repository and clone it locally.
2. Install dependencies:

   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env` and fill in your `VIRUSTOTAL_API_KEY`.

4. Build the project:

   ```bash
   npm run build
   ```

## Submitting Changes

- Open an issue to discuss significant changes before starting work.
- Follow the existing code style enforced by ESLint and Prettier.
- Write clear, concise commit messages.
- Include tests for new functionality where practical.
- Open a pull request against the `main` branch.

## Code Style

This project uses:

- **ESLint** – `npm run lint`
- **Prettier** – enforced automatically by ESLint

## Reporting Issues

Please use the GitHub issue tracker and include:

- Node.js version (`node --version`)
- Steps to reproduce the problem
- Expected vs. actual behaviour
- Any relevant log output (sanitise API keys before sharing)
