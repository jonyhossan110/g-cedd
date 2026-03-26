# Contributing to G-CEDD

Thank you for your interest in contributing to G-CEDD! We welcome contributions from the community.

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/jonyhossan110/g-cedd.git
   cd g-cedd
   ```

2. **Set up development environment**
   ```bash
   # Create virtual environment
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate

   # Install with development dependencies
   pip install -e ".[dev]"
   ```

3. **Run tests**
   ```bash
   pytest tests/
   ```

4. **Check code quality**
   ```bash
   ruff check g_cedd/
   mypy g_cedd/
   ```

## How to Contribute

### Reporting Bugs

- Use the bug report template when creating issues
- Include detailed steps to reproduce the issue
- Provide system information (OS, Python version, etc.)
- Include relevant log output or error messages

### Suggesting Features

- Use the feature request template
- Describe the problem you're trying to solve
- Explain why this feature would be useful
- Consider alternative solutions

### Code Contributions

1. **Fork the repository** on GitHub
2. **Create a feature branch** from `main`
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Run the test suite** to ensure nothing is broken
6. **Update documentation** if needed
7. **Commit your changes**
   ```bash
   git commit -m "Add: Brief description of your changes"
   ```
8. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
9. **Create a Pull Request** on GitHub

## Coding Standards

- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Write docstrings for all public functions and classes
- Keep line length under 100 characters
- Use descriptive variable and function names

## Testing

- Write unit tests for new functionality
- Ensure all tests pass before submitting PR
- Aim for good test coverage
- Use descriptive test names

## Documentation

- Update README.md for new features
- Add docstrings to new functions
- Update type hints as needed
- Keep examples in README up to date

## Commit Messages

Use clear, descriptive commit messages:

```
type: Brief description of changes

Detailed explanation if needed.
```

Types:
- `Add:` - New features
- `Fix:` - Bug fixes
- `Update:` - Changes to existing features
- `Remove:` - Removed features
- `Docs:` - Documentation changes
- `Test:` - Test-related changes

## License

By contributing to G-CEDD, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue or discussion if you have questions about contributing!