# Contributing to SimpleLB

Thank you for your interest in contributing to this project! We welcome contributions from the community and are pleased to have you join us.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Code Style](#code-style)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please be respectful and professional in all interactions.

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Go 1.21 or later
- Git
- A text editor or IDE

### Development Setup

1. **Fork the repository** on GitHub

2. **Clone your fork** locally:
```bash
git clone https://github.com/your-username/simplelb.git
cd simplelb
```

3. **Set up the upstream remote**:
```bash
git remote add upstream https://github.com/ddalcu/simplelb.git
```

4. **Create a development branch**:
```bash
git checkout -b feature/your-feature-name
```

5. **Start the development environment**:
```bash
docker-compose up --build
```

6. **Access the application**:
   - Web UI: http://localhost:81
   - Load balancer: http://localhost:80

## Making Changes

### Before You Start

- **Check existing issues** to see if someone is already working on something similar
- **Create an issue** to discuss major changes before implementing them
- **Keep changes focused** - one feature or bug fix per pull request

### Development Workflow

1. **Make your changes** in your feature branch
2. **Test your changes** thoroughly
3. **Update documentation** if needed
4. **Commit your changes** with clear, descriptive messages

### Commit Message Format

Use clear and descriptive commit messages:

```
<type>: <description>

<optional longer description>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat: add support for custom hash load balancing

fix: resolve SSL certificate retry button visibility

docs: update installation instructions for Docker
```

## Pull Request Process

1. **Update your branch** with the latest upstream changes:
```bash
git fetch upstream
git rebase upstream/main
```

2. **Ensure all tests pass** and the application builds successfully

3. **Create a pull request** with:
   - Clear title and description
   - Reference to any related issues
   - Screenshots for UI changes
   - Steps to test the changes

4. **Address review feedback** promptly

5. **Keep your branch up to date** during the review process

### Pull Request Template

When creating a PR, please include:

- **What**: Description of what changed
- **Why**: Reason for the change
- **How**: How the change was implemented
- **Testing**: How you tested the change
- **Screenshots**: If applicable, especially for UI changes

## Testing

### Manual Testing

1. **Build and run** the application:
```bash
docker-compose up --build
```

2. **Test core functionality**:
   - Create/edit/delete load balancers
   - Test different load balancing methods
   - Test SSL certificate generation (with valid domains)
   - Test log viewing functionality

3. **Test edge cases**:
   - Invalid input handling
   - Network errors
   - Certificate failures

### Automated Testing

While we don't have automated tests yet, we welcome contributions that add:
- Unit tests for Go functions
- Integration tests for API endpoints
- End-to-end tests for UI workflows

## Code Style

### Go Code

- Follow standard Go formatting (`go fmt`)
- Use meaningful variable and function names
- Add comments for exported functions
- Handle errors appropriately
- Use structured logging

### HTML/CSS/JavaScript

- Use semantic HTML
- Keep CSS organized and documented
- Use modern JavaScript features appropriately
- Ensure accessibility standards are met

### Docker

- Use multi-stage builds for efficiency
- Minimize layer count and size
- Use specific version tags for base images
- Document any new environment variables

## Project Structure

```
.
├── main.go                 # Main Go application
├── templates/              # HTML templates
│   ├── dashboard.html      # Main web interface
│   └── login.html         # Login page
├── Dockerfile             # Container definition
├── docker-compose.yml     # Development environment
├── supervisord.conf       # Process management
├── start.sh              # Container startup script
├── nginx.conf.template   # Base nginx configuration
├── go.mod                # Go module definition
├── .github/              # GitHub Actions workflows
├── docs/                 # Additional documentation
└── examples/             # Usage examples
```

## Reporting Issues

### Bug Reports

Please include:
- **Clear description** of the issue
- **Steps to reproduce** the problem
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Docker version, etc.)
- **Logs or screenshots** if applicable

### Feature Requests

Please include:
- **Clear description** of the desired feature
- **Use case** - why is this feature needed?
- **Proposed solution** or implementation ideas
- **Alternatives considered**

### Issue Labels

We use labels to organize issues:
- `bug`: Something isn't working
- `enhancement`: New feature or improvement
- `documentation`: Documentation improvements
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention needed
- `question`: Further information requested

## Development Tips

### Debugging

- Use `docker-compose logs -f` to view real-time logs
- Access container shell: `docker exec -it nginx-loadbalancer-nginx-loadbalancer-1 /bin/sh`
- View specific logs: 
  - App logs: `/var/log/management-ui/stderr.log`
  - Nginx logs: `/var/log/nginx/stderr.log`
  - Let's Encrypt logs: `/var/log/letsencrypt/letsencrypt.log`

### Testing SSL Features

- Use a development domain that you control
- Point the domain to your development server
- Test with staging Let's Encrypt environment first

### Performance Considerations

- Profile Go code for performance bottlenecks
- Optimize Docker image size
- Consider nginx configuration performance implications

## Release Process

1. **Version Bump**: Update version numbers in relevant files
2. **Changelog**: Update CHANGELOG.md with new features and fixes
3. **Tag**: Create a git tag following semantic versioning (v1.2.3)
4. **Release**: GitHub Actions will automatically build and publish Docker images

## Getting Help

- **Documentation**: Check the README and inline documentation
- **Issues**: Search existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions and ideas

## Recognition

Contributors will be recognized in:
- GitHub contributors list
- Release notes for significant contributions
- Special mentions for major features or improvements

Thank you for contributing to making this project better! 🎉