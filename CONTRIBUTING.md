# 🤝 Contributing to Advanced Cyber-Physical Range Simulator

We welcome contributions to the Advanced Cyber-Physical Range Simulator! This document provides guidelines for contributing to the project.

## 🎯 Project Overview

This is a comprehensive CPS cyber range simulation featuring:
- Docker-based infrastructure with honeypots
- Multi-agent neural network systems
- Suricata IDS integration
- Real-time security monitoring
- Advanced visualization tools

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Docker Desktop
- Git

### Setup Development Environment
```bash
# Clone the repository
git clone <your-repo-url>
cd advanced-cyber-range-simulator

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-neural.txt

# Install development tools
pip install pytest black flake8 mypy
```

## 📋 How to Contribute

### 1. Fork and Clone
- Fork the repository on GitHub
- Clone your fork locally
- Create a feature branch

### 2. Development Guidelines
- Follow PEP 8 style guidelines
- Write clear, documented code
- Add tests for new features
- Update documentation

### 3. Submit Changes
- Push to your fork
- Create a pull request
- Describe your changes clearly
- Include tests and documentation

## 🏗️ Project Structure

```
advanced-cyber-range-simulator/
├── python cyberrange_all_in_one.py    # Main simulation script
├── multi_agent_system.py              # Multi-agent architecture
├── neural_agent_integration.py        # Neural integration layer
├── advanced_neural_architectures.py   # Advanced neural models
├── suricata-monitor.py                # Suricata monitoring dashboard
├── configs/                           # Configuration files
│   └── suricata/                      # Suricata IDS configs
├── monitoring/                        # Docker compose files
│   ├── docker-compose-closed.yml     # Enhanced setup
│   └── laptop-optimization.yml       # Laptop setup
├── topology-viewer/                   # React visualization
├── tests/                            # Test files
├── benchmark/                        # Benchmark configurations
└── docs/                             # Documentation
```

## 🔧 Development Areas

### 1. Neural Network Enhancements
- New neural architectures
- Improved agent coordination
- Advanced learning algorithms
- Performance optimization

### 2. Security Features
- Additional IDS rules
- New honeypot types
- Enhanced monitoring
- Threat intelligence integration

### 3. Infrastructure
- New container types
- Network configurations
- Performance optimizations
- Cloud deployment options

### 4. Visualization
- Enhanced topology viewer
- Real-time dashboards
- 3D visualizations
- Mobile interfaces

### 5. Simulation Logic
- New attack patterns
- Defense strategies
- Physics models
- Benchmark scenarios

## 🧪 Testing

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_neural_system.py

# Run with coverage
pytest --cov=. tests/
```

### Test Categories
- **Unit Tests**: Individual components
- **Integration Tests**: Component interactions
- **System Tests**: Full simulation
- **Performance Tests**: Resource usage

### Writing Tests
- Use pytest framework
- Test both success and failure cases
- Mock external dependencies
- Include edge cases

## 📝 Code Style

### Python Guidelines
- Follow PEP 8
- Use type hints
- Document functions and classes
- Keep functions focused

### Example Code Style
```python
def calculate_risk_score(
    threat_level: float, 
    vulnerability_score: float, 
    asset_value: float
) -> float:
    """Calculate comprehensive risk score.
    
    Args:
        threat_level: Current threat level (0.0-1.0)
        vulnerability_score: Vulnerability assessment (0.0-1.0)
        asset_value: Asset criticality (0.0-1.0)
        
    Returns:
        Risk score (0.0-1.0)
    """
    return (threat_level * vulnerability_score * asset_value) ** 0.5
```

## 🐛 Bug Reports

### Reporting Bugs
1. Check existing issues
2. Create detailed bug report
3. Include reproduction steps
4. Add system information
5. Provide logs if available

### Bug Report Template
```markdown
## Bug Description
Brief description of the issue

## Steps to Reproduce
1. Run command: `python "python cyberrange_all_in_one.py" --enhanced-docker`
2. Observe error
3. Expected behavior vs actual

## System Information
- OS: Windows 10
- Python: 3.9.0
- Docker: 20.10.0
- RAM: 16GB

## Logs
```
[ERROR] Container failed to start...
```
```

## 💡 Feature Requests

### Proposing Features
1. Check existing issues and discussions
2. Create detailed feature request
3. Explain use case and benefits
4. Consider implementation approach
5. Include mockups if applicable

### Feature Request Template
```markdown
## Feature Description
Clear description of proposed feature

## Use Case
Why this feature is needed
Who would benefit
Current limitations

## Proposed Solution
How to implement
Technical considerations
Potential challenges

## Alternatives
Other approaches considered
Pros and cons
```

## 📖 Documentation

### Documentation Types
- **API Documentation**: Code references
- **User Guides**: How-to instructions
- **Architecture Docs**: System design
- **Tutorials**: Step-by-step guides

### Writing Documentation
- Use clear, concise language
- Include code examples
- Add screenshots/diagrams
- Keep documentation up-to-date

## 🔄 Release Process

### Version Management
- Use semantic versioning (MAJOR.MINOR.PATCH)
- Update CHANGELOG.md
- Tag releases in Git
- Create GitHub releases

### Release Checklist
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG updated
- [ ] Version bumped
- [ ] Release tagged
- [ ] GitHub release created

## 🏆 Recognition

### Contributor Recognition
- Contributors listed in README
- Special thanks in releases
- Featured in project showcase
- Invitation to core team (for significant contributions)

### Types of Contributions
- **Code**: New features, bug fixes
- **Documentation**: Guides, tutorials
- **Testing**: Test cases, bug reports
- **Design**: UI/UX, graphics
- **Community**: Support, discussions

## 📞 Getting Help

### Communication Channels
- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: Questions, ideas
- **Code Reviews**: Feedback on contributions

### Community Guidelines
- Be respectful and inclusive
- Provide constructive feedback
- Help others learn and grow
- Follow the code of conduct

## 🎯 Development Priorities

### High Priority
- Bug fixes and stability
- Performance improvements
- Security enhancements
- Documentation updates

### Medium Priority
- New neural architectures
- Additional container types
- Enhanced visualizations
- Benchmark scenarios

### Low Priority
- Experimental features
- Minor UI improvements
- Nice-to-have enhancements

## 📋 Review Process

### Pull Request Review
1. Automated checks (tests, linting)
2. Code review by maintainers
3. Documentation review
4. Integration testing
5. Approval and merge

### Review Criteria
- Code quality and style
- Test coverage
- Documentation
- Performance impact
- Security considerations

## 🌟 Recognition Program

### Contributor Levels
- **Contributor**: 1+ merged PRs
- **Active Contributor**: 5+ merged PRs
- **Core Contributor**: 10+ merged PRs
- **Maintainer**: Significant ongoing contributions

### Benefits
- GitHub organization membership
- Release management access
- Project direction input
- Special recognition in releases

---

Thank you for contributing to the Advanced Cyber-Physical Range Simulator! 🎉

Every contribution helps make this project better for the cybersecurity research community.
