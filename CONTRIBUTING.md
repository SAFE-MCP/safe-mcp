# Contributors Guide

Welcome to the SAFE-MCP project! We appreciate your interest in contributing to this framework for documenting and mitigating security threats in the Model Context Protocol ecosystem.

## Code of Conduct

This project follows the [CNCF Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project, you agree to abide by its terms. Please read the full text to understand what actions will and will not be tolerated.

## Licensing

This project uses a dual licensing structure:
- **Documentation** (including threat descriptions, markdown files, and written content) is licensed under [CC BY 4.0](LICENSE-CC-BY-4.0)
- **Code** (including scripts, detection rules, and software) is licensed under [Apache 2.0](LICENSE-APACHE-2.0)

By contributing, you agree that your contributions will be licensed under the applicable license based on the type of content.

## Developer Certificate of Origin (DCO)

All contributions to this repository MUST be signed off using the Developer Certificate of Origin (DCO). This is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project.

### DCO Sign-Off

To sign off your commits, use the `-s` or `--signoff` option when committing:

```bash
git commit -s -m "Your commit message"
```

This will add a sign-off message at the end of your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

The sign-off certifies that you agree with the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## How to Contribute

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the existing patterns and style
3. **Test your changes** if applicable
4. **Sign off your commits** using `git commit -s`
5. **Submit a pull request** with a clear description of your changes

## Types of Contributions

We welcome various types of contributions:

- **New Techniques**: Document new attack techniques following the [template](techniques/TEMPLATE.md)
- **Mitigations**: Add or improve mitigation strategies
- **Detection Rules**: Contribute Sigma rules or other detection mechanisms
- **Documentation**: Improve existing documentation or add examples
- **Code**: Scripts, tools, or automation for the framework
- **Bug Reports**: Report issues or inaccuracies
- **Reviews**: Review and provide feedback on pull requests

## Attribution and Version History

Contributors who make meaningful changes to technique documentation should add themselves to the Version History section at the bottom of the document. This ensures proper attribution for your work.

### Version History Format

Each technique document includes a Version History table. When you make significant contributions, add a new row:

```markdown
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-02 | Initial documentation | Your Name |
| 1.1 | 2025-01-15 | Added detection rules and mitigations | Your Name |
```

Include:
- **Version**: Increment the minor version (e.g., 1.0 → 1.1) for additions/improvements, major version (e.g., 1.1 → 2.0) for significant rewrites
- **Date**: Use YYYY-MM-DD format
- **Changes**: Brief, clear description of what you added or changed
- **Author**: Your name as you'd like to be credited
  - You may include your organization if comfortable: `Your Name, Organization`
  - If you prefer not to receive individual attribution, use: `The SAFE-MCP Authors`

## Questions?

If you have questions about contributing, please open an issue for discussion.

Thank you for contributing to SAFE-MCP!