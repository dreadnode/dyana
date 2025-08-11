# Dyana

<div align="center">

<img
  src="https://d1lppblt9t2x15.cloudfront.net/logos/5714928f3cdc09503751580cffbe8d02.png"
  alt="Logo"
  align="center"
  width="144px"
  height="144px"
/>

</div>

<h4 align="center">
    <a href="https://pypi.org/project/dyana/" target="_blank">
        <img alt="PyPI - Python Version" src="https://img.shields.io/pypi/pyversions/dyana">
        <img alt="PyPI - Version" src="https://img.shields.io/pypi/v/dyana">
    </a>
    <a href="https://github.com/dreadnode/dyana/blob/main/LICENSE" target="_blank">
        <img alt="GitHub License" src="https://img.shields.io/github/license/dreadnode/dyana">
    </a>
    <a href="https://github.com/dreadnode/dyana/actions/workflows/ci.yml">
        <img alt="GitHub Actions Workflow Status" src="https://github.com/dreadnode/dyana/actions/workflows/ci.yml/badge.svg">
    </a>
    <a href="https://github.com/dreadnode/dyana/actions/workflows/renovate.json5/badge.svg">
        <img alt="Renovate Status" src="https://github.com/dreadnode/dyana/actions/workflows/renovate.json5">
    </a>
</h4>

Dyana is a sandbox environment using Docker and [Tracee](https://github.com/aquasecurity/tracee) for loading, running and profiling a wide range of files, including machine learning models, ELF executables, Pickle serialized files, Javascripts [and more](https://docs.dreadnode.io/open-source/dyana/topics/loaders). It provides detailed insights into GPU memory usage, filesystem interactions, network requests, and security related events.

## Installation

Install with:

```bash
pip install dyana
```

To upgrade to the latest version, run:

```bash
pip install --upgrade dyana
```

To uninstall, run:

```bash
pip uninstall dyana
```

## Usage

See our docs on dyana usage [here](https://docs.dreadnode.io/open-source/dyana/basic-usage)

## License

Dyana is released under the [MIT license](LICENSE). Tracee is released under the [Apache 2.0 license](third_party_licenses/APACHE2.md).
