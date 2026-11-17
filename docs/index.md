# Overview

Dyana is a sandbox environment using Docker and [Tracee](https://github.com/aquasecurity/tracee) for loading, running, and profiling a wide range of files, including machine learning models, ELF executables, pickle files, JavaScript, and more.

In addition to trace-time inspection, Dyana includes a small host-side planning surface for choosing models that are likely to fit your hardware before you run anything.

It provides visibility into:

- GPU memory usage
- Filesystem interactions
- Network requests
- Security-relevant runtime events
- Model fit recommendations for the current host

## Fit Planning

Use [`dyana fit`](fit.md) to rank a compact set of model recommendations against the current machine's RAM, GPU or unified memory budget, and detected local runtimes such as Ollama or MLX.

## Loaders

Dyana ships with dedicated loaders for different file types. Each loader has its own arguments and executes in an isolated container, offline by default.

See [Loaders](topics/loaders.md) for the full set of supported loaders and examples.

## License

Dyana is released under the [MIT license](https://github.com/dreadnode/dyana/blob/main/LICENSE). Tracee is released under the [Apache 2.0 license](https://github.com/dreadnode/dyana/blob/main/third_party_licenses/APACHE2.md).
