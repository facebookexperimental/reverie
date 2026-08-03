# SaBRe 2.0

[![Build Status](https://app.travis-ci.com/srg-imperial/SaBRe.svg?branch=master)](https://app.travis-ci.com/srg-imperial/SaBRe)

SaBRe is a modular selective binary rewriter.
It is able to rewrite system calls, vDSO and named functions.
We currently support two architectures: `x86_64` and `RISC-V`.
We provide three plugins:

* *sbr-id*: intercepts system calls but does not do any processing -- mainly aimed at testing
* *sbr-trace*: a fast system-call tracer that mimics the original `strace` output
* *sbr-scfuzzer*: a parametric fault injector to fuzz system calls

SaBRe has two different system architectures. SaBRe 1.0 currently lives under [branch sabre_1.0](https://github.com/srg-imperial/SaBRe/tree/sabre_1.0) of this repo, while SaBRe 2.0 is the current main branch. For the differences between the two systems, look at section [SaBRe 1.0 vs 2.0](#sabre-10-vs-20). To learn more about the implementation details read our papers in [SaBRe research and papers](#sabre-research-and-papers).

## Building SaBRe

---

### Quick start and requirements

SaBRe execution does not rely on any third-party library.
However, SaBRe requires `cmake`, `make` and `gcc` for building.
To quickly get started, run:

```bash
git clone https://github.com/srg-imperial/SaBRe
cd SaBRe
mkdir build
cd build
cmake ..
make
```

The executable will be located at `./sabre` assuming you are in the build
directory you just created.
The compiled plugins will lie in separate subfolders under `plugins/`.
For instance, to run the `ls` command under the `sbr-trace` plugin:

```bash
./sabre plugins/sbr-trace/libsbr-trace.so -- /bin/ls
```

---

### Compiling SaBRe executable

`gcc` is recommended for compiling SaBRe.
Also the build system uses `cmake` and `make`.
So if you do not have them installed, use your package manager, e.g. for Debian/Ubuntu:

```bash
sudo apt install cmake make gcc
```

You can [download a snapshot of the repository](https://github.com/srg-imperial/SaBRe/archive/master.zip) or clone it if you have `git` installed:

```bash
git clone https://github.com/srg-imperial/SaBRe
```

The following build instructions assume that you are currently in the top level directory
of your copy of the SaBRe repository:

```bash
cd SaBRe
mkdir build
cd build
cmake ..
make
```

The sequel assumes the working directory is still `build/`.
If everything goes well, the executable will be located at `./sabre`.

---

### Running SaBRe

The general syntax to invoke SaBRe is:

```bash
SaBRe <PLUGIN> [<PLUGIN_OPTIONS>] -- <CLIENT> [<CLIENT_OPTIONS>]
```

Both `PLUGIN` and `CLIENT` denote full paths to, respectively, the plugin library and the client program to be run under SaBRe.
Once built, plugin libraries are located in separate subfolders under `plugins/`.
For instance, the path to the `sbr-trace` library is: `plugins/sbr-trace/libsbr-trace.so`.
As a full working example, if you want to execute the `ls` command under the `sbr-trace` plugin, just run:

```bash
./sabre plugins/sbr-trace/libsbr-trace.so -- /bin/ls
```

---

## How to debug in SaBRe

When using GDB with SaBRe you will notice that when the execution has reached the plugin's or the client's code, GDB is not able to show neither symbols nor source code.
To fix this you will have to load `debug-tools/gdb-symbol-loader.py` in your GDB and then run the registered commands.
SaBRe offers two helper commands:

* `sbr-src`: Loads some paths for the source code of well known libraries like `libc` under Ubuntu 18.04.
* `sbr-sym`: If provided with no arguments, it tries to load the symbols of some well know libraries that SaBRe is currently relocating (e.g. `libc`, `pthreads`, etc.). If strings are provided as arguments, we try to match those with the paths of libraries found in the maps of the running application and load their symbols. `sbr-sym` is using `add-symbol-file` under the hood and thus all restrictions and requirements apply.

---

## SaBRe 1.0 vs 2.0

SaBRe is binary rewriter that loads a user provided plugin into the memory space of a client application. This plugin is called to handle the intercepted system calls or function calls of the client application. The main difference between SaBRe 1.0 and 2.0 is in *which* memory space the plugin lives and operates.

Under SaBRe 1.0 the plugin lives in the memory space of SaBRe. That gives the maximum possible isolation between memory management and called libraries between SaBRe and the client. For example, if you use `malloc` inside the plugin, the memory will be allocated inside the memory arenas of SaBRe, while in 2.0 the plugin uses the same infrastructure as the client. The same difference applies for libraries too. If you choose some `libc` alternative or different version to be loaded with your plugin, SaBRe 1.0 will keep your plugin dependencies separate from the client. SaBRe 2.0 blends the plugin with the dependencies of the underlying client, and thus the same libraries will be used.

SaBRe 1.0 comes with some technical limitations though. Keeping this isolation between client and plugin is not an easy task. For example a custom allocator needs to be properly and carefully used. There are also some other restrictions with respect to multithreading and the TLS. There is currently a long discussion [here](https://github.com/srg-imperial/SaBRe/pull/54) that highlights some of these technical limitations and what effort is required from the plugin developer to overcome them.

If your priority is to maximise memory isolation and library interference, choose SaBRe 1.0. If you want to build complex application we recommend SaBRe 2.0.

---

## SaBRe research and papers

* [The original paper on SaBRe 1.0](https://link.springer.com/content/pdf/10.1007/s10009-021-00644-w.pdf)
* [SaBRe 1.0 limitation discussion](https://github.com/srg-imperial/SaBRe/pull/54)
* [SaBRe 2.0 used in fuzzing](https://arxiv.org/abs/2201.04048)
