## singleton-process

[![Crates.io](https://img.shields.io/crates/v/singleton-process.svg)](https://crates.io/crates/singleton-process)

Ensure only a single process actively running with an associated name. The user can choose whether to keep the existing or subsequent process.

```toml
[dependencies]
singleton-process = '0.1'
```

### Details

The singleton effect is in sync with the lifetime of the `SingletonProcess` object. If the effect is needed throughout the whole process, the object can be "forgotten" with [`std::mem::forget`](https://doc.rust-lang.org/std/mem/fn.forget.html).

Processes with the same `name` are grouped together. If the name is provided, user is responsible to make sure the name is unique only to the desired group of processes, and meets the requirement of the respective platform (see below). If omitted, the running executable's file name is used as the group name, which may not be sufficiently unique.

When subseqent process joins, if user chooses to favor the new process, current distinguished process is terminated by the new process, and the new process becomes the new distinguished process. If user chooses to favor the old process, the subseqent process exits immediately.

On Windows, an unnamed file mapping is created on the [`Global\` namespace](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces). It is then memory mapped and used to hold the distinguished process ID. The handle of the file mapping is held as long as the `SingletonProcess` object is alive.

On Linux, a lock file, created in the temp directory, is used to hold the process ID. The lock is held in sync with the object lifetime.

In both platforms, since the mechanism is tied to kernel objects (file mapping handle on Windows, file lock on Linux), and these kernel objects are automatically released upon process termination,  it is resilient to process crash.

### Platform-specific group name requirement

* Windows: The name can contain any character except the backslash character (\\), with no maximum length.
* Linux: Any name satisfying the underlying file system's requirement.

### Minimum Supported Rust Version

- Library usage: **1.74.0**
- Running tests/contributing: **1.75.0**

### Example

```rust
use singleton_process::SingletonProcess;

fn main() {
    std::mem::forget(SingletonProcess::try_new(None, true).unwrap());
}
```
