pub use self::inner::*;

#[derive(Debug, thiserror::Error)]
pub enum SingletonProcessError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(target_os = "windows")]
    #[error("Windows error: {0}")]
    Windows(windows::core::Error),

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[error("POSIX error: {0}")]
    Posix(#[from] nix::errno::Errno),
}

type Result<T> = std::result::Result<T, SingletonProcessError>;

#[cfg(target_os = "windows")]
mod inner {
    use std::env::current_exe;
    use std::mem::size_of_val;

    use windows::core::PCSTR;
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Memory::{CreateFileMappingA, MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, FILE_MAP_WRITE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    use crate::SingletonProcessError;

    pub struct SingletonProcess {
        _h_mapping: windows::core::Owned<HANDLE>,
    }

    impl SingletonProcess {
        pub fn try_new(name: Option<&str>, keep_new_process: bool) -> crate::Result<Self> {
            let this_pid = std::process::id();
            let pid_size = size_of_val(&this_pid);

            let mapping_name = format!("Global\\{}\0", name.unwrap_or(&current_exe()?.file_name().unwrap().to_string_lossy()));

            unsafe {
                let h_mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, pid_size as _, PCSTR(mapping_name.as_ptr()))?;
                let mapped_buffer = MapViewOfFile(h_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, pid_size);
                let mapped_value = mapped_buffer.Value as *mut _;

                if GetLastError() == ERROR_ALREADY_EXISTS {
                    let other_pid = *mapped_value;
                    assert_ne!(other_pid, 0);

                    if other_pid != this_pid {
                        if keep_new_process {
                            let h_other_proc = OpenProcess(PROCESS_TERMINATE, false, other_pid)?;
                            TerminateProcess(h_other_proc, 0)?;
                        } else {
                            std::process::exit(0);
                        }
                    }
                }

                *mapped_value = this_pid;
                UnmapViewOfFile(mapped_buffer)?;

                Ok(SingletonProcess {
                    _h_mapping: windows::core::Owned::new(h_mapping),
                })
            }
        }
    }

    impl From<windows::core::Error> for SingletonProcessError {
        fn from(e: windows::core::Error) -> Self {
            SingletonProcessError::Windows(e)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod inner {
    use std::env::{current_exe, temp_dir};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, Write};
    use std::mem::size_of_val;

    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    pub struct SingletonProcess {
        _file_lock: Flock<File>,
    }

    impl SingletonProcess {
        pub fn try_new(name: Option<&str>, keep_new_process: bool) -> crate::Result<Self> {
            type PidType = u32;

            let this_pid: PidType = std::process::id();
            let pid_size = size_of_val(&this_pid);

            let lock_file_name = temp_dir().join(format!("{}_singleton_process.lock", name.unwrap_or(&current_exe()?.file_name().unwrap().to_string_lossy())));
            let lock_file = OpenOptions::new().read(true).write(true).create(true).open(&lock_file_name)?;

            let (mut file_lock, is_first) = match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
                Ok(lock) => {
                    lock.relock(FlockArg::LockSharedNonblock)?;
                    lock.set_len(pid_size as _)?;

                    (lock, true)
                }
                Err((f, Errno::EAGAIN)) => (Flock::lock(f, FlockArg::LockSharedNonblock).map_err(|(_, e)| e)?, false),
                Err((_, e)) => Err(e)?,
            };

            if !is_first {
                let mut pid_buffer = this_pid.to_le_bytes();
                file_lock.read_exact(&mut pid_buffer)?;
                file_lock.rewind()?;

                let other_pid = PidType::from_le_bytes(pid_buffer);
                assert_ne!(other_pid, 0);

                if other_pid != this_pid {
                    if keep_new_process {
                        kill(Pid::from_raw(other_pid as _), Signal::SIGTERM).ok();
                    } else {
                        std::process::exit(0);
                    }
                }
            }

            file_lock.write(&this_pid.to_le_bytes())?;

            Ok(Self { _file_lock: file_lock })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use if_chain::if_chain;

    use super::*;

    fn get_parent_process_exe(system: &mut sysinfo::System) -> Option<PathBuf> {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

        system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet));

        if_chain! {
            if let Ok(current_pid) = sysinfo::get_current_pid();
            if let Some(current_process) = system.process(current_pid);
            if let Some(parent_pid) = current_process.parent();
            if let Some(parent_process) = system.process(parent_pid);
            then {
                parent_process.exe().map(|p| p.to_path_buf())
            } else {
                None
            }
        }
    }

    #[test]
    fn test_with_name() -> Result<()> {
        SingletonProcess::try_new(Some(&"my_unique_name"), true)?;

        Ok(())
    }

    #[test]
    fn test_reentrant() -> Result<()> {
        std::mem::forget(SingletonProcess::try_new(None, true)?);
        std::mem::forget(SingletonProcess::try_new(None, false)?);

        Ok(())
    }

    #[test]
    #[function_name::named]
    fn test_keep_old_process() -> Result<()> {
        let mut system = sysinfo::System::new();
        let parent_exe_pre = get_parent_process_exe(&mut system);
        std::mem::forget(SingletonProcess::try_new(None, false)?);
        let current_exe = std::env::current_exe()?;

        if let Some(p) = parent_exe_pre {
            assert_ne!(p, current_exe);
        }

        let mut cmd = Command::new(current_exe);
        cmd.arg(function_name!());
        assert!(cmd.status()?.success());

        Ok(())
    }

    #[test]
    #[function_name::named]
    fn test_keep_new_process() -> Result<()> {
        let mut system = sysinfo::System::new();
        let parent_exe_pre = get_parent_process_exe(&mut system);
        std::mem::forget(SingletonProcess::try_new(None, true)?);
        let current_exe = std::env::current_exe()?;

        if_chain! {
            if let Some(p) = parent_exe_pre;
            if p == current_exe;
            then {
                assert!(get_parent_process_exe(&mut system).is_none());
            } else {
                use nix::sys::signal::*;

                extern "C" fn exit_on_sigterm(_signal: i32) {
                    std::process::exit(0);
                }

                // make process exit gracefully on SIGTERM to avoid test failure
                unsafe { signal(Signal::SIGTERM, SigHandler::Handler(exit_on_sigterm)).unwrap(); }

                let mut cmd = Command::new(current_exe);
                cmd.arg(function_name!());
                cmd.status()?;
            }
        }

        Ok(())
    }
}
