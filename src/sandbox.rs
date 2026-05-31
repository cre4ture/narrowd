use std::path::Path;

use anyhow::Result;

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs::{self, OpenOptions};
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};
    use log::info;
    use nix::fcntl::{OFlag, open};
    use nix::libc;
    use nix::sys::stat::Mode;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }

    #[repr(C, packed)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

    const LANDLOCK_HANDLED_ACCESS_FS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    const LANDLOCK_ALLOWED_READ_ACCESS: u64 =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    const SECCOMP_ACTION_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const SECCOMP_ACTION_KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    const SECCOMP_ACTION_ERRNO: u32 = libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32);

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;

    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;

    #[cfg(target_arch = "riscv64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_00F3;

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    compile_error!("preauth seccomp sandbox currently supports x86_64, aarch64, and riscv64");

    pub fn enable_no_new_privs() -> Result<()> {
        let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }

    pub fn apply_preauth_sandbox(authorized_keys_file: &Path) -> Result<()> {
        let authorized_keys_root = install_authorized_keys_landlock(authorized_keys_file)?;
        install_preauth_seccomp_filter()?;
        info!(
            "applied pre-auth sandbox: landlock_root={} seccomp=filter",
            authorized_keys_root.display()
        );
        Ok(())
    }

    pub fn internal_probe(authorized_keys_file: &Path) -> Result<String> {
        enable_no_new_privs()?;
        apply_preauth_sandbox(authorized_keys_file)?;

        let read_back = fs::read_to_string(authorized_keys_file)
            .with_context(|| format!("failed to read {}", authorized_keys_file.display()))?;
        let write_denied = OpenOptions::new()
            .write(true)
            .open(authorized_keys_file)
            .is_err();
        let exec_denied = std::process::Command::new("/bin/true").status().is_err();

        let seccomp_mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
        if seccomp_mode < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(format!(
            "read_ok={}\nwrite_denied={}\nexec_denied={}\nseccomp_mode={}\n",
            u8::from(!read_back.is_empty() || authorized_keys_file.exists()),
            u8::from(write_denied),
            u8::from(exec_denied),
            seccomp_mode
        ))
    }

    pub fn internal_default_deny_probe(authorized_keys_file: &Path) -> Result<()> {
        enable_no_new_privs()?;
        apply_preauth_sandbox(authorized_keys_file)?;

        let name = CString::new("narrowd-seccomp-default-deny-probe")
            .expect("probe CString should not contain interior NUL bytes");
        let _ = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) };
        Ok(())
    }

    fn install_authorized_keys_landlock(authorized_keys_file: &Path) -> Result<PathBuf> {
        let abi = landlock_abi_version()?;
        if abi < 1 {
            anyhow::bail!("Landlock ABI version {abi} is too old for the pre-auth sandbox");
        }

        let ruleset_attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_HANDLED_ACCESS_FS,
            handled_access_net: 0,
            scoped: 0,
        };
        let ruleset_fd = syscall_owned_fd(
            libc::SYS_landlock_create_ruleset,
            &ruleset_attr as *const _ as libc::c_ulong,
            size_of::<LandlockRulesetAttr>() as libc::c_ulong,
            0,
        )
        .context("failed to create Landlock ruleset")?;

        let authorized_keys_root =
            nearest_existing_directory(authorized_keys_file).with_context(|| {
                format!(
                    "failed to find an existing directory for {}",
                    authorized_keys_file.display()
                )
            })?;
        let root_fd = open(
            &authorized_keys_root,
            OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY,
            Mode::empty(),
        )
        .with_context(|| {
            format!(
                "failed to open sandbox root {} for Landlock",
                authorized_keys_root.display()
            )
        })?;
        let path_rule = LandlockPathBeneathAttr {
            allowed_access: LANDLOCK_ALLOWED_READ_ACCESS,
            parent_fd: root_fd.as_raw_fd(),
        };

        syscall_no_ret(
            libc::SYS_landlock_add_rule,
            ruleset_fd.as_raw_fd() as libc::c_ulong,
            LANDLOCK_RULE_PATH_BENEATH as libc::c_ulong,
            &path_rule as *const _ as libc::c_ulong,
            0,
        )
        .with_context(|| {
            format!(
                "failed to add a Landlock read-only rule for {}",
                authorized_keys_root.display()
            )
        })?;

        syscall_no_ret(
            libc::SYS_landlock_restrict_self,
            ruleset_fd.as_raw_fd() as libc::c_ulong,
            0,
            0,
            0,
        )
        .context("failed to apply the Landlock pre-auth sandbox")?;

        Ok(authorized_keys_root)
    }

    fn install_preauth_seccomp_filter() -> Result<()> {
        let mut instructions = build_preauth_seccomp_instructions();

        let mut program = libc::sock_fprog {
            len: instructions.len() as u16,
            filter: instructions.as_mut_ptr(),
        };

        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
                libc::SECCOMP_FILTER_FLAG_TSYNC as libc::c_ulong,
                &mut program as *mut _ as libc::c_ulong,
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
                .context("failed to install the pre-auth seccomp filter")
        }
    }

    fn build_preauth_seccomp_instructions() -> Vec<libc::sock_filter> {
        let mut instructions = vec![
            bpf_stmt(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                std::mem::offset_of!(libc::seccomp_data, arch) as u32,
            ),
            bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                AUDIT_ARCH_NATIVE,
                1,
                0,
            ),
            bpf_ret(SECCOMP_ACTION_KILL_PROCESS),
            bpf_stmt(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                std::mem::offset_of!(libc::seccomp_data, nr) as u32,
            ),
        ];

        // Return EPERM for operations we intentionally want callers to see as
        // rejected, rather than killing the whole parser process.
        append_syscall_rules(&mut instructions, errno_syscalls(), SECCOMP_ACTION_ERRNO);

        // Everything else must be explicitly allowed. Any syscall that falls
        // through this table kills the process.
        append_syscall_rules(&mut instructions, allowed_syscalls(), SECCOMP_ACTION_ALLOW);

        instructions.push(bpf_ret(SECCOMP_ACTION_KILL_PROCESS));
        instructions
    }

    fn append_syscall_rules(
        instructions: &mut Vec<libc::sock_filter>,
        syscall_numbers: &[libc::c_long],
        action: u32,
    ) {
        for &syscall_nr in syscall_numbers {
            instructions.push(bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                syscall_nr as u32,
                0,
                1,
            ));
            instructions.push(bpf_ret(action));
        }
    }

    fn bpf_stmt(code: libc::c_uint, k: u32) -> libc::sock_filter {
        unsafe { libc::BPF_STMT(code as u16, k) }
    }

    fn bpf_jump(code: libc::c_uint, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        unsafe { libc::BPF_JUMP(code as u16, k, jt, jf) }
    }

    fn bpf_ret(action: u32) -> libc::sock_filter {
        bpf_stmt(libc::BPF_RET | libc::BPF_K, action)
    }

    fn errno_syscalls() -> &'static [libc::c_long] {
        &[
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_ptrace,
            libc::SYS_process_vm_writev,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_userfaultfd,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
            libc::SYS_open_by_handle_at,
            libc::SYS_setns,
            libc::SYS_unshare,
        ]
    }

    fn allowed_syscalls() -> &'static [libc::c_long] {
        &[
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_brk,
            libc::SYS_clock_gettime,
            libc::SYS_close,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_pwait2,
            libc::SYS_epoll_wait,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_fcntl,
            libc::SYS_futex,
            libc::SYS_getrandom,
            libc::SYS_getsockopt,
            libc::SYS_ioctl,
            libc::SYS_lseek,
            libc::SYS_madvise,
            libc::SYS_mlock,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_mremap,
            libc::SYS_munlock,
            libc::SYS_munmap,
            libc::SYS_newfstatat,
            libc::SYS_openat,
            libc::SYS_prctl,
            libc::SYS_read,
            libc::SYS_readv,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            libc::SYS_rseq,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sendmsg,
            libc::SYS_sendto,
            libc::SYS_set_robust_list,
            libc::SYS_setsockopt,
            libc::SYS_shutdown,
            libc::SYS_sigaltstack,
            libc::SYS_socketpair,
            libc::SYS_statx,
            libc::SYS_write,
            libc::SYS_writev,
        ]
    }

    fn landlock_abi_version() -> Result<i32> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                0,
                0,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };

        if result >= 0 {
            return Ok(result as i32);
        }

        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
                Err(error).context("Landlock is not available on this kernel")
            }
            _ => Err(error).context("failed to query the Landlock ABI version"),
        }
    }

    fn nearest_existing_directory(path: &Path) -> Result<PathBuf> {
        let mut current = if path.is_dir() {
            path.to_path_buf()
        } else {
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| path.to_path_buf())
        };

        loop {
            if current.is_dir() {
                return Ok(current);
            }

            let Some(parent) = current.parent() else {
                anyhow::bail!("no existing directory found for {}", path.display());
            };
            current = parent.to_path_buf();
        }
    }

    fn syscall_owned_fd(
        number: libc::c_long,
        arg1: libc::c_ulong,
        arg2: libc::c_ulong,
        arg3: libc::c_ulong,
    ) -> Result<OwnedFd> {
        let fd = unsafe { libc::syscall(number, arg1, arg2, arg3) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    fn syscall_no_ret(
        number: libc::c_long,
        arg1: libc::c_ulong,
        arg2: libc::c_ulong,
        arg3: libc::c_ulong,
        arg4: libc::c_ulong,
    ) -> Result<()> {
        let result = unsafe { libc::syscall(number, arg1, arg2, arg3, arg4) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn preauth_seccomp_filter_is_default_deny() {
            let instructions = build_preauth_seccomp_instructions();
            assert_eq!(
                instructions.last().map(|instruction| instruction.k),
                Some(SECCOMP_ACTION_KILL_PROCESS)
            );
        }

        #[test]
        fn preauth_seccomp_filter_keeps_dangerous_syscalls_out_of_allowlist() {
            assert!(!allowed_syscalls().contains(&libc::SYS_socket));
            assert!(!allowed_syscalls().contains(&libc::SYS_connect));
            assert!(!allowed_syscalls().contains(&libc::SYS_clone3));
            assert!(!allowed_syscalls().contains(&libc::SYS_execve));
            assert!(errno_syscalls().contains(&libc::SYS_socket));
            assert!(errno_syscalls().contains(&libc::SYS_connect));
            assert!(errno_syscalls().contains(&libc::SYS_clone3));
            assert!(errno_syscalls().contains(&libc::SYS_execve));
        }

        #[test]
        fn preauth_seccomp_filter_allows_linux_thread_registration_syscalls() {
            assert!(allowed_syscalls().contains(&libc::SYS_set_robust_list));
            assert!(allowed_syscalls().contains(&libc::SYS_rseq));
        }
    }
}

#[cfg(target_os = "linux")]
pub fn enable_no_new_privs() -> Result<()> {
    linux::enable_no_new_privs()
}

#[cfg(not(target_os = "linux"))]
pub fn enable_no_new_privs() -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply_preauth_sandbox(authorized_keys_file: &Path) -> Result<()> {
    linux::apply_preauth_sandbox(authorized_keys_file)
}

#[cfg(not(target_os = "linux"))]
pub fn apply_preauth_sandbox(_authorized_keys_file: &Path) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn internal_preauth_probe(authorized_keys_file: &Path) -> Result<String> {
    linux::internal_probe(authorized_keys_file)
}

#[cfg(not(target_os = "linux"))]
pub fn internal_preauth_probe(_authorized_keys_file: &Path) -> Result<String> {
    Ok("read_ok=1\nwrite_denied=0\nexec_denied=0\nseccomp_mode=0\n".to_string())
}

#[cfg(target_os = "linux")]
pub fn internal_preauth_default_deny_probe(authorized_keys_file: &Path) -> Result<()> {
    linux::internal_default_deny_probe(authorized_keys_file)
}

#[cfg(not(target_os = "linux"))]
pub fn internal_preauth_default_deny_probe(_authorized_keys_file: &Path) -> Result<()> {
    Ok(())
}
