use std::path::Path;

use anyhow::Result;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::fs::{self, OpenOptions};
    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result};
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };
    use log::info;
    use nix::errno::Errno;
    use nix::libc;
    use nix::sys::memfd::{MFdFlags, memfd_create};
    use nix::sys::prctl;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
    use rustix::thread::{SecureComputingMode, secure_computing_mode};
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompFilter, TargetArch, apply_filter_all_threads,
    };

    #[cfg(target_arch = "x86_64")]
    const TARGET_ARCH: TargetArch = TargetArch::x86_64;

    #[cfg(target_arch = "aarch64")]
    const TARGET_ARCH: TargetArch = TargetArch::aarch64;

    #[cfg(target_arch = "riscv64")]
    const TARGET_ARCH: TargetArch = TargetArch::riscv64;

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    compile_error!("preauth seccomp sandbox currently supports x86_64, aarch64, and riscv64");

    pub fn enable_no_new_privs() -> Result<()> {
        prctl::set_no_new_privs().context("failed to set no_new_privs")
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
        let socket_eperm = socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .is_err_and(|error| error == Errno::EPERM);

        let seccomp_mode =
            match secure_computing_mode().context("failed to query the seccomp mode")? {
                SecureComputingMode::Disabled => 0,
                SecureComputingMode::Strict => 1,
                SecureComputingMode::Filter => 2,
            };

        Ok(format!(
            "read_ok={}\nwrite_denied={}\nexec_denied={}\nsocket_eperm={}\nseccomp_mode={}\n",
            u8::from(!read_back.is_empty() || authorized_keys_file.exists()),
            u8::from(write_denied),
            u8::from(exec_denied),
            u8::from(socket_eperm),
            seccomp_mode
        ))
    }

    pub fn internal_default_deny_probe(authorized_keys_file: &Path) -> Result<()> {
        enable_no_new_privs()?;
        apply_preauth_sandbox(authorized_keys_file)?;

        let name = CString::new("narrowd-seccomp-default-deny-probe")
            .expect("probe CString should not contain interior NUL bytes");
        let _ = memfd_create(name.as_c_str(), MFdFlags::empty());
        Ok(())
    }

    fn install_authorized_keys_landlock(authorized_keys_file: &Path) -> Result<PathBuf> {
        let authorized_keys_root =
            nearest_existing_directory(authorized_keys_file).with_context(|| {
                format!(
                    "failed to find an existing directory for {}",
                    authorized_keys_file.display()
                )
            })?;
        let allowed_access = AccessFs::ReadFile | AccessFs::ReadDir;
        let status = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .context("failed to configure the Landlock ABI v1 access rights")?
            .create()
            .context("failed to create the Landlock ruleset")?
            .add_rule(PathBeneath::new(
                PathFd::new(&authorized_keys_root).with_context(|| {
                    format!(
                        "failed to open sandbox root {} for Landlock",
                        authorized_keys_root.display()
                    )
                })?,
                allowed_access,
            ))
            .with_context(|| {
                format!(
                    "failed to add a Landlock read-only rule for {}",
                    authorized_keys_root.display()
                )
            })?
            .restrict_self()
            .context("failed to apply the Landlock pre-auth sandbox")?;

        if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
            anyhow::bail!("Landlock sandbox was not fully enforced: {status:?}");
        }

        Ok(authorized_keys_root)
    }

    fn install_preauth_seccomp_filter() -> Result<()> {
        let (errno_filter, allowlist_filter) = build_preauth_seccomp_filters()?;

        // Installing the errno filter first leaves seccomp(2) available long
        // enough to install the final default-deny allowlist. The two stacked
        // filters then enforce the same combined policy as a single filter.
        apply_filter_all_threads(&errno_filter)
            .context("failed to install the pre-auth seccomp errno filter")?;
        apply_filter_all_threads(&allowlist_filter)
            .context("failed to install the pre-auth seccomp allowlist")?;
        Ok(())
    }

    fn build_preauth_seccomp_filters() -> Result<(BpfProgram, BpfProgram)> {
        let errno_filter = compile_seccomp_filter(
            errno_syscalls().iter().copied(),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
        )
        .context("failed to compile the pre-auth seccomp errno filter")?;

        // The allowlist must include errno-handled syscalls so their EPERM
        // result wins over this filter's default KillProcess result.
        let allowlist_filter = compile_seccomp_filter(
            allowed_syscalls().iter().chain(errno_syscalls()).copied(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
        )
        .context("failed to compile the pre-auth seccomp allowlist")?;

        Ok((errno_filter, allowlist_filter))
    }

    fn compile_seccomp_filter(
        syscalls: impl IntoIterator<Item = libc::c_long>,
        mismatch_action: SeccompAction,
        match_action: SeccompAction,
    ) -> Result<BpfProgram> {
        let rules: BTreeMap<_, _> = syscalls
            .into_iter()
            .map(|syscall_number| (syscall_number, Vec::new()))
            .collect();
        let filter = SeccompFilter::new(rules, mismatch_action, match_action, TARGET_ARCH)?;
        filter.try_into().map_err(Into::into)
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn preauth_seccomp_filter_is_default_deny() {
            let (_, allowlist_filter) = build_preauth_seccomp_filters().unwrap();
            assert_eq!(
                allowlist_filter.last().map(|instruction| instruction.k),
                Some(u32::from(SeccompAction::KillProcess))
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
    Ok("read_ok=1\nwrite_denied=0\nexec_denied=0\nsocket_eperm=0\nseccomp_mode=0\n".to_string())
}

#[cfg(target_os = "linux")]
pub fn internal_preauth_default_deny_probe(authorized_keys_file: &Path) -> Result<()> {
    linux::internal_default_deny_probe(authorized_keys_file)
}

#[cfg(not(target_os = "linux"))]
pub fn internal_preauth_default_deny_probe(_authorized_keys_file: &Path) -> Result<()> {
    Ok(())
}
