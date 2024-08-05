use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

use aya_obj::generated::bpf_attach_type::BPF_PERF_EVENT;

use crate::{
    bpf::{FEATURES, PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF},
    programs::{
        links::{FdLink, Link},
        probe::{detach_debug_fs, ProbeEvent},
        ProgramError,
    },
    sys::{bpf_link_create, perf_event::perf_event_ioctl, LinkTarget, SysResult, SyscallError},
};

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum PerfLinkIdInner {
    FdLinkId(<FdLink as Link>::Id),
    PerfLinkId(<PerfLink as Link>::Id),
}

#[derive(Debug)]
pub(crate) enum PerfLinkInner {
    FdLink(FdLink),
    PerfLink(PerfLink),
}

impl Link for PerfLinkInner {
    type Id = PerfLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::FdLink(link) => PerfLinkIdInner::FdLinkId(link.id()),
            Self::PerfLink(link) => PerfLinkIdInner::PerfLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::FdLink(link) => link.detach(),
            Self::PerfLink(link) => link.detach(),
        }
    }
}

/// The identifer of a PerfLink.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct PerfLinkId(RawFd);

/// The attachment type of PerfEvent programs.
#[derive(Debug)]
pub struct PerfLink {
    perf_fd: OwnedFd,
    event: Option<ProbeEvent>,
}

impl Link for PerfLink {
    type Id = PerfLinkId;

    fn id(&self) -> Self::Id {
        PerfLinkId(self.perf_fd.as_raw_fd())
    }

    fn detach(self) -> Result<(), ProgramError> {
        let Self { perf_fd, event } = self;
        let _: SysResult<_> = perf_event_ioctl(perf_fd.as_fd(), PERF_EVENT_IOC_DISABLE, 0);
        info!(
            "perf_link_detach: perf_fd: {:?}, event: {:?}",
            perf_fd, event
        );
        if let Some(event) = event {
            info!("perf_link_detach: detaching debugfs event: {:?}", event);
            let _: Result<_, _> = detach_debug_fs(event);
        }
        Ok(())
    }
}

pub(crate) fn perf_attach(
    prog_fd: BorrowedFd<'_>,
    fd: OwnedFd,
) -> Result<PerfLinkInner, ProgramError> {
    info!("perf_attach: prog_fd: {:?}, fd: {:?}", prog_fd, fd);
    if FEATURES.bpf_perf_link() {
        let link_fd = bpf_link_create(prog_fd, LinkTarget::Fd(fd.as_fd()), BPF_PERF_EVENT, None, 0)
            .map_err(|(_, io_error)| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
        Ok(PerfLinkInner::FdLink(FdLink::new(link_fd)))
    } else {
        perf_attach_either(prog_fd, fd, None)
    }
}

pub(crate) fn perf_attach_debugfs(
    prog_fd: BorrowedFd<'_>,
    fd: OwnedFd,
    event: ProbeEvent,
) -> Result<PerfLinkInner, ProgramError> {
    perf_attach_either(prog_fd, fd, Some(event))
}

fn perf_attach_either(
    prog_fd: BorrowedFd<'_>,
    fd: OwnedFd,
    event: Option<ProbeEvent>,
) -> Result<PerfLinkInner, ProgramError> {
    perf_event_ioctl(fd.as_fd(), PERF_EVENT_IOC_SET_BPF, prog_fd.as_raw_fd()).map_err(
        |(_, io_error)| SyscallError {
            call: "PERF_EVENT_IOC_SET_BPF",
            io_error,
        },
    )?;
    perf_event_ioctl(fd.as_fd(), PERF_EVENT_IOC_ENABLE, 0).map_err(|(_, io_error)| {
        SyscallError {
            call: "PERF_EVENT_IOC_ENABLE",
            io_error,
        }
    })?;

    Ok(PerfLinkInner::PerfLink(PerfLink { perf_fd: fd, event }))
}