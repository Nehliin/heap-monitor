#![no_std]
#![no_main]

use probes::malloc::{MallocEvent, FreeEvent};
use redbpf_probes::uprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut stack_trace: StackTrace = StackTrace::with_max_entries(1024);

#[map]
static mut malloc_event: PerfMap<MallocEvent> = PerfMap::with_max_entries(1024);

#[map]
static mut free_event: PerfMap<FreeEvent> = PerfMap::with_max_entries(1024);

#[uprobe]
fn malloc(regs: Registers) {
    let mut m_event = MallocEvent {
        ptr: regs.ret(),
        stackid: 0,
        size: regs.parm1(),
    };

    unsafe {
        if let Ok(stackid) = stack_trace.stack_id(regs.ctx, BPF_F_USER_STACK as _) {
            m_event.stackid = stackid;
            malloc_event.insert(regs.ctx, &m_event);
        }
    }
}

#[uprobe]
fn calloc(regs: Registers) {
    let mut m_event = MallocEvent {
        stackid: 0,
        ptr: regs.ret(),
        size: regs.parm1() * regs.parm2(),
    };

    unsafe {
        if let Ok(stackid) = stack_trace.stack_id(regs.ctx, BPF_F_USER_STACK as _) {
            m_event.stackid = stackid;
            malloc_event.insert(regs.ctx, &m_event);
        }
    }
}

#[uprobe]
fn free(regs: Registers) {
    let mut f_event = FreeEvent {
        ptr: regs.parm1(),
    };
    unsafe {
        free_event.insert(regs.ctx, &f_event);
    }
}
