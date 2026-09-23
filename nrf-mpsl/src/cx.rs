//! Radio coexistence (MPSL CX).
//!
//! MPSL exposes a single coexistence hook, `mpsl_cx_interface_set`, which both
//! the SoftDevice Controller and the IEEE 802.15.4 radio driver call through
//! (`mpsl_cx_request`, `mpsl_cx_release`, ...) before and after every radio
//! operation. Installing a [`CoexInterface`] with
//! [`MultiprotocolServiceLayer::set_coex_interface`] therefore makes every
//! protocol on the MPSL instance ask an external Packet Traffic Arbiter (PTA)
//! for the medium.
//!
//! # Execution context
//!
//! The protocol stacks call the interface from MPSL's high-priority radio
//! context (priority 0 interrupts), from their own lower-priority handlers,
//! and occasionally from thread mode. The C API is not re-entrant per function
//! but any function may preempt any other, so implementations must be
//! lock-free, must not block, and must not log. Touching GPIO registers and
//! atomics is fine.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::error::{Error, RetVal};
use crate::raw;
use crate::MultiprotocolServiceLayer;

/// A set of radio operations, as requested from or granted by a PTA.
///
/// Mirrors `mpsl_cx_op_map_t`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Ops(u8);

impl Ops {
    /// No operation.
    pub const NONE: Ops = Ops(0);
    /// Listening for asynchronous transmissions (`MPSL_CX_OP_IDLE_LISTEN`).
    pub const IDLE_LISTEN: Ops = Ops(raw::MPSL_CX_OP_IDLE_LISTEN as u8);
    /// Active reception (`MPSL_CX_OP_RX`).
    pub const RX: Ops = Ops(raw::MPSL_CX_OP_RX as u8);
    /// Active transmission (`MPSL_CX_OP_TX`).
    pub const TX: Ops = Ops(raw::MPSL_CX_OP_TX as u8);
    /// Every operation.
    pub const ALL: Ops = Ops(Self::IDLE_LISTEN.0 | Self::RX.0 | Self::TX.0);

    /// Builds a set from the raw bitmap. Unknown bits are kept.
    pub const fn from_bits(bits: u8) -> Self {
        Ops(bits)
    }

    /// The raw `mpsl_cx_op_map_t` bitmap.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every operation in `other` is in `self`.
    pub const fn contains(self, other: Ops) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether `self` and `other` share any operation.
    pub const fn intersects(self, other: Ops) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The union of two sets.
    pub const fn union(self, other: Ops) -> Ops {
        Ops(self.0 | other.0)
    }
}

impl core::ops::BitOr for Ops {
    type Output = Ops;
    fn bitor(self, rhs: Ops) -> Ops {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for Ops {
    fn bitor_assign(&mut self, rhs: Ops) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for Ops {
    type Output = Ops;
    fn bitand(self, rhs: Ops) -> Ops {
        Ops(self.0 & rhs.0)
    }
}

impl core::fmt::Debug for Ops {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ops(")?;
        let mut first = true;
        for (op, name) in [(Ops::IDLE_LISTEN, "IDLE_LISTEN"), (Ops::RX, "RX"), (Ops::TX, "TX")] {
            if self.contains(op) {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
        }
        write!(f, ")")
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Ops {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "Ops(idle_listen={}, rx={}, tx={})",
            self.contains(Ops::IDLE_LISTEN),
            self.contains(Ops::RX),
            self.contains(Ops::TX)
        )
    }
}

/// When a request takes effect. Mirrors `MPSL_CX_REQ_TRIG`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Trigger {
    /// The request is signalled during the [`CoexInterface::request`] call.
    Instant,
    /// A trigger value this crate does not know about.
    Unknown(u8),
}

impl Trigger {
    fn from_raw(raw: u8) -> Self {
        match raw as u32 {
            raw::MPSL_CX_REQ_TRIG_INSTANT => Trigger::Instant,
            other => Trigger::Unknown(other as u8),
        }
    }
}

/// A request for the medium, as passed by MPSL to [`CoexInterface::request`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Request {
    /// The operations the radio is about to perform.
    pub ops: Ops,
    /// Priority of the operation. Values above `u8::MAX / 2` are high
    /// priority in a two-level PTA.
    pub prio: u8,
    /// When the request takes effect.
    pub trigger: Trigger,
}

/// A protocol's callback for changes in the granted operations.
///
/// The protocol stacks register one with [`CoexInterface::register_callback`];
/// the PTA driver calls [`GrantCallback::call`] whenever the granted set
/// changes. It may be called from any context but must not preempt itself.
#[derive(Clone, Copy)]
pub struct GrantCallback(unsafe extern "C" fn(granted_ops: raw::mpsl_cx_op_map_t));

impl GrantCallback {
    /// Notifies the protocol that `granted` is the new set of granted operations.
    pub fn call(self, granted: Ops) {
        // SAFETY: MPSL registered this pointer and keeps the function alive for
        // the program's lifetime; the argument is a plain bitmap.
        unsafe { (self.0)(granted.bits()) }
    }

    /// The raw C function pointer.
    pub fn as_raw(self) -> unsafe extern "C" fn(granted_ops: raw::mpsl_cx_op_map_t) {
        self.0
    }

    /// Wraps a raw C function pointer.
    ///
    /// # Safety
    ///
    /// `f` must be safe to call with any op map from the contexts the PTA
    /// driver calls it from.
    pub unsafe fn from_raw(f: unsafe extern "C" fn(granted_ops: raw::mpsl_cx_op_map_t)) -> Self {
        GrantCallback(f)
    }
}

impl core::fmt::Debug for GrantCallback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "GrantCallback({:p})", self.0 as *const ())
    }
}

/// A Packet Traffic Arbiter client: the device-specific half of MPSL's
/// coexistence interface (`mpsl_cx_interface_t`).
///
/// See the [module documentation](self) for the execution-context rules every
/// method must follow.
pub trait CoexInterface: Sync + 'static {
    /// Signals the PTA that the radio is about to perform `request.ops`. Each
    /// call overrides the previous request.
    fn request(&self, request: &Request) -> Result<(), Error>;

    /// Withdraws the last request.
    fn release(&self) -> Result<(), Error>;

    /// The operations the PTA currently allows.
    fn granted_ops(&self) -> Ops;

    /// Microseconds from a [`request`](Self::request) returning to the grant
    /// signal being meaningful; 0 when it is always meaningful.
    fn req_grant_delay_us(&self) -> u32;

    /// Sets (or, with `None`, clears) the callback to notify when the granted
    /// operations change.
    fn register_callback(&self, callback: Option<GrantCallback>);
}

/// The installed interface, type-erased. Written once by
/// [`MultiprotocolServiceLayer::set_coex_interface`].
static INSTANCE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Holds the C vtable for one concrete interface type.
struct VTable<T: CoexInterface>(core::marker::PhantomData<T>);

impl<T: CoexInterface> VTable<T> {
    const METHODS: raw::mpsl_cx_interface_t = raw::mpsl_cx_interface_t {
        p_request: Some(request::<T>),
        p_release: Some(release::<T>),
        p_granted_ops_get: Some(granted_ops_get::<T>),
        p_req_grant_delay_get: Some(req_grant_delay_get::<T>),
        p_register_callback: Some(register_callback::<T>),
    };
}

/// # Safety
///
/// Only called by the trampolines below, which MPSL can reach only after
/// `set_coex_interface::<T>` stored a `&'static T` in `INSTANCE`.
unsafe fn instance<T: CoexInterface>() -> &'static T {
    unsafe { &*(INSTANCE.load(Ordering::Acquire) as *const T) }
}

fn to_c(result: Result<(), Error>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => error.to_retval().into(),
    }
}

unsafe extern "C" fn request<T: CoexInterface>(params: *const raw::mpsl_cx_request_t) -> i32 {
    // SAFETY: MPSL passes either null or a valid request for the call's duration.
    let Some(params) = (unsafe { params.as_ref() }) else {
        return RetVal::EINVAL.into();
    };
    let request = Request {
        ops: Ops::from_bits(params.ops),
        prio: params.prio,
        trigger: Trigger::from_raw(params.trigger),
    };
    to_c(unsafe { instance::<T>() }.request(&request))
}

unsafe extern "C" fn release<T: CoexInterface>() -> i32 {
    to_c(unsafe { instance::<T>() }.release())
}

unsafe extern "C" fn granted_ops_get<T: CoexInterface>(granted: *mut raw::mpsl_cx_op_map_t) -> i32 {
    if granted.is_null() {
        return RetVal::EINVAL.into();
    }
    let ops = unsafe { instance::<T>() }.granted_ops();
    // SAFETY: checked non-null; MPSL passes a valid out-pointer.
    unsafe { granted.write(ops.bits()) };
    0
}

unsafe extern "C" fn req_grant_delay_get<T: CoexInterface>() -> u32 {
    unsafe { instance::<T>() }.req_grant_delay_us()
}

unsafe extern "C" fn register_callback<T: CoexInterface>(cb: raw::mpsl_cx_cb_t) -> i32 {
    unsafe { instance::<T>() }.register_callback(cb.map(GrantCallback));
    0
}

impl MultiprotocolServiceLayer<'_> {
    /// Installs `interface` as MPSL's radio coexistence interface.
    ///
    /// Call this after MPSL is initialized and before building the SoftDevice
    /// Controller or the IEEE 802.15.4 driver: both pick up the interface on
    /// their first radio operation. Only one interface can ever be installed;
    /// a second call returns [`Error::EPERM`].
    pub fn set_coex_interface<T: CoexInterface>(&self, interface: &'static T) -> Result<(), Error> {
        let ptr = interface as *const T as *mut ();
        if INSTANCE
            .compare_exchange(core::ptr::null_mut(), ptr, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::EPERM);
        }
        // `METHODS` is a constant with no interior mutability, so the borrow
        // is promoted to `'static`, which MPSL requires.
        let methods: &'static raw::mpsl_cx_interface_t = &VTable::<T>::METHODS;
        let ret = unsafe { raw::mpsl_cx_interface_set(methods) };
        if let Err(error) = RetVal::from(ret).to_result() {
            INSTANCE.store(core::ptr::null_mut(), Ordering::Release);
            return Err(error);
        }
        Ok(())
    }
}
