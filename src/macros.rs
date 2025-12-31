#![allow(unused_macros)]

macro_rules! trace {
    ($($t:tt)*) => {
        log!(trace, $($t)*)
    }
}

macro_rules! debug {
    ($($t:tt)*) => {
        log!(debug, $($t)*)
    }
}

macro_rules! info {
    ($($t:tt)*) => {
        log!(info, $($t)*)
    }
}

macro_rules! warn {
    ($($t:tt)*) => {
        log!(warn, $($t)*)
    }
}

macro_rules! error {
    ($($t:tt)*) => {
        log!(error, $($t)*)
    }
}

macro_rules! log {
    ($level: ident, $($t:tt)*) => {
        #[cfg(feature = "tracing")]
        { tracing::$level!($($t)*) }
        // Silence unused variables warnings.
        #[cfg(not(feature = "tracing"))]
        { if false { let _ = ( $($t)* ); } }
    }
}
