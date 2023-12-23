//! # Rathernet CSMA/CD
//! Rathernet CSMA/CD is used to handle multiple access to the medium. The medium is a shared
//! channel available to multiple nodes. The implementation of Rathernet CSMA/CD is based on
//! WarpMac.
//! ## Frame structure
//! Ather: the frame structure of ather is the actual frame structure transmitted in the medium.
//! | Preamble (PREAMBLE_SYMBOL_LEN bits) | Length (LENGTH_BITS_LEN) | Payload (<= ATHER_PAYLOAD_BITS_LEN) |
//! CSMA/CA: the frame structure of CSMA/CA resides in the payload of ather frames.
//! | Dest (ADDRESS_BITS_LEN) | Src (ADDRESS_BITS_LEN) | Seq (SEQ_BITS_LEN) | Type (TYPE_BITS_LEN) |
//! | Flag (FLAG_BITS_LEN) | Payload (<= PAYLOAD_BITS_LEN) | Parity (PARITY_BITS_LEN) |

use crate::rather::builtin::PAYLOAD_BITS_LEN as ATHER_PAYLOAD_BITS_LEN;
use crc::{Crc, CRC_16_IBM_SDLC};
use std::time::Duration;

pub const ADDRESS_BITS_LEN: usize = 4;
pub const SEQ_BITS_LEN: usize = 8;
pub const TYPE_BITS_LEN: usize = 4;
pub const FLAG_BITS_LEN: usize = 4;

pub const PARITY_ALGORITHM: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_SDLC);
pub const PARITY_BITS_LEN: usize = 16;

pub const PAYLOAD_BITS_LEN: usize = ATHER_PAYLOAD_BITS_LEN
    - ADDRESS_BITS_LEN
    - ADDRESS_BITS_LEN
    - SEQ_BITS_LEN
    - TYPE_BITS_LEN
    - FLAG_BITS_LEN
    - PARITY_BITS_LEN;

pub const SOCKET_SLOT_TIMEOUT: Duration = Duration::from_millis(85);
pub const SOCKET_ACK_TIMEOUT: Duration = Duration::from_millis(30);
pub const SOCKET_RECIEVE_TIMEOUT: Duration = Duration::from_millis(25);

pub const SOCKET_MAX_RESENDS: usize = 8;
pub const SOCKET_MAX_RANGE: usize = 6;
pub const SOCKET_JAR_CAPACITY: usize = 4;

pub const SOCKET_FREE_THRESHOLD: f32 = 1e-5;
pub const SOCKET_COLISION_THRESHOLD: f32 = 1e-4;

pub const SOCKET_PERF_INTERVAL: Duration = Duration::from_millis(1000);
pub const SOCKET_PERF_TIMEOUT: Duration = Duration::from_millis(4000);
pub const SOCKET_PING_INTERVAL: Duration = Duration::from_millis(4000);
pub const SOCKET_PING_TIMEOUT: Duration = Duration::from_millis(2000);

pub const SOCKET_BROADCAST_ADDRESS: usize = (1 << ADDRESS_BITS_LEN) - 1;
