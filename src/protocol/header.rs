use bitflags::bitflags;

#[repr(u8)]
#[non_exhaustive]
pub enum MajorVersion {
    TheOnlyVersion = 0xC,
}

#[repr(u8)]
#[non_exhaustive]
pub enum MinorVersion {
    Default = 0x0,
    V1 = 0x1,
}

#[repr(u8)]
pub enum PacketType {
    Authentication = 0x1,
    Authorization = 0x2,
    Accounting = 0x3,
}

bitflags! {
    pub struct Flags: u8 {
        const Unencrypted   = 0b00000001;
        const SingleConnect = 0b00000100;
    }
}

pub struct Header {
    major_version: u8,
    minor_version: u8,
    sequence_number: u8,
    flags: Flags,
    session_id: u32,
    length: u32,
}
