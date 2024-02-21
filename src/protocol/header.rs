#[repr(u8)]
pub enum MajorVersion {
    #[non_exhaustive] TheOnlyVersion = 0xC,
}

#[repr(u8)]
pub enum MinorVersion {
    #[non_exhaustive] Default = 0x0,
    #[non_exhaustive] V1 = 0x1,
}

#[repr(u8)]
pub enum PacketType {
    Authentication = 0x1,
    Authorization = 0x2,
    Accounting = 0x3,
}

bitflags! {
    pub struct Flags: u8 {
        Unencrypted   = 0b00000001,
        SingleConnect = 0b00000100, 
    }
}

impl Flags {
    pub fn clear(&mut self) {
        self.bits = 0;
    }
}

pub struct Header {
    majorVersion: u8,
    minorVersion: u8,
    sequenceNumber: u8,
    flags: Flags,
    sessionId: u32,
    length: u32,
}
