pub trait Wire {
    fn to_buffer(&self) -> &[u8];
}
