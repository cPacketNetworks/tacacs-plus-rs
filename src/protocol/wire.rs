pub trait Wire {
    fn to_buffer(&self) -> Vec<u8>;
}
