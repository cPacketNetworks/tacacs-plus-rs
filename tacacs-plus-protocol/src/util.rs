/// Generates a display implementation for a bitflag struct that uses flag names.
macro_rules! bitflags_display_impl {
    ($flag_struct:ty) => {
        impl ::core::fmt::Display for $flag_struct {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                if self.is_empty() {
                    write!(f, "no flags set")
                } else {
                    let mut name_iter = self.iter_names();

                    while let Some((name, _)) = name_iter.next() {
                        // space-separate flag names, but don't add trailing space
                        if name_iter.remaining().is_empty() {
                            write!(f, "{name}")?;
                        } else {
                            write!(f, "{name} ")?;
                        }
                    }

                    Ok(())
                }
            }
        }
    };
}

pub(crate) use bitflags_display_impl;

// testing display implementations without allocation is difficult
#[cfg(all(test, feature = "std"))]
mod tests {
    use std::format;

    bitflags::bitflags! {
        struct TestFlags: u8 {
            const FLAG1 = 1;
            const FLAG2 = 2;
        }
    }

    bitflags_display_impl! { TestFlags }

    #[test]
    fn single_flag_no_trailing_space() {
        let single_flag = TestFlags::FLAG1;
        let output = format!("{single_flag}");

        assert_eq!(output, "FLAG1");
    }

    #[test]
    fn two_flags_space_separated() {
        let flags = TestFlags::all();
        let output = format!("{flags}");

        assert_eq!(output, "FLAG1 FLAG2");
    }
}
