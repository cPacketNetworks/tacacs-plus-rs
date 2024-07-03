//! Authorization features/packets of the TACACS+ protocol.

use crate::AsciiStr;

use super::{
    Argument, Arguments, AuthenticationContext, AuthenticationMethod, DeserializeError,
    DeserializeWithArguments, NotEnoughSpace, PacketBody, PacketType, Serialize, UserInformation,
};

#[cfg(test)]
mod tests;

/// An authorization request packet body, including arguments.
pub struct Request<'packet> {
    /// Method used to authenticate to TACACS+ client.
    pub method: AuthenticationMethod,

    /// Other client authentication information.
    pub authentication_context: AuthenticationContext,

    /// Information about the user connected to the TACACS+ client.
    pub user_information: UserInformation<'packet>,

    /// Additional arguments to provide as part of an authorization request.
    pub arguments: Arguments<'packet>,
}

impl PacketBody for Request<'_> {
    const TYPE: PacketType = PacketType::Authorization;
    const MINIMUM_LENGTH: usize =
        AuthenticationMethod::WIRE_SIZE + AuthenticationContext::WIRE_SIZE + 4;
}

impl Serialize for Request<'_> {
    fn wire_size(&self) -> usize {
        AuthenticationMethod::WIRE_SIZE
            + AuthenticationContext::WIRE_SIZE
            + self.user_information.wire_size()
            + self.arguments.wire_size()
    }

    fn serialize_into_buffer(&self, buffer: &mut [u8]) -> Result<usize, NotEnoughSpace> {
        if buffer.len() >= self.wire_size() {
            buffer[0] = self.method as u8;
            self.authentication_context
                .serialize_header_information(&mut buffer[1..4]);
            self.user_information
                .serialize_header_information(&mut buffer[4..7]);

            self.arguments.serialize_header(&mut buffer[7..])?;

            let body_start: usize = Self::MINIMUM_LENGTH + self.arguments.argument_count() as usize;

            let user_information_len = self
                .user_information
                .serialize_body_information(&mut buffer[body_start..]);

            self.arguments
                .serialize_body(&mut buffer[body_start + user_information_len..])?;

            Ok(self.wire_size())
        } else {
            Err(NotEnoughSpace(()))
        }
    }
}

/// The status of an authorization operation, as returned by the server.
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Status {
    /// Authorization passed; server may have additional arguments for the client.
    PassAdd = 0x01,

    /// Authorization passed; server provides argument values to override those provided in the request.
    PassReplace = 0x02,

    /// Authorization request was denied.
    Fail = 0x10,

    /// An error ocurred on the server.
    Error = 0x11,

    /// Forward authorization request to an alternative daemon.
    #[deprecated = "Forwarding to an alternative daemon was deprecated in RFC 8907."]
    Follow = 0x21,
}

impl TryFrom<u8> for Status {
    type Error = DeserializeError;

    fn try_from(value: u8) -> Result<Self, DeserializeError> {
        match value {
            0x01 => Ok(Status::PassAdd),
            0x02 => Ok(Status::PassReplace),
            0x10 => Ok(Status::Fail),
            0x11 => Ok(Status::Error),
            #[allow(deprecated)]
            0x21 => Ok(Status::Follow),
            _ => Err(DeserializeError::InvalidWireBytes),
        }
    }
}

/// The body of an authorization reply packet.
#[derive(PartialEq, Eq, Debug)]
pub struct Reply<'packet> {
    status: Status,
    server_message: AsciiStr<'packet>,
    data: &'packet [u8],
    arguments: Arguments<'packet>,
}

impl<'packet> Reply<'packet> {
    /// Determines the length of a reply packet encoded into the provided buffer, if possible.
    pub fn claimed_length(buffer: &[u8]) -> Option<usize> {
        if buffer.len() >= Self::MINIMUM_LENGTH {
            let argument_count = buffer[1] as usize;

            // also ensure that all argument lengths are present
            if buffer.len() >= Self::MINIMUM_LENGTH + argument_count {
                let (server_message_length, data_length) = Self::extract_field_lengths(buffer)?;
                let encoded_arguments_length: usize = buffer
                    [Self::MINIMUM_LENGTH..Self::MINIMUM_LENGTH + argument_count]
                    .iter()
                    .map(|&length| length as usize)
                    .sum();

                Some(
                    Self::MINIMUM_LENGTH
                        + server_message_length
                        + data_length
                        + argument_count // argument lengths in "header"
                        + encoded_arguments_length,
                )
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Extracts the server message and data lengths from a raw reply packet, if possible.
    fn extract_field_lengths(buffer: &[u8]) -> Option<(usize, usize)> {
        // data length is the last field in the required part of the header, so we need a full (minimal) header
        if buffer.len() >= Self::MINIMUM_LENGTH {
            let server_message_length = u16::from_be_bytes(buffer[2..4].try_into().ok()?);
            let data_length = u16::from_be_bytes(buffer[4..6].try_into().ok()?);

            Some((server_message_length as usize, data_length as usize))
        } else {
            None
        }
    }

    /// The result status of the request.
    pub fn status(&self) -> Status {
        self.status
    }

    /// The message received from the server.
    pub fn server_mesage(&self) -> AsciiStr {
        self.server_message
    }

    /// The domain-specific data received from the server.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// The arguments sent by the server.
    pub fn arguments(&self) -> &Arguments<'packet> {
        &self.arguments
    }
}

impl PacketBody for Reply<'_> {
    const TYPE: PacketType = PacketType::Authorization;
    const MINIMUM_LENGTH: usize = 6;
}

impl<'raw> DeserializeWithArguments<'raw> for Reply<'raw> {
    fn deserialize_from_buffer(
        buffer: &'raw [u8],
        argument_space: &'raw mut [Argument<'raw>],
    ) -> Result<Self, DeserializeError> {
        let claimed_length = Self::claimed_length(buffer).ok_or(DeserializeError::UnexpectedEnd)?;

        if buffer.len() >= claimed_length {
            let status: Status = buffer[0].try_into()?;
            let argument_count = buffer[1] as usize;

            let (server_message_length, data_length) =
                Self::extract_field_lengths(buffer).ok_or(DeserializeError::UnexpectedEnd)?;

            let body_start = 6 + argument_count;
            let data_start = body_start + server_message_length;
            let arguments_start = data_start + data_length;

            let server_message = AsciiStr::try_from_bytes(&buffer[body_start..data_start])
                .ok_or(DeserializeError::InvalidWireBytes)?;
            let data = &buffer[data_start..arguments_start];

            let argument_lengths = &buffer[6..6 + argument_count];
            let total_argument_length: usize = argument_lengths
                .iter()
                .map(|&length| usize::from(length))
                .sum();
            let argument_values = &buffer[arguments_start..arguments_start + total_argument_length];
            let arguments =
                Arguments::deserialize(argument_lengths, argument_values, argument_space)?;

            Ok(Self {
                status,
                server_message,
                data,
                arguments,
            })
        } else {
            Err(DeserializeError::UnexpectedEnd)
        }
    }
}

// TODO: reconciling Request arguments with Reply? (ADD/REPL status)
