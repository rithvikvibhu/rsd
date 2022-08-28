use extended_primitives::{Buffer, VarInt};
use handshake_encoding::{Decodable, DecodingError, Encodable};
use handshake_types::{Name, NameHash};

//@todo formatting, and I think common functions to_hex, from_hex.
//@todo testing.
//@when I say formatting I mean Debug and to_string functions.

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OpenCovenant {
    ///The hash of the name for the Open.
    pub name_hash: NameHash,
    ///The height at which the bid occured
    ///The height should always be 0 for an Open.
    pub height: u32,
    ///The raw name that the open is for.
    pub name: Name,
}

impl OpenCovenant {
    pub fn get_items(&self) -> Vec<Buffer> {
        let mut items = Vec::new();

        let mut buffer = Buffer::new();
        buffer.write_hash(self.name_hash);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_u32(self.height);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_str(&self.name);
        items.push(buffer);

        items
    }

    pub fn from_items(mut items: Vec<Buffer>) -> OpenCovenant {
        let name_hash = items[0].read_hash().unwrap();
        let height = items[1].read_u32().unwrap();
        let name_length = items[2].len();
        let name = items[2].read_string(name_length).unwrap();

        OpenCovenant {
            name_hash,
            height,
            name: name.parse().unwrap(),
        }
    }
}

impl Encodable for OpenCovenant {
    fn size(&self) -> u32 {
        let mut size = VarInt::from(3 as u64).encoded_size();
        let name_hash_length = VarInt::from(32 as u64);
        let height_length = VarInt::from(4 as u64);
        let name_length = VarInt::from(self.name.len() as u64);

        //@todo change encoded size to usize (I think);
        size += name_hash_length.encoded_size();
        size += height_length.encoded_size();
        size += name_length.encoded_size();
        size += 32;
        size += 4;
        size += self.name.len() as u32;

        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_u8(2);
        buffer.write_varint(3);

        //Name Hash
        buffer.write_varint(32);
        buffer.write_hash(self.name_hash);

        //Height
        buffer.write_varint(4);
        buffer.write_u32(self.height);

        //Name
        buffer.write_varint(self.name.len());
        buffer.write_str(&self.name);

        buffer
    }
}

impl Decodable for OpenCovenant {
    type Err = DecodingError;

    fn decode(buffer: &mut Buffer) -> Result<Self, Self::Err> {
        //3
        buffer.read_varint()?;

        buffer.read_varint()?;
        let name_hash = buffer.read_hash()?;

        buffer.read_varint()?;
        let height = buffer.read_u32()?;

        let name_length = buffer.read_varint()?;
        //TODO check
        let name = buffer.read_string(name_length.as_u64() as usize)?;

        Ok(OpenCovenant {
            name_hash,
            height,
            name: name.parse().unwrap(),
        })
    }
}
