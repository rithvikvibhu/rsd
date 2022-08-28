use extended_primitives::{Buffer, Hash, VarInt};
use handshake_encoding::{Decodable, DecodingError, Encodable};
use handshake_types::NameHash;

//@todo formatting, and I think common functions to_hex, from_hex.
//@todo testing.
//@when I say formatting I mean Debug and to_string functions.

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RenewCovenant {
    pub name_hash: NameHash,
    pub height: u32,
    //TODO see above.
    pub block_hash: Hash,
}

impl RenewCovenant {
    pub fn get_items(&self) -> Vec<Buffer> {
        let mut items = Vec::new();

        let mut buffer = Buffer::new();
        buffer.write_hash(self.name_hash);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_u32(self.height);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_hash(self.block_hash);
        items.push(buffer);

        items
    }

    pub fn from_items(mut items: Vec<Buffer>) -> RenewCovenant {
        let name_hash = items[0].read_hash().unwrap();
        let height = items[1].read_u32().unwrap();
        let block_hash = items[2].read_hash().unwrap();

        RenewCovenant {
            name_hash,
            height,
            block_hash,
        }
    }
}

impl Encodable for RenewCovenant {
    fn size(&self) -> u32 {
        let mut size = VarInt::from(3 as u64).encoded_size();
        let name_hash_length = VarInt::from(32 as u64);
        let height_length = VarInt::from(4 as u64);
        let block_length = VarInt::from(32 as u64);

        size += name_hash_length.encoded_size();
        size += height_length.encoded_size();
        size += block_length.encoded_size();
        size += 32;
        size += 4;
        size += 32;

        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_u8(8);
        buffer.write_varint(3);

        //Name Hash
        //Hashes are 32 bytes
        buffer.write_varint(32);
        buffer.write_hash(self.name_hash);

        //Height
        buffer.write_varint(4);
        buffer.write_u32(self.height);

        //Block Hash
        buffer.write_varint(32);
        buffer.write_hash(self.block_hash);

        buffer
    }
}

impl Decodable for RenewCovenant {
    type Err = DecodingError;

    fn decode(buffer: &mut Buffer) -> Result<Self, Self::Err> {
        //3
        buffer.read_varint()?;

        buffer.read_varint()?;
        let name_hash = buffer.read_hash()?;

        buffer.read_varint()?;
        let height = buffer.read_u32()?;

        buffer.read_varint()?;
        let block_hash = buffer.read_hash()?;

        Ok(RenewCovenant {
            name_hash,
            height,
            block_hash,
        })
    }
}
