use extended_primitives::{Buffer, Hash, VarInt};
use handshake_encoding::{Decodable, DecodingError, Encodable};
use handshake_types::NameHash;

//@todo formatting, and I think common functions to_hex, from_hex.
//@todo testing.
//@when I say formatting I mean Debug and to_string functions.

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RevealCovenant {
    pub name_hash: NameHash,
    pub height: u32,
    //@todo review if this needs to be a Hash or Uint256
    pub nonce: Hash,
}

impl RevealCovenant {
    pub fn get_items(&self) -> Vec<Buffer> {
        let mut items = Vec::new();

        let mut buffer = Buffer::new();
        buffer.write_hash(self.name_hash);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_u32(self.height);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_hash(self.nonce);
        items.push(buffer);

        items
    }

    pub fn from_items(mut items: Vec<Buffer>) -> RevealCovenant {
        let name_hash = items[0].read_hash().unwrap();
        let height = items[1].read_u32().unwrap();
        let nonce = items[2].read_hash().unwrap();

        RevealCovenant {
            name_hash,
            height,
            nonce,
        }
    }
}

impl Encodable for RevealCovenant {
    fn size(&self) -> u32 {
        let mut size = VarInt::from(3 as u64).encoded_size();
        let name_hash_length = VarInt::from(32 as u64);
        let height_length = VarInt::from(4 as u64);
        //TODO double check this.
        let nonce_length = VarInt::from(32 as u64);

        size += name_hash_length.encoded_size();
        size += height_length.encoded_size();
        size += nonce_length.encoded_size();
        size += 32;
        size += 4;
        size += 32;

        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_u8(4);
        buffer.write_varint(3);

        //Name Hash
        //Hashes are 32 bytes
        buffer.write_varint(32);
        buffer.write_hash(self.name_hash);

        //Height
        buffer.write_varint(4);
        buffer.write_u32(self.height);

        //Nonce
        buffer.write_varint(32);
        buffer.write_hash(self.nonce);

        buffer
    }
}

impl Decodable for RevealCovenant {
    type Err = DecodingError;

    fn decode(buffer: &mut Buffer) -> Result<Self, Self::Err> {
        //3
        buffer.read_varint()?;

        buffer.read_varint()?;
        let name_hash = buffer.read_hash()?;

        buffer.read_varint()?;
        let height = buffer.read_u32()?;

        buffer.read_varint()?;
        let nonce = buffer.read_hash()?;

        Ok(RevealCovenant {
            name_hash,
            height,
            nonce,
        })
    }
}
