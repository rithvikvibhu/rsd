use extended_primitives::{Buffer, VarInt};
use handshake_encoding::{Decodable, DecodingError, Encodable};
use handshake_types::NameHash;

//@todo formatting, and I think common functions to_hex, from_hex.
//@todo testing.
//@when I say formatting I mean Debug and to_string functions.

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UpdateCovenant {
    pub name_hash: NameHash,
    pub height: u32,
    pub record_data: Buffer,
}

impl UpdateCovenant {
    pub fn get_items(&self) -> Vec<Buffer> {
        let mut items = Vec::new();

        let mut buffer = Buffer::new();
        buffer.write_hash(self.name_hash);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_u32(self.height);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.extend(self.record_data.clone());
        items.push(buffer);

        items
    }

    pub fn from_items(mut items: Vec<Buffer>) -> UpdateCovenant {
        let name_hash = items[0].read_hash().unwrap();
        let height = items[1].read_u32().unwrap();

        let record_length = items[2].len();
        let record_data = Buffer::from(items[2].read_bytes(record_length).unwrap());

        UpdateCovenant {
            name_hash,
            height,
            record_data,
        }
    }
}

impl Encodable for UpdateCovenant {
    fn size(&self) -> u32 {
        let mut size = VarInt::from(3 as u64).encoded_size();
        let name_hash_length = VarInt::from(32 as u64);
        let height_length = VarInt::from(4 as u64);
        let name_length = VarInt::from(self.record_data.len() as u64);

        //@todo encoded_size should return a usize...
        size += name_hash_length.encoded_size();
        size += height_length.encoded_size();
        size += name_length.encoded_size();
        size += 32;
        size += 4;
        size += self.record_data.len() as u32;

        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_u8(7);
        buffer.write_varint(3);

        //Name Hash
        //Hashes are 32 bytes
        buffer.write_varint(32);
        buffer.write_hash(self.name_hash);

        //Height
        buffer.write_varint(4);
        buffer.write_u32(self.height);

        //Record Data
        buffer.write_var_bytes(&self.record_data);

        buffer
    }
}

impl Decodable for UpdateCovenant {
    type Err = DecodingError;

    fn decode(buffer: &mut Buffer) -> Result<Self, Self::Err> {
        //3
        buffer.read_varint()?;

        buffer.read_varint()?;
        let name_hash = buffer.read_hash()?;

        buffer.read_varint()?;
        let height = buffer.read_u32()?;

        //Record Data
        let record_data = Buffer::from(buffer.read_var_bytes()?);

        Ok(UpdateCovenant {
            name_hash,
            height,
            record_data,
        })
    }
}
