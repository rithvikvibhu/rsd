use extended_primitives::{Buffer, Hash, VarInt};
use handshake_encoding::{Decodable, DecodingError, Encodable};
use handshake_types::{Name, NameHash};

//@todo formatting, and I think common functions to_hex, from_hex.
//@todo testing.
//@when I say formatting I mean Debug and to_string functions.

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FinalizeCovenant {
    pub name_hash: NameHash,
    pub height: u32,
    pub name: Name,
    pub flags: u8,
    pub claimed: u32,
    pub renewals: u32,
    pub block_hash: Hash,
}

impl FinalizeCovenant {
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

        let mut buffer = Buffer::new();
        buffer.write_u8(self.flags);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_u32(self.claimed);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_u32(self.renewals);
        items.push(buffer);

        let mut buffer = Buffer::new();
        buffer.write_hash(self.block_hash);
        items.push(buffer);

        items
    }

    pub fn from_items(mut items: Vec<Buffer>) -> FinalizeCovenant {
        let name_hash = items[0].read_hash().unwrap();
        let height = items[1].read_u32().unwrap();
        //Name
        let name_length = items[2].len();
        let name = items[2].read_string(name_length).unwrap();
        let flags = items[3].read_u8().unwrap();
        let claimed = items[4].read_u32().unwrap();
        let renewals = items[5].read_u32().unwrap();
        let block_hash = items[6].read_hash().unwrap();

        FinalizeCovenant {
            name_hash,
            height,
            name: name.parse().unwrap(),
            flags,
            claimed,
            renewals,
            block_hash,
        }
    }
}

impl Encodable for FinalizeCovenant {
    fn size(&self) -> u32 {
        let mut size = VarInt::from(7 as u64).encoded_size();
        let name_hash_length = VarInt::from(32 as u64);
        let height_length = VarInt::from(4 as u64);
        let name_length = VarInt::from(self.name.len() as u64);
        let flags_length = VarInt::from(1 as u64);
        let claimed_length = VarInt::from(4 as u64);
        let renewals_length = VarInt::from(4 as u64);
        let block_hash_length = VarInt::from(32 as u64);

        size += name_hash_length.encoded_size();
        size += height_length.encoded_size();
        size += name_length.encoded_size();
        size += flags_length.encoded_size();
        size += renewals_length.encoded_size();
        size += claimed_length.encoded_size();
        size += block_hash_length.encoded_size();
        size += 32;
        size += 4;
        size += self.name.len() as u32;
        size += 1;
        size += 4;
        size += 4;
        size += 32;

        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_u8(10);
        buffer.write_varint(7);

        //Name Hash
        //Hashes are 32 bytes
        buffer.write_varint(32);
        buffer.write_hash(self.name_hash);

        //Height
        buffer.write_varint(4);
        buffer.write_u32(self.height);

        //Record Data
        buffer.write_varint(self.name.len());
        buffer.write_str(&self.name);

        //Record Data
        buffer.write_varint(1);
        buffer.write_u8(self.flags);

        //Claimed
        buffer.write_varint(4);
        buffer.write_u32(self.claimed);

        //Renewals
        buffer.write_varint(4);
        buffer.write_u32(self.renewals);

        //Block Hash
        buffer.write_varint(32);
        buffer.write_hash(self.block_hash);

        buffer
    }
}

impl Decodable for FinalizeCovenant {
    type Err = DecodingError;

    fn decode(buffer: &mut Buffer) -> Result<Self, Self::Err> {
        //7
        buffer.read_varint()?;

        buffer.read_varint()?;
        let name_hash = buffer.read_hash()?;

        buffer.read_varint()?;
        let height = buffer.read_u32()?;

        //Name
        let name_length = buffer.read_varint()?;
        let name = buffer.read_string(name_length.as_u64() as usize)?;

        //Flags
        buffer.read_varint()?;
        let flags = buffer.read_u8()?;

        buffer.read_varint()?;
        let claimed = buffer.read_u32()?;

        buffer.read_varint()?;
        let renewals = buffer.read_u32()?;

        buffer.read_varint()?;
        let block_hash = buffer.read_hash()?;

        Ok(FinalizeCovenant {
            name_hash,
            height,
            name: name.parse().unwrap(),
            flags,
            claimed,
            renewals,
            block_hash,
        })
    }
}
