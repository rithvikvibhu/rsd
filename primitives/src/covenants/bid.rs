use extended_primitives::{Buffer, Hash, VarInt};
use handshake_encoding::{Decodable, DecodingError, Encodable};
use handshake_types::{Name, NameHash};

//@todo formatting, and I think common functions to_hex, from_hex.
//@todo testing.
//@when I say formatting I mean Debug and to_string functions.

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BidCovenant {
    pub name_hash: NameHash,
    pub height: u32,
    pub name: Name,
    //TODO *might* want to make this a BidHash, but that'll be a later impl
    //*blind hash*
    //Also rename
    pub hash: Hash,
}

impl BidCovenant {
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
        buffer.write_hash(self.hash);
        items.push(buffer);

        items
    }

    pub fn from_items(mut items: Vec<Buffer>) -> BidCovenant {
        let name_hash = items[0].read_hash().unwrap();
        let height = items[1].read_u32().unwrap();
        let name_length = items[2].len();
        let name = items[2].read_string(name_length).unwrap();
        let hash = items[3].read_hash().unwrap();

        BidCovenant {
            name_hash,
            height,
            //@todo ideally we wouldn't have to unwrap here, but we almost know for certain that
            //this will work. There may be a better way to handle to this perhaops assert
            name: name.parse().unwrap(),
            hash,
        }
    }
}

impl Encodable for BidCovenant {
    fn size(&self) -> u32 {
        let mut size = VarInt::from(4 as u64).encoded_size();
        let name_hash_length = VarInt::from(32 as u64);
        let height_length = VarInt::from(4 as u64);
        let name_length = VarInt::from(self.name.len() as u64);
        let hash_length = VarInt::from(32 as u64);

        //@todo I think we should switch varint encoded size to usize
        size += name_hash_length.encoded_size();
        size += height_length.encoded_size();
        size += name_length.encoded_size();
        size += hash_length.encoded_size();
        size += 32;
        size += 4;
        size += self.name.len() as u32;
        size += 32;

        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_u8(3);
        buffer.write_varint(4);

        //Name Hash
        //Hashes are 32 bytes
        buffer.write_varint(32);
        buffer.write_hash(self.name_hash);

        //Height
        buffer.write_varint(4);
        buffer.write_u32(self.height);

        //Name
        buffer.write_varint(self.name.len());
        buffer.write_str(&self.name);

        //Hashes are 32 bytes
        buffer.write_varint(32);
        buffer.write_hash(self.hash);

        buffer
    }
}

impl Decodable for BidCovenant {
    type Err = DecodingError;

    fn decode(buffer: &mut Buffer) -> Result<Self, Self::Err> {
        //4
        buffer.read_varint()?;

        buffer.read_varint()?;
        let name_hash = buffer.read_hash()?;

        buffer.read_varint()?;
        let height = buffer.read_u32()?;

        let name_length = buffer.read_varint()?;
        //TODO check
        let name = buffer.read_string(name_length.as_u64() as usize)?;

        buffer.read_varint()?;
        let hash = buffer.read_hash()?;

        Ok(BidCovenant {
            name_hash,
            height,
            name: name.parse().unwrap(),
            hash,
        })
    }
}
