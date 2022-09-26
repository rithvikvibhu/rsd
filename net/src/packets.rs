use crate::common::{MAX_INV, USER_AGENT};
use crate::net_address::NetAddress;
use crate::types::{Nonce, ProtocolVersion, Services};
use crate::{Result, error::Error};
use chrono::{DateTime, TimeZone, Utc};
use extended_primitives::Buffer;
use extended_primitives::Hash;
use extended_primitives::VarInt;
use handshake_encoding::{Decodable, Encodable};
use handshake_primitives::{Block, BlockHeader, Inventory, Transaction};
use handshake_protocol::network::Network;
use handshake_types::Bloom;
use log::debug;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rand::Rng;
use std::convert::{TryInto, TryFrom};
use std::fmt::Debug;
use downcast_rs::{DowncastSync, impl_downcast};


#[derive(Copy, Clone, Debug, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum PacketType {
    Version = 0,
    Verack = 1,
    Ping = 2,
    Pong = 3,
    GetAddr = 4,
    Addr = 5,
    Inv = 6,
    GetData = 7,
    NotFound = 8,
    GetBlocks = 9,
    GetHeaders = 10,
    Headers = 11,
    SendHeaders = 12,
    Block = 13,
    Tx = 14,
    Reject = 15,
    Mempool = 16,
    FilterLoad = 17,
    FilterAdd = 18,
    FilterClear = 19,
    MerkleBlock = 20,
    FeeFilter = 21,
    SendCompact = 22,
    CompactBlock = 23,
    GetBlockTransaction = 24,
    BlockTransaction = 25,
    GetProof = 26,
    Proof = 27,
    Claim = 28,
    Airdrop = 29,
    Unknown = 30,
    Internal = 31,
    Data = 32,
}


#[derive(Debug)]
pub struct Payload {
    pub magic: u32,
    pub code: PacketType,
    pub packet_size: u32,
    pub packet: Option<Box<dyn Packet>>,
}

impl Payload {
    pub fn from_packet(packet: Box<dyn Packet>, network: Network) -> Result<Self> {
        Ok(Payload {
            magic: network.magic(),
            code: packet.code(),
            packet_size: packet.size(),
            packet: Some(packet),
        })
    }

    pub fn parse_header(mut packet: Buffer) -> Result<Self> {
        let magic = packet.read_u32()?;

        let payload_type = match PacketType::try_from(packet.read_u8()?) {
            Ok(p) => p,
            Err(error) => {
                debug!("Cannot parse packet type: {}", error);
                return Err(Error::InvalidPacketType);
            },
        };

        let packet_size = packet.read_u32()?;

        //Check magic number, throw packet invalid magic number
        //Check size, and ensure it's below constant max message size. -> We already have
        //This checked in Brontide, but I think let's check it again here.

        Ok(
            Payload {
                magic,
                code: payload_type,
                packet_size,
                packet: None,
            }
        )
    }

    pub fn decode(&mut self, mut raw_packet: Buffer) {
        let packet = match self.code {
            PacketType::Version => VersionPacket::decode(&mut raw_packet),
            PacketType::Verack => VerackPacket::decode(&mut raw_packet),
            PacketType::Ping => PingPacket::decode(&mut raw_packet),
            PacketType::Pong => PongPacket::decode(&mut raw_packet),
            PacketType::Unknown => UnknownPacket::decode(&mut raw_packet),
            _ => { Err(Error::InvalidPacketType) },
        };

        match packet {
            Ok(packet) => self.packet = Some(packet),
            Err(error) => debug!("Cannot decode packet: {}", error),
        }
    }

    // pub fn decode(packet_type: u8, mut raw_packet: Buffer) -> Result<Self> {
    //     match packet_type {
    //         0 => Ok(Self::VersionPacket(VersionPacket::decode(&mut raw_packet)?)),
    //         1 => Ok(Self::VerackPacket(VerackPacket::decode(&mut raw_packet)?)),
    //         // 2 => Ok(Packet::Ping(PingPacket::decode(raw_packet)?)),
    //         // 3 => Ok(Packet::Pong(PongPacket::decode(raw_packet)?)),
    //         // 4 => Ok(Packet::GetAddr),
    //         // 5 => {
    //         //     let packet = AddrPacket::decode(raw_packet)?;
    //         //     Ok(Packet::Addr(packet))
    //         // }
    //         // 6 => {
    //         //     let packet = InvPacket::decode(raw_packet)?;
    //         //     Ok(Packet::Inv(packet))
    //         // }
    //         // 7 => Ok(Packet::GetData),
    //         // 8 => Ok(Packet::NotFound),
    //         // 9 => {
    //         //     let packet = GetBlocksPacket::decode(raw_packet)?;
    //         //     Ok(Packet::GetBlocks(packet))
    //         // }
    //         _ => Ok(Self::UnknownPacket(UnknownPacket::decode(&mut raw_packet)?)),
    //     }
    // }

    pub fn frame(&self, network: Network) -> Result<Buffer> {
        let mut buffer = Buffer::new();

        match &self.packet {
            Some(packet) => {
                // Write payload header
                buffer.write_u32(network.magic());
                buffer.write_u8(packet.code().into());
                buffer.write_u32(packet.size());

                // Write encoded packet
                buffer.extend(packet.encode());

                Ok(buffer)
            },
            None => Err(Error::NoPacket),
        }
    }
}

pub trait Packet: std::fmt::Debug + DowncastSync {
    // new() ?

    fn code(&self) -> PacketType;

    fn size(&self) -> u32 {
        0
    }

    fn encode(&self) -> Buffer {
        Buffer::new()
    }

    fn decode(buffer: &mut Buffer) -> Result<Box<dyn Packet>> where Self: Sized;
}
impl_downcast!(sync Packet);


#[derive(Clone, Debug, PartialEq)]
pub struct VersionPacket {
    pub(crate) version: ProtocolVersion,
    pub(crate) services: Services,
    //Check on this.
    time: DateTime<Utc>,
    remote: NetAddress,
    //This doesn't feel correct, probably should be a setBuffer TODO
    nonce: Buffer,
    pub(crate) agent: String,
    pub(crate) height: u32,
    pub(crate) no_relay: bool,
}

impl VersionPacket {
    pub fn new(addr: NetAddress, height: u32, no_relay: bool) -> Self {
        //TODO we probably want to implement noncelist here.
        let nonce = rand::thread_rng().gen::<[u8; 8]>();
        VersionPacket {
            version: ProtocolVersion::default(),
            services: Services::LOCAL_SERVICES,
            time: Utc::now(),
            remote: addr,
            agent: USER_AGENT.to_owned(),
            nonce: Buffer::from(nonce.to_vec()),
            height,
            no_relay,
        }
    }
}

impl Packet for VersionPacket {
    fn code(&self) -> PacketType {
        PacketType::Version
    }

    fn size(&self) -> u32 {
        let mut size = 0;
        size += 20;
        size += self.remote.size();
        size += 8;
        size += 1;
        size += self.agent.len() as u32;
        size += 5;
        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_u32(self.version.as_u32()); //TODO protocol version should deref to a u32
        buffer.write_u32(self.services.bits());
        buffer.write_u32(0);
        buffer.write_u64(self.time.timestamp() as u64);
        buffer.extend(self.remote.encode());
        buffer.extend(self.nonce.clone());
        buffer.write_u8(self.agent.len() as u8);
        buffer.write_str(&self.agent);
        buffer.write_u32(self.height);
        buffer.write_u8(self.no_relay as u8);

        buffer
    }

    fn decode(mut packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let version = packet.read_u32()?;
        let services = packet.read_u32()?;
        packet.read_u32()?;
        let timestamp = packet.read_u64()?;
        let remote = NetAddress::decode(&mut packet)?;
        let nonce = packet.read_bytes(8)?;
        let agent_length = packet.read_u8()?;
        let agent = packet.read_string(agent_length as usize)?;
        let height = packet.read_u32()?;
        let no_relay = packet.read_u8()?;

        Ok(Box::new(VersionPacket {
            version: ProtocolVersion::from(version),
            services: Services::from_bits_truncate(services),
            time: Utc.timestamp(timestamp as i64, 0),
            remote,
            agent,
            nonce: Buffer::from(nonce),
            height,
            no_relay: no_relay == 1,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct VerackPacket {
}

impl VerackPacket {
    pub fn new() -> Self {
        VerackPacket {}
    }
}

impl Packet for VerackPacket {
    fn code(&self) -> PacketType {
        PacketType::Verack
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        Ok(Box::new(VerackPacket {}))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct PingPacket {
    //TODO probably make this a custom type. -> I think it's the same nonce as hostname.
    pub(crate) nonce: Nonce,
}

impl PingPacket {
    pub fn new(nonce: Nonce) -> Self {
        PingPacket {
            nonce,
        }
    }
}

impl Packet for PingPacket {
    fn code(&self) -> PacketType {
        PacketType::Ping
    }

    fn size(&self) -> u32 {
        8
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_bytes(&self.nonce);

        buffer
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let nonce = packet.read_bytes(8)?;
        Ok(Box::new(PingPacket {
            nonce: nonce.try_into().unwrap(),
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct PongPacket {
    pub(crate) nonce: Nonce,
}

impl PongPacket {
    pub fn new(nonce: Nonce) -> Self {
        PongPacket {
            nonce,
        }
    }
}

impl Packet for PongPacket {
    fn code(&self) -> PacketType {
        PacketType::Pong
    }

    fn size(&self) -> u32 {
        8
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_bytes(&self.nonce);

        buffer
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let nonce = packet.read_bytes(8)?;

        Ok(Box::new(PongPacket {
            nonce: nonce.try_into().unwrap(),
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct UnknownPacket {
    data: Buffer,
}

impl Packet for UnknownPacket {
    fn code(&self) -> PacketType {
        PacketType::Unknown
    }

    fn size(&self) -> u32 {
        self.data.len() as u32
    }

    fn encode(&self) -> Buffer {
        self.data.clone()
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        Ok(Box::new(UnknownPacket {
            data: packet.clone(),
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct GetAddrPacket {
}

impl GetAddrPacket {
    pub fn new() -> Self {
        GetAddrPacket {}
    }
}

impl Packet for GetAddrPacket {
    fn code(&self) -> PacketType {
        PacketType::GetAddr
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        Ok(Box::new(GetAddrPacket {}))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct AddrPacket {
    items: Vec<NetAddress>,
}

impl Packet for AddrPacket {
    fn code(&self) -> PacketType {
        PacketType::Addr
    }

    fn size(&self) -> u32 {
        let mut size = 0;
        let length = VarInt::from(self.items.len() as u64);
        size += length.encoded_size();
        let items = self.items.iter();
        for addr in items {
            size += addr.size();
        }

        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_varint(self.items.len());
        let items = self.items.iter();
        for item in items {
            buffer.extend(item.encode());
        }

        buffer
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let count = packet.read_varint()?;
        //TODO would it be faster to initalize with capacity here? since we know the count.
        let mut items = Vec::new();
        for _ in 0..count.to_u64() {
            items.push(NetAddress::decode(packet)?);
        }

        Ok(Box::new(AddrPacket {
            items,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct InvPacket {
    items: Vec<Inventory>,
}

impl Packet for InvPacket {
    fn code(&self) -> PacketType {
        PacketType::Inv
    }

    fn size(&self) -> u32 {
        let mut size = 0;
        let length = VarInt::from(self.items.len() as u64);
        size += length.encoded_size();

        let items = self.items.iter();
        for item in items {
            size += item.size();
        }

        size
    }

    fn encode(&self) -> Buffer {
        assert!(self.items.len() < MAX_INV as usize);

        let mut buffer = Buffer::new();

        buffer.write_varint(self.items.len());

        let items = self.items.iter();

        for item in items {
            buffer.extend(item.encode());
        }

        buffer
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let count = packet.read_varint()?;

        let mut items = Vec::new();
        for _ in 0..count.to_u64() {
            items.push(Inventory::decode(packet)?);
        }

        Ok(Box::new(InvPacket {
            items,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct GetDataPacket {
}

impl GetDataPacket {
    pub fn new() -> Self {
        GetDataPacket {}
    }
}

impl Packet for GetDataPacket {
    fn code(&self) -> PacketType {
        PacketType::GetData
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        Ok(Box::new(GetDataPacket {}))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct NotFoundPacket {
}

impl NotFoundPacket {
    pub fn new() -> Self {
        NotFoundPacket {}
    }
}

impl Packet for NotFoundPacket {
    fn code(&self) -> PacketType {
        PacketType::NotFound
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        Ok(Box::new(NotFoundPacket {}))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct GetBlocksPacket {
    locator: Vec<Hash>,
    stop: Hash,
}

impl Packet for GetBlocksPacket {
    fn code(&self) -> PacketType {
        PacketType::GetBlocks
    }

    fn size(&self) -> u32 {
        let mut size = 0;
        let length = VarInt::from(self.locator.len() as u64);
        size += length.encoded_size();
        //Each hash is 32 bytes.
        size += self.locator.len() as u32 * 32;
        //Stop size
        size += 32;
        size
    }

    fn encode(&self) -> Buffer {
        assert!(self.locator.len() < MAX_INV as usize);

        let mut buffer = Buffer::new();

        buffer.write_varint(self.locator.len());
        let items = self.locator.iter();
        for item in items {
            buffer.write_hash(*item);
        }

        buffer.write_hash(self.stop);

        buffer
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let count = packet.read_varint()?;

        //TODO probably catch this error, and destroy the peer.
        //TODO have count.to_usize, count.to_u32, etc
        assert!(count.as_u64() <= MAX_INV as u64);

        let mut locator: Vec<Hash> = Vec::new();

        for _ in 0..count.to_u64() {
            locator.push(packet.read_hash()?);
        }

        let stop = packet.read_hash()?;

        Ok(Box::new(GetBlocksPacket {
            locator,
            stop,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct GetHeadersPacket {
    locator: Vec<Hash>,
    stop: Hash,
}

impl Packet for GetHeadersPacket {
    fn code(&self) -> PacketType {
        PacketType::GetHeaders
    }

    fn size(&self) -> u32 {
        let mut size = 0;
        let length = VarInt::from(self.locator.len() as u64);
        size += length.encoded_size();
        //Each hash is 32 bytes.
        size += self.locator.len() as u32 * 32;
        //Stop size
        size += 32;
        size
    }

    fn encode(&self) -> Buffer {
        assert!(self.locator.len() < MAX_INV as usize);

        let mut buffer = Buffer::new();

        buffer.write_varint(self.locator.len());
        let items = self.locator.iter();
        for item in items {
            buffer.write_hash(*item);
        }

        buffer.write_hash(self.stop);

        buffer
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let count = packet.read_varint()?;

        //TODO probably catch this error, and destroy the peer.
        //TODO have count.to_usize, count.to_u32, etc
        assert!(count.as_u64() <= MAX_INV as u64);

        let mut locator: Vec<Hash> = Vec::new();

        for _ in 0..count.to_u64() {
            locator.push(packet.read_hash()?);
        }

        let stop = packet.read_hash()?;

        Ok(Box::new(GetHeadersPacket {
            locator,
            stop,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct HeadersPacket {
    items: Vec<BlockHeader>,
}

impl Packet for HeadersPacket {
    fn code(&self) -> PacketType {
        PacketType::Headers
    }

    fn size(&self) -> u32 {
        let mut size = 0;
        let length = VarInt::from(self.items.len() as u64);
        size += length.encoded_size();
        let items = self.items.iter();
        for addr in items {
            size += addr.size();
        }

        size
    }

    fn encode(&self) -> Buffer {
        //TODO not a big fan of these asserts.
        assert!(self.items.len() <= 2000);

        let mut buffer = Buffer::new();

        buffer.write_varint(self.items.len());
        let items = self.items.iter();
        for item in items {
            buffer.extend(item.encode());
        }

        buffer
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let count = packet.read_varint()?;

        //TODO not a big fan of these asserts.
        assert!(count.as_u64() <= 2000);

        //TODO would it be faster to initalize with capacity here? since we know the count.
        let mut items = Vec::new();
        for _ in 0..count.to_u64() {
            items.push(BlockHeader::decode(packet)?);
        }

        Ok(Box::new(HeadersPacket {
            items,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct SendHeadersPacket {
}

impl SendHeadersPacket {
    pub fn new() -> Self {
        SendHeadersPacket {}
    }
}

impl Packet for SendHeadersPacket {
    fn code(&self) -> PacketType {
        PacketType::SendHeaders
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        Ok(Box::new(SendHeadersPacket {}))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct BlockPacket {
    block: Block,
}

impl BlockPacket {
    pub fn new(block: Block) -> BlockPacket {
        BlockPacket {
            block,
        }
    }
}

impl Packet for BlockPacket {
    fn code(&self) -> PacketType {
        PacketType::Block
    }

    fn size(&self) -> u32 {
        self.block.size()
    }

    fn encode(&self) -> Buffer {
        self.block.encode()
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let block = Block::decode(packet)?;

        Ok(Box::new(BlockPacket {
            block,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct TxPacket {
    tx: Transaction,
}

impl TxPacket {
    pub fn new(tx: Transaction) -> TxPacket {
        TxPacket {
            tx,
        }
    }
}

impl Packet for TxPacket {
    fn code(&self) -> PacketType {
        PacketType::Tx
    }

    fn size(&self) -> u32 {
        self.tx.size()
    }

    fn encode(&self) -> Buffer {
        self.tx.encode()
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let tx = Transaction::decode(packet)?;

        Ok(Box::new(TxPacket {
            tx,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct RejectPacket {
    message: u8,
    //Going to be a custom type.
    reject_code: u8,
    reason: String,
    hash: Option<Hash>,
}

impl Packet for RejectPacket {
    fn code(&self) -> PacketType {
        PacketType::Reject
    }

    fn size(&self) -> u32 {
        let mut size = 0;
        size += 1;
        size += 1;
        size += 1;
        size += self.reason.len() as u32;

        if self.hash.is_some() {
            size += 32;
        }

        size
    }

    fn encode(&self) -> Buffer {
        let mut buffer = Buffer::new();

        buffer.write_u8(self.message);
        buffer.write_u8(self.reject_code);
        buffer.write_u8(self.reason.len() as u8);
        buffer.write_str(&self.reason);

        if let Some(hash) = self.hash {
            buffer.write_hash(hash);
        }

        buffer
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let message = packet.read_u8()?;
        let reject_code = packet.read_u8()?;
        let reason_length = packet.read_u8()?;

        let reason = packet.read_string(reason_length as usize)?;
        let hash: Option<Hash>;

        //Redo this and use the actual packet types instead of hardcoded numbers TODO
        match message {
            13 => hash = Some(packet.read_hash()?),
            14 => hash = Some(packet.read_hash()?),
            28 => hash = Some(packet.read_hash()?),
            29 => hash = Some(packet.read_hash()?),
            _ => hash = None,
        };

        Ok(Box::new(RejectPacket {
            message,
            reject_code,
            reason,
            hash,
        }))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct MempoolPacket {
}

impl MempoolPacket {
    pub fn new() -> Self {
        MempoolPacket {}
    }
}

impl Packet for MempoolPacket {
    fn code(&self) -> PacketType {
        PacketType::Mempool
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        Ok(Box::new(MempoolPacket {}))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct FilterLoadPacket {
    filter: Bloom,
}

impl Packet for FilterLoadPacket {
    fn code(&self) -> PacketType {
        PacketType::FilterLoad
    }

    fn size(&self) -> u32 {
        self.filter.size()
    }

    fn encode(&self) -> Buffer {
        self.filter.encode()
    }

    fn decode(packet: &mut Buffer) -> Result<Box<dyn Packet>> {
        let filter = Bloom::decode(packet)?;

        Ok(Box::new(FilterLoadPacket {
            filter
        }))
    }
}
