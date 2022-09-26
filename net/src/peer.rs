use crate::net_address::NetAddress;
use crate::packets::*;
use handshake_types::Time;
use log::warn;
use std::convert::TryFrom;
use std::io::{Write, Read};
use std::net::SocketAddr;
//TODO reimplement when types crate is available.
use crate::error::Error;
use crate::types::{IdentityKey, Nonce, ProtocolVersion, Services};
use crate::Result;
use chrono::{DateTime, Utc};
use extended_primitives::Buffer;
use futures::channel::mpsc::UnboundedSender;
use futures::lock::Mutex;
use futures::sink::SinkExt;
use handshake_encoding::Encodable;
use handshake_protocol::network::Network;
use handshake_types::difficulty::Difficulty;
// use romio::TcpStream;
use std::net::TcpStream;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Outbound = 0,
    Inbound = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Connected,
    Initial,
    Banned,
    //TODO might not need disconnected
    Disconnected,
}

//Defaults
#[derive(Clone, Debug)]
pub struct PeerLiveInfo {
    // pub total_difficulty: Difficulty,
    pub height: u32,
    pub last_seen: Time,
    pub first_seen: Time,
    pub last_send: Time,
    pub last_receive: Time,
}

//Unchanging information about a peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub user_agent: String,
    pub version: Option<ProtocolVersion>,
    pub address: NetAddress,
    pub services: Services,
    pub no_relay: bool,
    pub direction: Direction,
}

//Information about a peers ping/pong responses.
#[derive(Clone, Debug)]
pub struct PingStats {
    challenge: Option<Nonce>,
    last_pong: Time,
    last_ping: Time,
    min_ping: Time,
}

//TODO do we really need to have a network here?
#[derive(Debug)]
pub struct Peer {
    //ARC
    pub info: PeerInfo,
    //ARC
    pub live_info: Mutex<PeerLiveInfo>,
    //We might want to break this into 2, one for writing and one for reading.
    //would prevent locks on both, and increase the speed here.
    //ARC
    pub stream: Mutex<TcpStream>,
    //ARC
    pub network: Network,
    //Possibly combine state and live info into the same lock.
    pub state: Arc<Mutex<State>>,
    //TODO this might need to be RwLock
    pub loader: RwLock<bool>,
    //ARC
    pub tx: Mutex<UnboundedSender<Payload>>,
    pub ping_stats: Mutex<PingStats>,
    pub prefer_headers: Mutex<bool>,
}

impl Peer {
    //Connect to a new peer.
    //TODO should be a custom key type. - not sure if we want to store this inside of the peer.
    pub async fn connect(
        addr: NetAddress,
        key: [u8; 32],
        network: Network,
        tx: UnboundedSender<Payload>,
    ) -> Result<Peer> {
        println!("LOG: Peer connect: {:#?}", addr);

        let hostname = &addr.address.to_string();
        let stream = TcpStream::connect(hostname).expect("Could not connect");
        // println!("LOG Peer connect: stream: {:#?}", stream);

        //TODO split the stream to readers and writers
        //TODO maybe should make these their own structs.
        //let (srx, stx) = stream.split();

        let info = PeerInfo {
            address: addr,
            user_agent: "".to_owned(),
            //TODO not sure what to default this to.
            no_relay: false,
            direction: Direction::Outbound,
            version: None,
            services: Services::empty(),
        };

        let live_info = PeerLiveInfo {
            height: 0,
            last_seen: Time::new(),
            first_seen: Time::new(),
            last_send: Time::new(),
            last_receive: Time::new(),
        };

        let ping_stats = PingStats {
            challenge: None,
            last_ping: Time::new(),
            last_pong: Time::new(),
            min_ping: Time::new(),
        };

        let state = Arc::new(Mutex::new(State::Initial));

        Ok(Peer {
            info,
            live_info: Mutex::new(live_info),
            stream: Mutex::new(stream),
            loader: RwLock::new(false),
            network,
            state,
            tx: Mutex::new(tx),
            ping_stats: Mutex::new(ping_stats),
            prefer_headers: Mutex::new(false),
        })
    }

    //Accept an incoming connection.
    // pub fn accept() {}

    //Handle all incoming messages, and put them into a message queue.
    pub async fn handle_messages(&mut self) -> Result<()> {
        //Need to check if this peer no longer exists on each loop, since otherwise we'll never
        //drop this.
        loop {
            let payload = self.next_message().await?;
            println!("LOG: handle_message: {:#?}", payload);

            let packet = match payload.packet.as_ref() {
                Some(packet) => packet,
                None => { continue; }
            };

            if packet.code() == PacketType::Version {
                self.handle_version(&payload).await?;
                continue;
            }

            if packet.code() == PacketType::Verack {
                self.handle_verack(&payload).await?;
                continue;
            }

            //If we have not received a version, then continue, and add to the peers ban score.
            if self.info.version.is_none() {
                // self.increase_ban(1);
                continue;
            }

            //Get state lock
            let state = self.state.lock().await;

            //TODO maybe just check for banned/disconnected here as well. -> Could do a match
            //statement. Although, it probably should be above the next message stuff.
            //If we have not received a verack, then continue and add a ban score.
            if *state != State::Connected {
                // self.increase_ban(1);
                continue;
            }

            match packet.code().into() {
                //TODO filterload, filteradd, filterclear, feefilter,
                //sendcompact

                PacketType::Ping => self.handle_ping(&payload).await?,
                PacketType::Pong => self.handle_pong(&payload).await?,
                // Packet::SendHeaders => self.handle_send_headers().await?,
                //Remaining packets, do nothing. They are sent to the pool.
                _ => {
                    println!("LOG: handle_message: did not match any in peer");
                    ()
                }
            };

            //Acquire tx lock.
            let mut tx = self.tx.lock().await;

            //TODO need to implement the error here
            tx.send(payload).await.unwrap();
        }

        Ok(())
    }

    pub async fn handle_version(&mut self, payload: &Payload) -> Result<()> {
        let generic_packet = payload.packet.as_ref().unwrap();
        assert_eq!(PacketType::try_from(payload.code).unwrap(), PacketType::Version);

        let packet = generic_packet.as_any().downcast_ref::<VersionPacket>().unwrap();

        if self.info.version.is_some() {
            warn!("Peer sent a duplcation version.");
            // Increase ban by 1.
            // self.increase_ban(1);
        }

        //Do all non-changing info here.
        self.info.version = Some(packet.version);
        self.info.services = packet.services;
        self.info.user_agent = packet.agent.clone();
        self.info.no_relay = packet.no_relay;

        //Acquire lock, and change live info.
        let mut live_info = self.live_info.lock().await;

        //TODO do we set interaction stuff here?
        live_info.height = packet.height;

        // dbg!(&self);

        //Send Verack
        self.send_verack().await?;

        Ok(())
    }

    pub async fn handle_verack(&self, payload: &Payload) -> Result<()> {
        //TODO see if currentlyConnected is important or not.
        //if self.info.direction == Direction::Outbound {
        //    //Get state lock.
        //    let mut state = self.state.lock().await;

        //    *state = State::Connected;
        //    // info!("New outbound peer connected: version: {}, blocks: {}, peer: {}", self.info.version, self.info.address);
        //}

        //Get state lock.
        let mut state = self.state.lock().await;

        //Mark the node as connected.
        *state = State::Connected;

        Ok(())
    }

    pub async fn handle_ping(&self, payload: &Payload) -> Result<()> {
        let generic_packet = payload.packet.as_ref().unwrap();
        assert_eq!(PacketType::try_from(payload.code).unwrap(), PacketType::Ping);

        let packet = generic_packet.as_any().downcast_ref::<PingPacket>().unwrap();

        //Assume the packets always have nonce. Write a test to ensure that this is the case TODO
        //The test should try to send a ping that does not have a nonce, and we should handle it
        //accordingly.
        let pong_packet = PongPacket::new(packet.nonce);
        self.send(Box::new(pong_packet)).await?;
        Ok(())
    }

    pub async fn handle_pong(&self, payload: &Payload) -> Result<()> {
        let generic_packet = payload.packet.as_ref().unwrap();
        assert_eq!(PacketType::try_from(payload.code).unwrap(), PacketType::Pong);

        let packet = generic_packet.as_any().downcast_ref::<PongPacket>().unwrap();

        let nonce = packet.nonce;
        let now = Time::now();

        //Acquire ping stats lock
        let mut stats = self.ping_stats.lock().await;

        if let Some(challenge_nonce) = stats.challenge {
            if nonce != challenge_nonce {
                if nonce == [0; 8] {
                    // info!("Peer sent a zero nonce {}", self.info.address);
                    stats.challenge = None;
                    return Ok(());
                }
                // info!("Peer sent the wrong nonce {}.", self.info.address);
                return Ok(());
            }

            if now >= stats.last_pong {
                stats.last_pong = now;
                if stats.min_ping == 0 {
                    stats.min_ping = now - stats.last_ping;
                }
                stats.min_ping = std::cmp::min(stats.min_ping, now - stats.last_ping);
            } else {
                // info!("Timing mismatch {}", self.info.address);
            }
        } else {
            // info!("Peer sent an unsolicited pong {}", self.info.address);
        }

        stats.challenge = None;

        Ok(())
    }

    pub async fn handle_send_headers(&self) -> Result<()> {
        //Acquire send headers lock.
        let mut prefer_headers = self.prefer_headers.lock().await;

        if *prefer_headers {
            // info!("Peer sent a duplicate sendheaders {}", self.info.address);
            return Ok(());
        };

        *prefer_headers = true;

        Ok(())
    }

    // this.preferHeaders = true;

    // if (!this.network.selfConnect) {
    //   if (this.options.hasNonce(packet.nonce))
    //     throw new Error('We connected to ourself. Oops.');
    // }

    // if (this.version < common.MIN_VERSION)
    //   throw new Error('Peer does not support required protocol version.');

    // if (this.outbound) {
    //   if (!(this.services & services.NETWORK))
    //     throw new Error('Peer does not support network services.');

    //   if (this.options.spv) {
    //     if (!(this.services & services.BLOOM))
    //       throw new Error('Peer does not support BIP37.');
    //   }
    // }

    // this.send(new packets.VerackPacket());
    // this.logger.info(
    //   'Received version (%s): version=%d height=%d services=%s agent=%s',
    //   peer.hostname(),
    //   packet.version,
    //   packet.height,
    //   packet.services.toString(2),
    //   packet.agent);

    // this.network.time.add(peer.hostname(), packet.time);
    // this.nonces.remove(peer.hostname());

    // if (!peer.outbound && packet.remote.isRoutable())
    //   this.hosts.markLocal(packet.remote);

    pub async fn init_version(&mut self) -> Result<()> {
        // TODO: Assume outbound for now

        // Send version
        self.send_version().await?;

        // // Wait for a message
        // let ack = self.next_message().await?;
        // dbg!(ack);

        Ok(())
    }

    //TODO this needs to be tested as I think it might be holding the lock not allowing sending to
    //occur.
    pub async fn next_message(&self) -> Result<Payload> {
        let mut stream = self.stream.lock().await;

        // Read message header
        let mut header = vec![0; 9];
        stream.read_exact(&mut header)?;
        let header_buf = Buffer::from(header.clone());

        // Parse header to get payload size to fetch next
        let mut payload = Payload::parse_header(header_buf)?;

        // Read packet payload
        let mut packet_content = vec![0; payload.packet_size as usize];
        stream.read_exact(&mut packet_content)?;
        payload.decode(Buffer::from(packet_content));

        Ok(payload)
    }

    pub async fn send(&self, packet: Box<dyn Packet>) -> Result<()> {
        println!("LOG: send: packet: {:#?}", packet);

        let payload = Payload::from_packet(packet, self.network).unwrap();
        let encoded = payload.frame(self.network).unwrap().to_vec();

        let mut stream = self.stream.lock().await;
        // dbg!("Encoded packet being sent:");
        // dbg!(&encoded);
        stream.write_all(&encoded)?;
        Ok(())
    }

    pub async fn send_version(&self) -> Result<()> {
        //Need to pass in height dynamically. TODO
        //Also need to pass in no_relay dynamically TODO
        let packet = VersionPacket::new(self.info.address, 0, false);
        //Each packet might have a different timeout requirement -> We should probably set this in
        //the packet struct itself.
        self.send(Box::new(packet)).await?;
        Ok(())
    }

    pub async fn send_verack(&self) -> Result<()> {
        let packet = VerackPacket::new();
        self.send(Box::new(packet)).await?;
        Ok(())
    }

    pub async fn is_connected(&self) -> bool {
        let state = match self.state.lock().await {
            state => state,
            _ => return false,
        };

        State::Connected == *state
    }

    pub fn is_outbound(&self) -> bool {
        Direction::Outbound == self.info.direction
    }

    pub fn set_loader(&self, load: bool) -> Result<()> {
        let mut loader = match self.loader.write() {
            Ok(loader) => loader,
            Err(_) => return Err(Error::LockError),
        };

        *loader = load;

        Ok(())
    }

    pub fn hostname(&self) -> SocketAddr {
        self.info.address.get_socket_addr()
    }

    // pub async fn receive_version(&mut self, packet: Packet::Version) -> Result<()> {
    //     if self.info.version

    // }
    // async handleVersion(packet) {
    // if (this.version !== -1)
    // throw new Error('Peer sent a duplicate version.');

    // this.version = packet.version;
    // this.services = packet.services;
    // this.height = packet.height;
    // this.agent = packet.agent;
    // this.noRelay = packet.noRelay;
    // this.local = packet.remote;
    // // set the peer's key on their local address
    // this.local.setKey(this.address.getKey());

    // if (!this.network.selfConnect) {
    // if (this.options.hasNonce(packet.nonce))
    // throw new Error('We connected to ourself. Oops.');
    // }

    // if (this.version < common.MIN_VERSION)
    // throw new Error('Peer does not support required protocol version.');

    // if (this.outbound) {
    // if (!(this.services & services.NETWORK))
    // throw new Error('Peer does not support network services.');

    // if (this.options.spv) {
    // if (!(this.services & services.BLOOM))
    //   throw new Error('Peer does not support BIP37.');
    // }
    // }

    // this.send(new packets.VerackPacket());
    // }

    //TODO function that writes to the stream and takes a generic packet.
    //We set lastsend in this function.
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::seeds;
//     use futures::executor;
//     use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//     use std::str::FromStr;

//     // #[test]
//     // fn test_peer_connect() {
//     //     executor::block_on(async {

//     //     let local_key = [1; 32];

//     //     let seeds = seeds::testnet_seed_nodes();
//     //     // let peer_address: NetAddress = seeds[3].parse().unwrap();
//     //     let peer_address: NetAddress = "ak2hy7feae2o5pfzsdzw3cxkxsu3lxypykcl6iphnup4adf2ply6a@138.68.61.31:13038".parse().unwrap();

//     //     dbg!(&peer_address);

//     //     let mut peer = Peer::connect(peer_address, local_key, Network::Testnet).await.unwrap();

//     //     // peer.init_version().await.unwrap();
//     //     peer.handle_messages().await;

//     //     ()
//     // })
//     // }

// }
