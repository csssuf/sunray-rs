//! Implementation of the Sun Ray Authentication Server.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::str;
use std::u32;

use bytes::BytesMut;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Decoder, Encoder, Framed};
use tokio_proto::pipeline::ServerProto;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AuthMessageType {
    InfoReq,
    KeepAliveReq,
    KeepAliveCnf,
    DiscInf,
    DiscRsp,
    ConnInf,
    ConnRsp,
    Unknown,
    Empty,
}

impl Default for AuthMessageType {
    fn default() -> AuthMessageType {
        AuthMessageType::Empty
    }
}

impl fmt::Display for AuthMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AuthMessageType::InfoReq => write!(f, "infoReq"),
            AuthMessageType::KeepAliveReq => write!(f, "keepAliveReq"),
            AuthMessageType::KeepAliveCnf => write!(f, "keepAliveCnf"),
            AuthMessageType::DiscInf => write!(f, "discInf"),
            AuthMessageType::DiscRsp => write!(f, "discRsp"),
            AuthMessageType::ConnInf => write!(f, "connInf"),
            AuthMessageType::ConnRsp => write!(f, "connRsp"),
            AuthMessageType::Empty => write!(f, "empty"),
            _ => write!(f, "unknown"),
        }
    }
}

impl<'a> From<&'a str> for AuthMessageType {
    fn from(s: &'a str) -> Self {
        match s {
            "infoReq" => AuthMessageType::InfoReq,
            "keepAliveReq" => AuthMessageType::KeepAliveReq,
            "keepAliveCnf" => AuthMessageType::KeepAliveCnf,
            "discInf" => AuthMessageType::DiscInf,
            "discRsp" => AuthMessageType::DiscRsp,
            "connInf" => AuthMessageType::ConnInf,
            "connRsp" => AuthMessageType::ConnRsp,
            _ => AuthMessageType::Unknown,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuthMessage {
    pub message_type: AuthMessageType,
    pub mtu: Option<u32>,
    pub barrier_level: Option<u64>,
    pub cause: Option<String>,
    pub client_rand: Option<String>,
    pub ddc_config: Option<u32>,
    pub event: Option<String>,
    pub first_server: Option<IpAddr>,
    pub fw: Option<String>,
    pub hw: Option<String>,
    pub id: Option<String>,
    pub init_state: Option<u32>,
    pub key_types: Option<Vec<String>>,
    pub namespace: Option<String>,
    pub pn: Option<u32>,
    pub real_ip: Option<IpAddr>,
    pub sn: Option<String>,
    pub state: Option<String>,
    pub token_seq: Option<u32>,
    pub type_: Option<String>,
    pub access: Option<String>,
}

pub struct AuthCodec;

impl Decoder for AuthCodec {
    type Item = AuthMessage;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<AuthMessage>, io::Error> {
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let line = buf.split_to(i);
            buf.split_to(1);

            return match str::from_utf8(line.as_ref()) {
                Ok(s) => {
                    let mut out = AuthMessage::default();

                    let mut split_str = s.split_whitespace();

                    if let Some(message_type) = split_str.next() {
                        out.message_type = AuthMessageType::from(message_type);
                    } else {
                        return Err(io::Error::new(io::ErrorKind::Other, "no message type"));
                    }

                    for kv_pair_str in split_str {
                        let kv_pair: Vec<&str> = kv_pair_str.split('=').collect();

                        if kv_pair.len() != 2 {
                            return Err(io::Error::new(io::ErrorKind::Other, "bad key/value pair"));
                        }

                        let key = kv_pair[0];
                        let value = kv_pair[1];

                        match key {
                            "MTU" => out.mtu = Some(value.parse().expect("not an integer")),
                            "barrierLevel" => {
                                out.barrier_level = Some(value.parse().expect("not an integer"))
                            }
                            "cause" => out.cause = Some(value.to_owned()),
                            "clientRand" => out.client_rand = Some(value.to_owned()),
                            "ddcconfig" => {
                                out.ddc_config = Some(value.parse().expect("not an integer"))
                            }
                            "event" => out.event = Some(value.to_owned()),
                            "firstServer" => {
                                // TODO: ipv6?
                                let value =
                                    u32::from_str_radix(value, 16).expect("not a hex integer");
                                out.first_server = Some(IpAddr::V4(Ipv4Addr::from(value)))
                            }
                            "fw" => out.fw = Some(value.to_owned()),
                            "hw" => out.hw = Some(value.to_owned()),
                            "id" => out.id = Some(value.to_owned()),
                            "initState" => {
                                out.init_state = Some(value.parse().expect("not an integer"))
                            }
                            "keyTypes" => {
                                let key_type_list = value.split(',');
                                let mut key_types = Vec::new();

                                for key_type in key_type_list {
                                    key_types.push(key_type.to_owned());
                                }

                                out.key_types = Some(key_types);
                            }
                            "namespace" => out.namespace = Some(value.to_owned()),
                            "pn" => out.pn = Some(value.parse().expect("not an integer")),
                            "realIP" => {
                                // TODO: ipv6?
                                let value =
                                    u32::from_str_radix(value, 16).expect("not a hex integer");
                                out.real_ip = Some(IpAddr::V4(Ipv4Addr::from(value)))
                            }
                            "sn" => out.sn = Some(value.to_owned()),
                            "state" => out.state = Some(value.to_owned()),
                            "tokenSeq" => {
                                out.token_seq = Some(value.parse().expect("not an integer"))
                            }
                            "type" => out.type_ = Some(value.to_owned()),
                            _ => {}
                        }
                    }

                    Ok(Some(out))
                }
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "invalid string")),
            };
        }

        Ok(None)
    }
}

impl Encoder for AuthCodec {
    type Item = AuthMessage;
    type Error = io::Error;

    fn encode(&mut self, msg: AuthMessage, buf: &mut BytesMut) -> Result<(), io::Error> {
        if msg.message_type == AuthMessageType::Empty {
            return Ok(());
        }

        let mut out = String::from(format!("{}", msg.message_type));

        if let Some(access) = msg.access {
            out += format!(" access={}", access).as_str();
        }

        if let Some(token_seq) = msg.token_seq {
            out += format!(" tokenSeq={}", token_seq).as_str();
        }

        buf.extend(out.as_bytes());
        buf.extend(b"\n");
        Ok(())
    }
}

pub struct AuthProto;

impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for AuthProto {
    type Request = AuthMessage;
    type Response = AuthMessage;
    type Transport = Framed<T, AuthCodec>;
    type BindTransport = ::std::result::Result<Self::Transport, io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Ok(io.framed(AuthCodec))
    }
}
