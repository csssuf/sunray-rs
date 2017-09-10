//! Implementation of the Sun Ray Authentication Server.

use std::fmt;
use std::io;
use std::str;

use bytes::BytesMut;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Encoder, Decoder, Framed};
use tokio_proto::pipeline::ServerProto;

#[derive(Copy, Clone, Debug)]
pub enum AuthMessageType {
    InfoReq,
    KeepAliveReq,
    DiscInf,
    ConnInf,
    DiscRsp,
    ConnRsp,
    Unknown,
}

impl Default for AuthMessageType {
    fn default() -> AuthMessageType {
        AuthMessageType::Unknown
    }
}

impl fmt::Display for AuthMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AuthMessageType::InfoReq => write!(f, "infoReq"),
            AuthMessageType::KeepAliveReq => write!(f, "keepAliveReq"),
            AuthMessageType::DiscInf => write!(f, "discInf"),
            AuthMessageType::ConnInf => write!(f, "connInf"),
            AuthMessageType::DiscRsp => write!(f, "discRsp"),
            AuthMessageType::ConnRsp => write!(f, "connRsp"),
            _ => write!(f, "unknown"),
        }
    }
}

impl<'a> From<&'a str> for AuthMessageType {
    fn from(s: &'a str) -> Self {
        match s {
            "infoReq" => AuthMessageType::InfoReq,
            "keepAliveReq" => AuthMessageType::KeepAliveReq,
            "discInf" => AuthMessageType::DiscInf,
            "connInf" => AuthMessageType::ConnInf,
            "discRsp" => AuthMessageType::DiscRsp,
            "connRsp" => AuthMessageType::ConnRsp,
            _ => AuthMessageType::Unknown,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuthMessage {
    message_type: AuthMessageType,
    mtu: Option<u32>,
    barrier_level: Option<u64>,
    cause: Option<String>,
    client_rand: Option<String>,
    ddc_config: Option<u32>,
    event: Option<String>,
    // TODO: first_server is actually an ip address
    first_server: Option<String>,
    fw: Option<String>,
    hw: Option<String>,
    id: Option<String>,
    init_state: Option<u32>,
    key_types: Option<Vec<String>>,
    namespace: Option<String>,
    pn: Option<u32>,
    // TODO: real_ip is actually an ip address
    real_ip: Option<String>,
    sn: Option<String>,
    state: Option<String>,
    token_seq: Option<u32>,
    type_: Option<String>,
}

pub struct AuthCodec;

impl Decoder for AuthCodec {
    type Item = AuthMessage;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<AuthMessage>, io::Error> {
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let line = buf.split_to(i);
            buf.split_to(1);

            return match str::from_utf8(&line.as_ref()) {
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
                            "barrierLevel" => out.barrier_level = Some(value.parse().expect("not an integer")),
                            "cause" => out.cause = Some(value.to_owned()),
                            "clientRand" => out.client_rand = Some(value.to_owned()),
                            "ddcconfig" => out.ddc_config = Some(value.parse().expect("not an integer")),
                            "event" => out.event = Some(value.to_owned()),
                            "firstServer" => out.first_server = Some(value.to_owned()),
                            "fw" => out.fw = Some(value.to_owned()),
                            "hw" => out.hw = Some(value.to_owned()),
                            "id" => out.id = Some(value.to_owned()),
                            "initState" => out.init_state = Some(value.parse().expect("not an integer")),
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
                            "realIP" => out.real_ip = Some(value.to_owned()),
                            "sn" => out.sn = Some(value.to_owned()),
                            "state" => out.state = Some(value.to_owned()),
                            "tokenSeq" => out.token_seq = Some(value.parse().expect("not an integer")),
                            "type" => out.type_ = Some(value.to_owned()),
                            _ => {}
                        }
                    }

                    Ok(Some(out))
                }
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "invalid string")),
            }
        }

        Ok(None)
    }
}

impl Encoder for AuthCodec {
    type Item = AuthMessage;
    type Error = io::Error;

    fn encode(&mut self, _msg: AuthMessage, _buf: &mut BytesMut) -> Result<(), io::Error> {
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
