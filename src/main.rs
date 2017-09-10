extern crate futures;
extern crate sunray;
extern crate tokio_proto;
extern crate tokio_service;

use sunray::*;

use std::io;

use futures::{future, Future};
use tokio_proto::TcpServer;
use tokio_service::Service;

struct AuthenticationService;

impl Service for AuthenticationService {
    type Request = AuthMessage;
    type Response = AuthMessage;

    type Error = io::Error;

    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        println!("{:?}", req);
        Box::new(future::ok(req))
    }
}

fn main() {
    let addr = "0.0.0.0:7009".parse().unwrap();

    let server = TcpServer::new(AuthProto, addr);
    server.serve(|| Ok(AuthenticationService));
}
