//! End-to-end local protocol evidence. This fake WARP peer is not Cloudflare.
//! Every business connection crosses WarpEgress's real userspace packet pump.
mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use network_relay::{auth, check};
use sha2::{Digest, Sha256};
use support::persistent::{PersistentFlows, PersistentTcp, PersistentUdp};
use support::relay::{TestEnv, TestRelay, PASSWORD, USER, WAIT};
use support::warp_peer::{peer_addr, WarpPeer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use warp_masque_egress::{Egress, Transport, WarpEgress};

const BULK_BYTES: usize = 64 << 20;
const CHUNK: usize = 64 << 10;

struct Fixture {
    _env: TestEnv,
    peer: WarpPeer,
    warp: Arc<WarpEgress>,
    relay: TestRelay,
}
impl Fixture {
    async fn start(transport: Transport) -> Result<Self> {
        Self::start_with_sockets(transport, None).await
    }
    /// With `max_sockets` set, the egress's socket limit no longer depends on
    /// the memory of the machine running the test.
    async fn start_with_sockets(transport: Transport, max_sockets: Option<usize>) -> Result<Self> {
        let label = match transport {
            Transport::H2 => "h2",
            Transport::H3 => "h3",
        };
        let env = TestEnv::new(label)?;
        let peer = WarpPeer::start(transport).await?;
        let mut config = peer.config(&env.path)?;
        config.max_sockets = max_sockets.or(config.max_sockets);
        let warp = Arc::new(
            tokio::time::timeout(WAIT, WarpEgress::connect(&config)).await.context("WARP handshake deadline")??,
        );
        let relay = TestRelay::start(&env, warp.clone()).await?;
        Ok(Self { _env: env, peer, warp, relay })
    }
    async fn finish(mut self) -> Result<()> {
        self.relay.shutdown().await?;
        self.warp.shutdown().await;
        ensure!(!self.warp.available(), "shutdown left egress available");
        ensure!(self.warp.status().workers == 0, "egress workers survived shutdown");
        let _ = self.peer.shutdown().await;
        Ok(())
    }
}


#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn old_limits() -> Result<()> {
    for transport in [Transport::H2,Transport::H3] {
        let fixture=Fixture::start_with_sockets(transport,Some(256)).await?;
        let opts=fixture.relay.options();
        let mut a=check::H3::connect(&opts,&opts.addresses).await?;
        let mut b=check::H3::connect(&opts,&opts.addresses).await?;
        async fn open(h:&mut check::H3,user:&str)->Result<(StatusCode,check::H3ClientStream)> {
            let req=Request::builder().method(Method::CONNECT).uri("fixture.test:7").header("proxy-authorization",auth::basic_authorization(user,PASSWORD)).body(())?;
            let mut s=h.request(req).await?;
            Ok((tokio::time::timeout(WAIT,s.recv_response()).await??.status(),s))
        }
        let mut held=vec![];
        for _ in 0..32 {let (status,s)=open(&mut a,USER).await?; ensure!(status==StatusCode::OK,"{status}"); held.push(s);}
        ensure!(open(&mut a,USER).await?.0==StatusCode::SERVICE_UNAVAILABLE);
        for _ in 0..16 {let (status,s)=open(&mut b,"second").await?;ensure!(status==StatusCode::OK,"{status}");held.push(s);}
        ensure!(open(&mut b,"second").await?.0==StatusCode::SERVICE_UNAVAILABLE);
        ensure!(fixture.relay.relay.active_tunnels()==48);
        let mut last=held.pop().unwrap();last.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);last.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);drop(last);
        tokio::time::timeout(WAIT,async {while fixture.relay.relay.active_tunnels()!=47 {tokio::time::sleep(Duration::from_millis(10)).await;}}).await?;
        let (status,mut s)=open(&mut b,"second").await?;ensure!(status==StatusCode::OK);
        s.send_data(Bytes::from_static(b"refunded")).await?;
        let mut got=tokio::time::timeout(WAIT,s.recv_data()).await??.context("peer EOF")?;
        ensure!(got.copy_to_bytes(got.remaining()).as_ref()==b"refunded");
        println!("{transport:?}: A32 OK, A33=503, B16 OK (48 held), B17=503, release one and readmitted echo OK");
        drop((s,held,a,b));
        fixture.finish().await?;
    }
    Ok(())
}
