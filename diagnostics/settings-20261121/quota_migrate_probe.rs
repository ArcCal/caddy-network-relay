// Run against the real WARP CLI with a private loopback enrollment and echo target.
mod support;
use anyhow::{ensure, Context, Result};
use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use network_relay::{auth, check};
use std::{process::{Child, Command, Stdio}, time::Duration};
use support::{relay::{TestEnv, PASSWORD, USER, WAIT}, warp_peer::WarpPeer};
use warp_masque_egress::Transport;
const BIN: &str = env!("CARGO_BIN_EXE_network-relay-cf-masque");
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn open(client: &mut check::H3, user: &str) -> Result<(StatusCode, check::H3ClientStream)> {
    let request = Request::builder().method(Method::CONNECT).uri("fixture.test:7")
        .header("proxy-authorization", auth::basic_authorization(user,PASSWORD)).body(())?;
    let mut stream = client.request(request).await?;
    let status = tokio::time::timeout(WAIT,stream.recv_response()).await??.status();
    Ok((status,stream))
}
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn explicit_quota_then_remove_and_restart() -> Result<()> {
    let hash = auth::hash_password(PASSWORD)?;
    for mode in [Transport::H2, Transport::H3] {
        let env = TestEnv::new("quota-migration")?;

        let addr=std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;

        let old = "max_tunnels = 48\nmax_tunnels_per_user = 32\n";
        for (case, remove_total, remove_user, a, b, block_a, block_b) in [
            ("legacy",false,false,32,16,true,true),
            ("remove-total",true,false,32,24,true,false),
            ("remove-user",false,true,40,8,false,true),
            ("remove-both",true,true,40,24,false,false),
        ] {
        // The protocol fixture accepts exactly one outer WARP connection.
        let mut peer = WarpPeer::start(mode).await?;
        let settings = peer.settings();
        let config=format!("listen = '{addr}'\n[tls]\ncert = {:?}\nkey = {:?}\n[web]\nroot = {:?}\n[relay]\nblocked_destinations=[]\nblocked_ports=[]\nblock_own_addresses=false\n{old}[[user]]\nname='{USER}'\npassword_hash='{hash}'\n[[user]]\nname='second'\npassword_hash='{hash}'\n{settings}",env.path.join("fullchain.pem"),env.path.join("privkey.pem"), env.path.join("site"));
        let path=env.path.join("relay.toml");
            let mut effective=config;
            if remove_total {effective=effective.replace("max_tunnels = 48\n","");}
            if remove_user {effective=effective.replace("max_tunnels_per_user = 32\n","");}
            std::fs::write(&path,effective)?;
            let mut command=Command::new(BIN);
            command.args(["serve","--config"]).arg(&path);
            let checked=Command::new(BIN).args(["serve","--config"]).arg(&path).arg("--check").output()?;
            ensure!(checked.status.success());
            println!("{mode:?} configuration={case} {}",String::from_utf8_lossy(&checked.stdout).trim());
            let mut server=Server(command.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?);
            tokio::time::timeout(WAIT,async {
                loop {
                    ensure!(server.0.try_wait()?.is_none(),"relay startup failed");
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {return Ok::<_,anyhow::Error>(());}
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await??;
            let opts=check::Options {host:"relay.test".into(),port:addr.port(),addresses:vec![addr],
                user:USER.into(),password:PASSWORD.into(),udp_template:network_relay::proto::DEFAULT_UDP_PATH_TEMPLATE.into(),
                tcp_target:"fixture.test:7".into(),udp_target:("fixture.test".into(),53),dns_name:"fixture.test".into(),
                ca:Some(env.path.join("ca.pem")),client_cert:None,timeout:WAIT};
            let mut client = check::H3::connect(&opts,&opts.addresses).await?;
            let mut held = Vec::new();
            for (user,count,blocked) in [(USER,a,block_a),("second",b,block_b)] {
                for _ in 0..count {
                    let (status, stream)=open(&mut client,user).await?;
                    ensure!(status==StatusCode::OK,"admission returned {status} with {} held",held.len());
                    held.push(stream);
                }
                if blocked {ensure!(open(&mut client,user).await?.0==StatusCode::SERVICE_UNAVAILABLE);}
            }
            for (i,s) in held.iter_mut().enumerate() {
                let payload = Bytes::from(vec![i as u8,42]);
                s.send_data(payload.clone()).await?;
                let mut echo=tokio::time::timeout(WAIT,s.recv_data()).await??.context("unexpected EOF")?;
                ensure!(echo.copy_to_bytes(echo.remaining())==payload);
            }
            println!("{mode:?} configuration={case} authenticated and echoed {} concurrent tunnels",held.len());
            drop((held,client,server));
            peer.shutdown().await;
        }
    }
    Ok(())
}
