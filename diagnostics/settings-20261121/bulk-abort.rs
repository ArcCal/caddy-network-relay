
#[cfg(test)]
mod measured_bulk_abort {
    use super::*;
    use std::io::Read;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_bulk_abort_delivery() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr=listener.local_addr().unwrap();
        let payload=vec![0x58;8*1024*1024];
        let mut reset=0;
        let mut timeout=0;
        for _ in 0..32 {
            let reader=std::thread::spawn(move || {
                let mut p=std::net::TcpStream::connect(addr).unwrap();
                p.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut buf=[0;65536];
                loop {
                    match p.read(&mut buf) {
                        Ok(0) => panic!("truncated stream delivered EOF"),
                        Ok(_) => continue,
                        Err(e) => return e.kind()
                    }
                }
            });
            let (sock,_) = listener.accept().await.unwrap();
            sock.set_nodelay(true).unwrap();
            let stream=Stream::tcp(sock,CancellationToken::new()).unwrap();
            stream.write.lock().await.write_all(&payload).await.unwrap();
            stream.reset(0,true).await;
            drop(stream);
            match reader.join().unwrap() {
                io::ErrorKind::ConnectionReset => reset+=1,
                io::ErrorKind::TimedOut|io::ErrorKind::WouldBlock => timeout+=1,
                e=>panic!("unexpected read error: {e:?}"),
            }
        }
        eprintln!("BULK-CLOSE local={:?} reset={reset} timeout={timeout}",std::env::var("TRACE_DRAIN_LOCAL"));
    }
}
