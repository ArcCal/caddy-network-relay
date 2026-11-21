from pathlib import Path
p=Path('network-relay-rs/Core/src/backend.rs')
s=p.read_text()
marker='let _ = read.as_ref().set_zero_linger();'
assert s.count(marker)==1
p.write_text(s.replace(marker, '''use std::os::fd::AsRawFd;
                let tcp=read.as_ref();
                if std::env::var("TRACE_DRAIN_LOCAL").as_deref()==Ok("fixed") {tokio::time::sleep(std::time::Duration::from_millis(2)).await;}
                if std::env::var("TRACE_DRAIN_LOCAL").as_deref()==Ok("1") {
                    for _ in 0..32 {
                        let mut queued=0i32;
                        let mut len=std::mem::size_of_val(&queued) as libc::socklen_t;
                        let result=unsafe {libc::getsockopt(tcp.as_raw_fd(),libc::SOL_SOCKET,0x1024,(&mut queued as *mut i32).cast(),&mut len)};
                        assert_eq!(result,0);
                        if queued==0 {break}
                        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    }
                }
                eprintln!("TRACE abort {:?} {:?}",tcp.peer_addr(),tcp.set_zero_linger());'''))
