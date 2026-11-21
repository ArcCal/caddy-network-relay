from pathlib import Path
p=Path('clients/network-relay-rs/Core/src/backend.rs');s=p.read_text()
i=s.index('{',s.index('fn report('))+1
s=s[:i]+'\n    eprintln!("CLOSE-RS backend error id={id} error={error}");'+s[i:]
s=s.replace('let removed = locked(&state).remove_tree(event.id);','eprintln!("CLOSE-RS close request id={} flags={}", event.id,event.flags);\n                let removed = locked(&state).remove_tree(event.id);')
s=s.replace('let _ = read.as_ref().set_zero_linger();','eprintln!("CLOSE-RS local abort peer={:?} linger={:?}",read.peer_addr(),read.as_ref().set_zero_linger());')
p.write_text(s)
p=Path('clients/network-relay-rs/Core/src/socks.rs');s=p.read_text().replace('                        io.abort();','                        eprintln!("CLOSE-RS SOCKS error peer={peer} id={} error={e}",io.id());\n                        io.abort();')
p.write_text(s)
