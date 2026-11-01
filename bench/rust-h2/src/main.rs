//! rust-h2: the `h2` crate (hyper's HTTP/2 implementation) as a server on the HTTP/2 client byte
//! stream bench_h2h3 --dump writes, in memory: a current-thread tokio runtime, an in-memory duplex
//! pipe, the client bytes written in 16 KiB pieces, and a handler that answers 200 with
//! content-type text/plain and the same 13-byte body as the C benchmark. The time covers the whole
//! connection, client side included (it only copies bytes and counts responses), divided by the
//! number of requests. Prints the same "= bench set impl ns" lines as bench_h2h3.
//!
//!     cargo run --release -- DIR [passes]
use bytes::Bytes;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static BODY: &[u8] = b"hello, world\n";

fn records(path: &str) -> Vec<Vec<u8>> {
    let b = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        let n = u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
        out.push(b[i + 4..i + 4 + n].to_vec());
        i += 4 + n;
    }
    out
}

async fn one_conn(client: &[u8], nreq: usize) -> usize {
    let (mut cli, srv) = tokio::io::duplex(1 << 22);
    let server = async move {
        let mut conn = h2::server::Builder::new()
            .max_concurrent_streams(1000)
            .handshake::<_, Bytes>(srv)
            .await
            .unwrap();
        while let Some(r) = conn.accept().await {
            let (_req, mut respond) = r.unwrap();
            let resp = http::Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(())
                .unwrap();
            let mut send = respond.send_response(resp, false).unwrap();
            send.send_data(Bytes::from_static(BODY), true).unwrap();
        }
    };
    let client = async move {
        let (mut rd, mut wr) = tokio::io::split(&mut cli);
        let write = async {
            for chunk in client.chunks(16384) {
                wr.write_all(chunk).await.unwrap();
            }
        };
        let read = async {
            // count DATA frames with END_STREAM until every request is answered
            let (mut buf, mut have, mut done) = (vec![0u8; 1 << 20], 0usize, 0usize);
            while done < nreq {
                let n = rd.read(&mut buf[have..]).await.unwrap();
                assert!(n > 0, "server closed early");
                have += n;
                let mut off = 0;
                while have - off >= 9 {
                    let len = (buf[off] as usize) << 16
                        | (buf[off + 1] as usize) << 8
                        | buf[off + 2] as usize;
                    if have - off < 9 + len {
                        break;
                    }
                    if buf[off + 3] == 0 && buf[off + 4] & 1 != 0 {
                        done += 1;
                    }
                    off += 9 + len;
                }
                buf.copy_within(off..have, 0);
                have -= off;
            }
            done
        };
        let (_, done) = tokio::join!(write, read);
        done
    };
    tokio::select! {
        done = client => done,
        _ = server => 0,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = &args[1];
    let passes: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(100) / 4 + 1;
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut ok = true;
    for set in ["browser", "gRPC", "h2load"] {
        let client = &records(&format!("{dir}/h2client_{set}.bin"))[0];
        let nreq = count_requests(client);
        let mut best = f64::MAX;
        for _ in 0..passes {
            let t0 = Instant::now();
            let done = rt.block_on(one_conn(client, nreq));
            let t = t0.elapsed().as_nanos() as f64 / nreq as f64;
            if done != nreq {
                eprintln!("h2 answered {done} of {nreq}");
                ok = false;
            }
            best = best.min(t);
        }
        println!("= h2server {set} h2-rust {best:.1}");
    }
    if !ok {
        println!("GATE FAILED");
        std::process::exit(1);
    }
    println!("gate: every request answered");
}

/// requests in the client stream: HEADERS or DATA frames with END_STREAM, one per stream
fn count_requests(b: &[u8]) -> usize {
    let (mut off, mut n) = (24, 0); // after the connection preface
    while off + 9 <= b.len() {
        let len = (b[off] as usize) << 16 | (b[off + 1] as usize) << 8 | b[off + 2] as usize;
        if b[off + 3] <= 1 && b[off + 4] & 1 != 0 {
            n += 1;
        }
        off += 9 + len;
    }
    n
}
