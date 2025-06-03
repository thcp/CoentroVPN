use shared_utils::crypto::aes_gcm::AesGcmCipher;
use shared_utils::proto::framing::{Frame, FrameType, FrameFlags, StreamFramer}; // Corrected import
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{interval, Duration};
use std::sync::Arc;
use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;

const SERVER_ADDR: &str = "127.0.0.1:8080";
const NUM_CLIENTS: usize = 100;
const TEST_DURATION_SECS: u64 = 30;
const DATA_SIZE_BYTES: usize = 1024;

// Server-side handler for a single client connection
async fn handle_client_connection(mut socket: TcpStream, cipher: Arc<AesGcmCipher>, client_addr: std::net::SocketAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("Handling connection from: {}", client_addr);
    let mut stream_framer = StreamFramer::new(); // Each connection gets its own framer
    let mut buffer = vec![0; DATA_SIZE_BYTES * 2];

    loop {
        match socket.read(&mut buffer).await {
            Ok(0) => {
                println!("Connection closed by {}", client_addr);
                break;
            }
            Ok(n) => {
                let encrypted_data_received = &buffer[..n];
                match cipher.decrypt(encrypted_data_received) {
                    Ok(framed_data) => {
                        match stream_framer.process_data(&framed_data) {
                            Ok(_) => {
                                while let Some(frame) = stream_framer.next_frame() {
                                    let response_payload = frame.payload.clone();
                                    // Explicitly handle Frame::new error
                                    match Frame::new(FrameType::Data, FrameFlags::new(), response_payload) {
                                        Ok(response_frame_obj) => {
                                            let framed_response = stream_framer.encode(&response_frame_obj);
                                            // Explicitly handle cipher.encrypt error
                                            match cipher.encrypt(&framed_response) {
                                                Ok(encrypted_response) => {
                                                    if let Err(e) = socket.write_all(&encrypted_response).await {
                                                        eprintln!("Error writing response to {}: {}", client_addr, e);
                                                        // Propagate the error to ensure the handler's error is logged by the spawner
                                                        return Err(Box::new(e)); 
                                                    }
                                                }
                                                Err(e) => {
                                                    eprintln!("Server: Error encrypting response for {}: {}", client_addr, e);
                                                    // Consider breaking the inner loop or returning if encryption fails
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Server: Error creating response frame for {}: {}", client_addr, e);
                                            // Consider breaking the inner loop or returning
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Server: Error processing framed data from {}: {}", client_addr, e);
                                // This error implies that the data, even after successful decryption, was not valid frame data.
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Server: Error decrypting data from {}: {} ({} bytes received)", client_addr, e, encrypted_data_received.len());
                        // This means the raw encrypted data could not be decrypted.
                        // This is a more fundamental issue than a framing error after successful decryption.
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from socket {}: {}", client_addr, e);
                break;
            }
        }
    }
    Ok(())
}

async fn run_server(cipher: Arc<AesGcmCipher>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(SERVER_ADDR).await?;
    println!("Server listening on {}", SERVER_ADDR);

    loop {
        let (socket, addr) = listener.accept().await?;
        let server_cipher_clone = Arc::clone(&cipher);
        tokio::spawn(async move {
            if let Err(e) = handle_client_connection(socket, server_cipher_clone, addr).await {
                eprintln!("Handler for {} error: {}", addr, e);
            }
        });
    }
}

async fn run_client(id: usize, cipher: Arc<AesGcmCipher>) -> Result<(), Box<dyn Error + Send + Sync>> {
    match TcpStream::connect(SERVER_ADDR).await {
        Ok(mut stream) => {
            println!("Client {} connected to {}", id, SERVER_ADDR);
            let mut data_to_send = vec![0u8; DATA_SIZE_BYTES];
            OsRng.fill_bytes(&mut data_to_send);

            let client_framer = StreamFramer::new(); // Client's own framer for sending (encode takes &self)
            let mut client_response_framer = StreamFramer::new(); // Client's own framer for receiving responses (process_data takes &mut self)

            let mut send_interval = interval(Duration::from_millis(100));
            let test_end_time = tokio::time::Instant::now() + Duration::from_secs(TEST_DURATION_SECS);
            let mut packets_sent = 0;
            let mut packets_received = 0;
            let mut read_buffer = vec![0; DATA_SIZE_BYTES * 2]; // Buffer for reading responses

            while tokio::time::Instant::now() < test_end_time {
                tokio::select! {
                    _ = send_interval.tick() => {
                        let frame_to_send_obj = Frame::new(FrameType::Data, FrameFlags::new(), data_to_send.clone())?;
                        let framed_data = client_framer.encode(&frame_to_send_obj);
                        if let Ok(encrypted_data) = cipher.encrypt(&framed_data) {
                            if stream.write_all(&encrypted_data).await.is_err() {
                                eprintln!("Client {}: Error sending data", id);
                                return Ok(());
                            }
                            packets_sent += 1;
                        } else {
                            eprintln!("Client {}: Error encrypting data", id);
                        }
                    }
                    read_result = stream.read(&mut read_buffer) => {
                        match read_result {
                            Ok(0) => {
                                println!("Client {}: Server closed connection", id);
                                return Ok(());
                            }
                            Ok(n) => {
                                let received_encrypted_data = &read_buffer[..n];
                                if let Ok(decrypted_framed_data) = cipher.decrypt(received_encrypted_data) {
                                     match client_response_framer.process_data(&decrypted_framed_data) {
                                        Ok(_) => {
                                            while let Some(_response_frame) = client_response_framer.next_frame() {
                                                packets_received += 1;
                                                // println!("Client {}: Received and deframed {} bytes", id, response_frame.payload.len());
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Client {}: Error processing server response: {}", id, e);
                                        }
                                     }
                                } else {
                                    eprintln!("Client {}: Error decrypting response ({} bytes received)", id, n);
                                }
                            }
                            Err(e) => {
                                eprintln!("Client {}: Error reading from socket: {}", id, e);
                                return Ok(());
                            }
                        }
                    }
                }
            }
            println!("Client {}: Test finished. Sent: {}, Received: {}", id, packets_sent, packets_received);
        }
        Err(e) => {
            eprintln!("Client {}: Failed to connect to server: {}", id, e);
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = Arc::new(AesGcmCipher::new(&key).expect("Failed to create cipher")); // Handle Result

    // Start the server in a separate task
    let server_cipher_clone = Arc::clone(&cipher);
    tokio::spawn(async move {
        if let Err(e) = run_server(server_cipher_clone).await { // Removed framer from here
            eprintln!("Server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut client_handles = Vec::new();
    for i in 0..NUM_CLIENTS {
        let client_cipher_clone = Arc::clone(&cipher);
        // Client creates its own StreamFramer internally now
        let handle = tokio::spawn(async move {
            if let Err(e) = run_client(i, client_cipher_clone).await { // Removed framer from here
                eprintln!("Client {} error: {}", i, e);
            }
        });
        client_handles.push(handle);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    for handle in client_handles {
        handle.await?;
    }

    println!("Stress test completed.");
    Ok(())
}
