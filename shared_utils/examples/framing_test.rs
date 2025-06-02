//! A simple test for the Stream Framing protocol.
//!
//! This example demonstrates how to use the Stream Framing protocol
//! in a more realistic scenario with a simulated client and server.

use shared_utils::proto::framing::{Frame, FrameType, StreamFramer};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn main() -> io::Result<()> {
    // Start the server in a separate thread
    let server_thread = thread::spawn(|| {
        if let Err(e) = run_server() {
            eprintln!("Server error: {}", e);
        }
    });

    // Give the server a moment to start
    thread::sleep(Duration::from_millis(100));

    // Run the client
    if let Err(e) = run_client() {
        eprintln!("Client error: {}", e);
    }

    // Wait for the server to finish
    server_thread.join().unwrap();

    Ok(())
}

fn run_server() -> io::Result<()> {
    println!("Starting server on 127.0.0.1:8080");
    let listener = TcpListener::bind("127.0.0.1:8080")?;

    for stream in listener.incoming() {
        let mut stream = stream?;
        println!(
            "Server: Connection established from {}",
            stream.peer_addr()?
        );

        // Create a stream framer for decoding incoming frames
        let mut framer = StreamFramer::new();
        let mut buffer = [0u8; 1024];

        // Handle multiple frames from the client
        loop {
            // Read data from the client
            let n = match stream.read(&mut buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Server: Read error: {}", e);
                    break;
                }
            };

            println!("Server: Received {} bytes", n);

            // Process the data and decode frames
            let frame_count = match framer.process_data(&buffer[..n]) {
                Ok(count) => count,
                Err(e) => {
                    eprintln!("Server: Frame processing error: {}", e);
                    break;
                }
            };

            println!("Server: Decoded {} frames", frame_count);

            // Process each frame
            while let Some(frame) = framer.next_frame() {
                println!("Server: Received frame: {:?}", frame);
                println!(
                    "Server: Frame payload: {:?}",
                    String::from_utf8_lossy(&frame.payload)
                );

                // Create a response frame
                let response = match frame.frame_type {
                    FrameType::Data => {
                        let response_data = format!(
                            "Received your data: {}",
                            String::from_utf8_lossy(&frame.payload)
                        )
                        .into_bytes();
                        Frame::new_data(response_data).unwrap()
                    }
                    FrameType::Control => {
                        let response_data = b"Control acknowledged".to_vec();
                        Frame::new_control(response_data).unwrap()
                    }
                    FrameType::Keepalive => Frame::new_keepalive().unwrap(),
                    FrameType::Config => {
                        let response_data = b"Config applied".to_vec();
                        Frame::new_config(response_data).unwrap()
                    }
                    FrameType::Error => {
                        let response_data = b"Error received".to_vec();
                        Frame::new_error(response_data).unwrap()
                    }
                };

                // Encode and send the response
                let encoded = framer.encode(&response);
                if let Err(e) = stream.write_all(&encoded) {
                    eprintln!("Server: Write error: {}", e);
                    return Err(e);
                }
                println!("Server: Sent response frame: {:?}", response);
            }
        }

        println!("Server: Client disconnected");
    }

    Ok(())
}

fn run_client() -> io::Result<()> {
    println!("Client: Connecting to server at 127.0.0.1:8080");
    let mut stream = TcpStream::connect("127.0.0.1:8080")?;
    println!("Client: Connected to server");

    // Create a stream framer for encoding/decoding frames
    let mut framer = StreamFramer::new();

    // Create different types of frames to send
    let frames = vec![
        Frame::new_data(b"Hello from client!".to_vec()).unwrap(),
        Frame::new_control(b"Control message".to_vec()).unwrap(),
        Frame::new_config(b"Config request".to_vec()).unwrap(),
    ];

    // Send each frame and receive the response
    for frame in frames {
        println!("Client: Sending frame: {:?}", frame);
        println!(
            "Client: Frame payload: {:?}",
            String::from_utf8_lossy(&frame.payload)
        );

        // Encode and send the frame
        let encoded = framer.encode(&frame);
        stream.write_all(&encoded)?;

        // Read the response
        let mut buffer = [0u8; 1024];
        let n = stream.read(&mut buffer)?;
        println!("Client: Received {} bytes", n);

        // Process the response
        let frame_count = framer.process_data(&buffer[..n]).unwrap();
        println!("Client: Decoded {} frames", frame_count);

        // Get the response frame
        if let Some(response) = framer.next_frame() {
            println!("Client: Received response frame: {:?}", response);
            println!(
                "Client: Response payload: {:?}",
                String::from_utf8_lossy(&response.payload)
            );
        }

        // Add a small delay between frames
        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
