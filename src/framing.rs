// Length-prefixed frame reader
use std::io::{self, ErrorKind, Read};

/// Stateful reader for [len:4][body:len]
pub struct FrameReader {
    // Partial length bytes
    len_buf: [u8; 4],
    len_filled: usize,

    // Current body progress
    body_len: usize,
    body_filled: usize,

    // Hard cap
    max_frame_len: usize,
}

impl FrameReader {
    /// New reader with max frame cap
    pub fn new(max_frame_len: usize) -> Self {
        Self {
            len_buf: [0; 4],
            len_filled: 0,
            body_len: 0,
            body_filled: 0,
            max_frame_len,
        }
    }

    /// Try read next full frame
    /// Returns Ok(Some(len)) when complete
    pub fn read_next<R: Read>(
        &mut self,
        reader: &mut R,
        body_buf: &mut Vec<u8>,
    ) -> io::Result<Option<usize>> {
        // Read 4-byte BE length
        if self.len_filled < 4 {
            loop {
                match reader.read(&mut self.len_buf[self.len_filled..]) {
                    Ok(0) => {
                        // EOF while reading length
                        if self.len_filled == 0 {
                            return Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "connection closed while reading frame length",
                            ));
                        } else {
                            return Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "truncated frame length",
                            ));
                        }
                    }
                    Ok(n) => {
                        self.len_filled += n;
                        if self.len_filled < 4 {
                            // Need more
                            continue;
                        }

                        let len = u32::from_be_bytes(self.len_buf) as usize;
                        // Validate length
                        if len == 0 || len > self.max_frame_len {
                            return Err(io::Error::new(
                                ErrorKind::InvalidData,
                                format!("invalid frame length: {}", len),
                            ));
                        }

                        // Prepare body buffer
                        self.body_len = len;
                        self.body_filled = 0;
                        body_buf.clear();
                        body_buf.resize(len, 0);
                        break;
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        // No data yet
                        return Err(io::Error::new(ErrorKind::WouldBlock, "would block"));
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // Read body bytes
        while self.body_filled < self.body_len {
            match reader.read(&mut body_buf[self.body_filled..self.body_len]) {
                Ok(0) => {
                    // EOF mid-frame
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "truncated frame body"));
                }
                Ok(n) => {
                    self.body_filled += n;
                    if self.body_filled == self.body_len {
                        // Frame complete
                        let len = self.body_len;
                        self.reset_frame_state();
                        return Ok(Some(len));
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    // Partial frame, continue later
                    return Err(io::Error::new(ErrorKind::WouldBlock, "would block"));
                }
                Err(e) => return Err(e),
            }
        }

        // Should not happen
        Ok(None)
    }

    /// Reset for next frame
    fn reset_frame_state(&mut self) {
        self.len_buf = [0; 4];
        self.len_filled = 0;
        self.body_len = 0;
        self.body_filled = 0;
    }
}