//! # Rather Streams
//! Rather streams are used to send and receive data on an ather. The data is encoded in the form of
//! audio signals in the method of phase shift keying (PSK). The stream is composed of a header
//! (8 symbols), a length field (7 symbols with 1 parity symbol), a body (n symbols with
//! maximum 127 symbols) and a checksum field (8 symbols). The header is used to identify the
//! start of a stream. The length field is used to indicate the length of the body. The checksum
//! field is used to verify the integrity of the stream. The body is the actual data to be sent.

// TODO: implement the parity of length field and checksum field

use super::{
    frame::Header,
    signal::{self, BandPass},
    Body, Frame, Preamble, Symbol, Warmup,
};
use crate::raudio::{
    AudioInputStream, AudioOutputStream, AudioSamples, AudioTrack, ContinuousStream,
};
use bitvec::prelude::*;
use cpal::SupportedStreamConfig;
use std::{
    mem,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{self, Poll, Waker},
    time::Duration,
};
use tokio::sync::{
    self,
    mpsc::{self, UnboundedSender},
};
use tokio_stream::{Stream, StreamExt};

const WARMUP_LEN: usize = 8;
const PREAMBLE_LEN: usize = 48;
const LENGTH_LEN: usize = 7;
const PAYLOAD_LEN: usize = (1 << LENGTH_LEN) - 1;
const CORR_THRESHOLD: f32 = 0.15;

#[derive(Debug, Clone)]
pub struct AtherStreamConfig {
    pub frequency: u32,
    pub bit_rate: u32,
    pub warmup: Warmup,
    pub preamble: Preamble,
    pub symbols: (Symbol, Symbol),
    pub stream_config: SupportedStreamConfig,
}

impl AtherStreamConfig {
    pub fn new(frequency: u32, bit_rate: u32, stream_config: SupportedStreamConfig) -> Self {
        let duration = 1.0 / bit_rate as f32;
        let sample_rate = stream_config.sample_rate().0;

        Self {
            frequency,
            bit_rate,
            warmup: Warmup::new(WARMUP_LEN, sample_rate, duration),
            preamble: Preamble::new(PREAMBLE_LEN, sample_rate, duration),
            symbols: Symbol::new(frequency, sample_rate, duration),
            stream_config,
        }
    }
}

pub struct AtherOutputStream {
    config: AtherStreamConfig,
    stream: AudioOutputStream<AudioTrack<f32>>,
}

impl AtherOutputStream {
    pub fn new(config: AtherStreamConfig, stream: AudioOutputStream<AudioTrack<f32>>) -> Self {
        Self { config, stream }
    }
}

impl AtherOutputStream {
    pub async fn write(&self, bits: &BitSlice) {
        let mut frames = vec![create_warmup(&self.config)];
        frames.extend(encode_packet(&self.config, bits));

        let track = AudioTrack::new(
            self.config.stream_config.clone(),
            frames
                .into_iter()
                .map(|frame| frame.into())
                .collect::<Vec<AudioSamples<f32>>>()
                .concat()
                .into(),
        );
        self.stream.write(track).await;
    }

    pub async fn write_timeout(&self, bits: &BitSlice, timeout: Duration) {
        let mut frames = vec![create_warmup(&self.config)];
        frames.extend(encode_packet(&self.config, bits));

        let track = AudioTrack::new(
            self.config.stream_config.clone(),
            frames
                .into_iter()
                .map(|frame| frame.into())
                .collect::<Vec<AudioSamples<f32>>>()
                .concat()
                .into(),
        );
        tokio::select! {
            _ = async {
                self.stream.write(track).await;
            } => {}
            _ = tokio::time::sleep(timeout) => {}
        };
    }
}

fn create_warmup(config: &AtherStreamConfig) -> Frame {
    Frame::new(
        config.stream_config.clone(),
        Header::new(
            config.warmup.clone().into(),
            0usize.encode(config.symbols.clone()),
        ),
        Body::new(vec![]),
    )
}

fn encode_packet(config: &AtherStreamConfig, bits: &BitSlice) -> Vec<Frame> {
    let mut frames = vec![];
    for chunk in bits.chunks(PAYLOAD_LEN) {
        let payload = chunk.encode(config.symbols.clone());
        let length = chunk.len().encode(config.symbols.clone())[..LENGTH_LEN].to_owned();

        frames.push(Frame::new(
            config.stream_config.clone(),
            Header::new(config.preamble.clone(), length),
            Body::new(payload),
        ));
    }
    if bits.len() % PAYLOAD_LEN == 0 {
        let payload = vec![];
        let length = 0usize.encode(config.symbols.clone())[..LENGTH_LEN].to_owned();

        frames.push(Frame::new(
            config.stream_config.clone(),
            Header::new(config.preamble.clone(), length),
            Body::new(payload),
        ));
    }

    frames
}

trait AtherEncoding {
    fn encode(&self, symbols: (Symbol, Symbol)) -> Vec<Symbol>;
}

impl AtherEncoding for usize {
    fn encode(&self, symbols: (Symbol, Symbol)) -> Vec<Symbol> {
        self.view_bits::<Lsb0>()
            .into_iter()
            .map(|bit| {
                if *bit {
                    symbols.1.clone()
                } else {
                    symbols.0.clone()
                }
            })
            .collect::<Vec<Symbol>>()
    }
}

impl AtherEncoding for BitSlice {
    fn encode(&self, symbols: (Symbol, Symbol)) -> Vec<Symbol> {
        let mut samples = vec![];
        for bit in self {
            if *bit {
                samples.push(symbols.1.clone());
            } else {
                samples.push(symbols.0.clone());
            }
        }
        samples
    }
}

pub struct AtherInputStream {
    task: AtherInputTask,
    sender: UnboundedSender<AtherInputTaskCmd>,
}

impl AtherInputStream {
    pub fn new(config: AtherStreamConfig, mut stream: AudioInputStream<f32>) -> Self {
        let (sender, mut reciever) = mpsc::unbounded_channel();
        let task = Arc::new(Mutex::new(AtherInputTaskState::Pending));
        tokio::spawn({
            let task = task.clone();
            async move {
                let mut buf = vec![];
                while let Some(cmd) = reciever.recv().await {
                    match cmd {
                        AtherInputTaskCmd::Running => {
                            match decode_packet(&config, &mut stream, &mut buf).await {
                                Some(bits) => {
                                    let mut guard = task.lock().unwrap();
                                    match guard.take() {
                                        AtherInputTaskState::Running(waker) => {
                                            *guard = AtherInputTaskState::Completed(bits);
                                            waker.wake();
                                        }
                                        content => *guard = content,
                                    }
                                }
                                None => {
                                    buf.clear();
                                }
                            }
                        }
                        AtherInputTaskCmd::Suspended => {
                            stream.suspend();
                            let mut guard = task.lock().unwrap();
                            match guard.take() {
                                AtherInputTaskState::Running(waker) => {
                                    *guard = AtherInputTaskState::Suspended(None);
                                    waker.wake();
                                }
                                AtherInputTaskState::Completed(bits) => {
                                    *guard = AtherInputTaskState::Suspended(Some(bits));
                                }
                                content => *guard = content,
                            }
                        }
                        AtherInputTaskCmd::Resume => {
                            stream.resume();
                            let mut guard = task.lock().unwrap();
                            match guard.take() {
                                AtherInputTaskState::Suspended(bits) => {
                                    if let Some(bits) = bits {
                                        *guard = AtherInputTaskState::Completed(bits);
                                    } else {
                                        *guard = AtherInputTaskState::Pending;
                                    }
                                }
                                content => *guard = content,
                            }
                        }
                    }
                }
            }
        });
        Self { sender, task }
    }
}

enum AtherInputTaskCmd {
    Running,
    Suspended,
    Resume,
}

type AtherInputTask = Arc<Mutex<AtherInputTaskState>>;

enum AtherInputTaskState {
    Pending,
    Running(Waker),
    Completed(BitVec),
    Suspended(Option<BitVec>),
}

impl AtherInputTaskState {
    fn take(&mut self) -> AtherInputTaskState {
        mem::replace(self, AtherInputTaskState::Suspended(None))
    }
}

impl Stream for AtherInputStream {
    type Item = BitVec;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let mut guard = self.task.lock().unwrap();
        match guard.take() {
            AtherInputTaskState::Pending => {
                *guard = AtherInputTaskState::Running(cx.waker().clone());
                self.sender.send(AtherInputTaskCmd::Running).unwrap();
                Poll::Pending
            }
            AtherInputTaskState::Running(_) => {
                *guard = AtherInputTaskState::Running(cx.waker().clone());
                Poll::Pending
            }
            AtherInputTaskState::Completed(bits) => {
                *guard = AtherInputTaskState::Pending;
                Poll::Ready(Some(bits))
            }
            AtherInputTaskState::Suspended(bits) => {
                if let Some(bits) = bits {
                    *guard = AtherInputTaskState::Suspended(None);
                    Poll::Ready(Some(bits))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    }
}

async fn decode_packet(
    // async fn decode_frame(
    config: &AtherStreamConfig,
    stream: &mut AudioInputStream<f32>,
    buf: &mut Vec<f32>,
) -> Option<BitVec> {
    let sample_rate = config.stream_config.sample_rate().0 as f32;
    let band_pass = (
        config.frequency as f32 - 1000.,
        config.frequency as f32 + 1000.,
    );
    let preamble_len = config.preamble.0.len();
    let symbol_len = config.symbols.0 .0.len();

    println!("Start decode");

    loop {
        println!(
            "Looping on the preamble {}, expect {}",
            buf.len(),
            preamble_len
        );
        if buf.len() >= preamble_len {
            let (index, value) = signal::synchronize(&config.preamble.0, buf);
            if index >= 0 {
                let index = index as usize;
                println!("Got index {} with {}", index, value);
                if value > CORR_THRESHOLD && index + preamble_len < buf.len() {
                    *buf = buf.split_off(index + preamble_len);
                    break;
                }
                println!(
                    "Failed to comform the threshold, got {}, len {}",
                    value,
                    buf.len()
                );
            }
            println!("Failed to find a start, len {}", buf.len());
        }

        println!("Wait for more data");
        match stream.next().await {
            Some(sample) => buf.extend(sample.iter()),
            None => return None,
        }
        println!("Done");
    }

    println!("Preamble found");

    let (mut length, mut index) = (0usize, 0usize);
    while index < LENGTH_LEN {
        if buf.len() > symbol_len {
            buf.band_pass(sample_rate, band_pass);
            let value = signal::dot_product(&config.symbols.0 .0, buf[..symbol_len].as_ref());
            println!("length value {}", value);
            if value <= 0. {
                length += 1 << index;
            }

            *buf = buf.split_off(symbol_len);
            index += 1;
        } else {
            match stream.next().await {
                Some(sample) => buf.extend(sample.iter()),
                None => return None,
            }
        }
    }

    println!("Found length {}", length);

    let (mut bits, mut index) = (bitvec![], 0usize);
    while index < length {
        if buf.len() > symbol_len {
            buf.band_pass(sample_rate, band_pass);
            let value = signal::dot_product(&config.symbols.0 .0, buf[..symbol_len].as_ref());
            if value > 0. {
                bits.push(false);
            } else {
                bits.push(true);
            }

            *buf = buf.split_off(symbol_len);
            index += 1;
        } else {
            match stream.next().await {
                Some(sample) => buf.extend(sample.iter()),
                None => return None,
            }
        }
    }

    Some(bits)
}

// async fn decode_packet(
//     config: &AtherStreamConfig,
//     stream: &Arc<sync::Mutex<AudioInputStream<f32>>>,
//     buf: &mut Vec<f32>,
// ) -> Option<BitVec> {
//     let mut bits = bitvec![];
//     loop {
//         match decode_frame(config, stream, buf).await {
//             Some(frame) => {
//                 if frame.is_empty() {
//                     break;
//                 } else {
//                     bits.extend(frame);
//                 }
//             }
//             None => return None,
//         }
//     }
//     Some(bits)
// }

impl ContinuousStream for AtherInputStream {
    fn resume(&self) {
        self.sender.send(AtherInputTaskCmd::Resume).unwrap();
    }

    fn suspend(&self) {
        self.sender.send(AtherInputTaskCmd::Suspended).unwrap();
    }
}
