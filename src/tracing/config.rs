use crate::tracing::types::{
    MaxInflight, MaxRounds, PacketSize, PayloadPattern, Sequence, SourcePort, TimeToLive, TraceId,
};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::time::Duration;

/// The tracing protocol.
#[derive(Debug, Copy, Clone)]
pub enum TracerProtocol {
    /// Internet Control Message Protocol
    Icmp,
    /// User Datagram Protocol
    Udp,
    /// Transmission Control Protocol
    Tcp,
}

impl Display for TracerProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Icmp => write!(f, "icmp"),
            Self::Udp => write!(f, "udp"),
            Self::Tcp => write!(f, "tcp"),
        }
    }
}

/// TODO
#[derive(Debug, Copy, Clone)]
pub struct TracerConfig {
    pub target_addr: IpAddr,
    pub protocol: TracerProtocol,
    pub trace_identifier: TraceId,
    pub max_rounds: Option<MaxRounds>,
    pub first_ttl: TimeToLive,
    pub max_ttl: TimeToLive,
    pub grace_duration: Duration,
    pub max_inflight: MaxInflight,
    pub min_sequence: Sequence,
    pub read_timeout: Duration,
    pub min_round_duration: Duration,
    pub max_round_duration: Duration,
    pub packet_size: PacketSize,
    pub payload_pattern: PayloadPattern,
    pub source_port: SourcePort,
}

impl TracerConfig {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        target_addr: IpAddr,
        protocol: TracerProtocol,
        max_rounds: Option<usize>,
        trace_identifier: u16,
        first_ttl: u8,
        max_ttl: u8,
        grace_duration: Duration,
        max_inflight: u8,
        min_sequence: u16,
        read_timeout: Duration,
        min_round_duration: Duration,
        max_round_duration: Duration,
        packet_size: u16,
        payload_pattern: u8,
        source_port: u16,
    ) -> Self {
        Self {
            target_addr,
            protocol,
            trace_identifier: TraceId::from(trace_identifier),
            max_rounds: max_rounds.map(MaxRounds::from),
            first_ttl: TimeToLive::from(first_ttl),
            max_ttl: TimeToLive::from(max_ttl),
            grace_duration,
            max_inflight: MaxInflight::from(max_inflight),
            min_sequence: Sequence::from(min_sequence),
            read_timeout,
            min_round_duration,
            max_round_duration,
            packet_size: PacketSize::from(packet_size),
            payload_pattern: PayloadPattern::from(payload_pattern),
            source_port: SourcePort::from(source_port),
        }
    }
}