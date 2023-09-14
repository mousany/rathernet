use anyhow::Result;
use cpal::{traits::HostTrait, Device, Host};
use rodio::{DeviceTrait, OutputStream, OutputStreamHandle, StreamError};

pub struct AsioHost {
    pub inner: Host,
}

impl AsioHost {
    pub fn try_new() -> Result<Self> {
        let host = cpal::host_from_id(cpal::HostId::Asio)?;
        Ok(Self { inner: host })
    }
}

pub struct AsioOutputStream {
    pub stream: OutputStream,
    pub handle: OutputStreamHandle,
}

impl AsioOutputStream {
    fn try_from_device(device: &Device) -> Result<Self> {
        let (stream, handle) = OutputStream::try_from_device(device)?;
        Ok(Self { stream, handle })
    }

    pub fn try_from_name(name: &str) -> Result<Self> {
        let host = AsioHost::try_new()?;
        match host
            .inner
            .devices()?
            .find(|d| d.name().map(|s| s == name).unwrap_or(false))
        {
            Some(ref device) => AsioOutputStream::try_from_device(device),
            None => Err(StreamError::NoDevice.into()),
        }
    }

    pub fn try_default() -> Result<Self> {
        let host = AsioHost::try_new()?;
        match host.inner.default_output_device() {
            Some(ref device) => AsioOutputStream::try_from_device(device),
            None => Err(StreamError::NoDevice.into()),
        }
    }
}
