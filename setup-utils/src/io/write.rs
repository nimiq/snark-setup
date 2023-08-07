//! Utilities for writing and reading group elements to buffers in parallel
use crate::{buffer_size, Result, UseCompression};

use ark_ec::AffineRepr;
use ark_serialize::Write;
use ark_std::cfg_chunks_mut;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Used for writing elements to a buffer directly
pub trait Serializer {
    /// Writes a compressed or uncompressed element to the buffer
    fn write_element(&mut self, element: &impl AffineRepr, compression: UseCompression) -> Result<()>;

    /// Writes a list of elements serially
    fn write_elements_exact<G: AffineRepr>(&mut self, elements: &[G], compression: UseCompression) -> Result<()> {
        elements.iter().map(|el| self.write_element(el, compression)).collect()
    }
}

pub trait BatchSerializer {
    /// Initializes the buffer with the provided element
    fn init_element<G: AffineRepr>(&mut self, element: &G, compression: UseCompression) -> Result<()>;

    /// Writes multiple elements to the buffer. Internally calls `write_element`
    fn write_batch<G: AffineRepr>(&mut self, elements: &[G], compression: UseCompression) -> Result<()>;
}

impl<W: Write> Serializer for W {
    fn write_element(&mut self, element: &impl AffineRepr, compression: UseCompression) -> Result<()> {
        element.serialize_with_mode(self, compression)?;
        Ok(())
    }
}

impl Serializer for [u8] {
    fn write_element(&mut self, element: &impl AffineRepr, compression: UseCompression) -> Result<()> {
        (&mut &mut *self).write_element(element, compression)
    }
}

// PITODO
// #[allow(unused_mut)]
impl BatchSerializer for [u8] {
    fn init_element<G: AffineRepr>(&mut self, element: &G, compression: UseCompression) -> Result<()> {
        let element_size = buffer_size::<G>(compression);
        cfg_chunks_mut!(self, element_size)
            .map(|mut buf| {
                (&mut buf[0..element_size]).write_element(element, compression)?;
                Ok(())
            })
            .collect::<Result<()>>()
    }

    /// Writes multiple elements to the buffer. Internally calls `write_element`
    fn write_batch<G: AffineRepr>(&mut self, elements: &[G], compression: UseCompression) -> Result<()> {
        let element_size = buffer_size::<G>(compression);
        cfg_chunks_mut!(self, element_size)
            .zip(elements)
            .map(|(mut buf, element)| {
                (&mut buf[0..element_size]).write_element(element, compression)?;
                Ok(())
            })
            .collect()
    }
}
