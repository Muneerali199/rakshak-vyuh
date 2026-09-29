//! Minimal, allocation-light reader over a byte slice.
//!
//! The dissector never indexes a slice directly. Every read goes through
//! `Reader`, which returns `Truncated` instead of panicking. That property is
//! what lets us fuzz the parsers without a `catch_unwind` in the loop.

use crate::error::{Result, VyuhError};

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    pub fn offset(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read exactly `n` bytes and advance.
    #[inline]
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(VyuhError::Truncated {
                need: n,
                have: self.remaining(),
                offset: self.pos,
            });
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    #[inline]
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Look at the next byte without consuming it.
    ///
    /// Needed wherever a disambiguation decision has to be made before
    /// committing to the read. Reading speculatively and rewinding by hand is
    /// where parser bugs come from.
    #[inline]
    pub fn peek_u8(&self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(VyuhError::Truncated {
                need: 1,
                have: 0,
                offset: self.pos,
            });
        }
        Ok(self.data[self.pos])
    }

    /// Look at the next `n` bytes without consuming them.
    ///
    /// `peek_u8` covers single-octet disambiguation. Some choices need a wider
    /// window: recognising whether an SA substructure is length-framed takes
    /// four octets, and its identity depends on the octets after them. Reading
    /// those speculatively and rewinding is exactly the class of bug this
    /// reader exists to prevent.
    #[inline]
    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(VyuhError::Truncated {
                need: n,
                have: self.remaining(),
                offset: self.pos,
            });
        }
        Ok(&self.data[self.pos..self.pos + n])
    }

    /// Return the cursor to a previously recorded offset.
    ///
    /// A speculative parse that decides to back out has to rewind, and a
    /// hand-written `pos -= n` turns a malformed packet into an arithmetic
    /// panic in debug and a huge offset in release. The target is clamped to
    /// the slice, so a bad call degrades to "read no further" rather than
    /// wrapping.
    #[inline]
    pub fn rewind_to(&mut self, target: usize) {
        self.pos = target.min(self.data.len());
    }

    #[inline]
    pub fn u16_be(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    #[inline]
    pub fn u24_be(&mut self) -> Result<u32> {
        let b = self.take(3)?;
        Ok(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32)
    }

    #[inline]
    pub fn u32_be(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Consume and discard `n` bytes, but only if they are actually present.
    #[inline]
    pub fn skip(&mut self, n: usize) -> Result<()> {
        if self.remaining() < n {
            return Err(VyuhError::Truncated {
                need: n,
                have: self.remaining(),
                offset: self.pos,
            });
        }
        self.pos += n;
        Ok(())
    }

    /// A sub-reader limited to `n` bytes, advancing self past them.
    pub fn split(&mut self, n: usize) -> Result<Reader<'a>> {
        let bytes = self.take(n)?;
        Ok(Reader::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian_fields() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(r.u16_be().unwrap(), 0x0102);
        assert_eq!(r.u24_be().unwrap(), 0x030405);
        assert_eq!(r.offset(), 5);
    }

    #[test]
    fn truncated_read_is_an_error_not_a_panic() {
        let mut r = Reader::new(&[0x01]);
        assert!(matches!(r.u32_be(), Err(VyuhError::Truncated { .. })));
    }

    #[test]
    fn split_bounds_the_sub_reader() {
        let mut r = Reader::new(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let mut sub = r.split(2).unwrap();
        assert_eq!(sub.u16_be().unwrap(), 0xAABB);
        assert!(sub.is_empty());
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn peek_does_not_advance() {
        let mut r = Reader::new(&[0x7F, 0x01]);
        assert_eq!(r.peek_u8().unwrap(), 0x7F);
        assert_eq!(r.peek_u8().unwrap(), 0x7F);
        assert_eq!(r.offset(), 0);
        assert_eq!(r.u8().unwrap(), 0x7F);
        assert_eq!(r.offset(), 1);
    }

    #[test]
    fn peek_at_the_end_is_truncated_not_a_panic() {
        let r = Reader::new(&[]);
        assert!(matches!(r.peek_u8(), Err(VyuhError::Truncated { .. })));
    }
}
