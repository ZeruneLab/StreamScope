#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum BitError {
    #[error("H.264 RBSP 数据不足")]
    EndOfData,
    #[error("Exp-Golomb 数值超出支持范围")]
    ExpGolombOverflow,
}

#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    data: &'a [u8],
    bit_position: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bit_position: 0,
        }
    }

    pub fn read_bit(&mut self) -> Result<bool, BitError> {
        let byte = *self
            .data
            .get(self.bit_position / 8)
            .ok_or(BitError::EndOfData)?;
        let value = byte & (1 << (7 - self.bit_position % 8)) != 0;
        self.bit_position += 1;
        Ok(value)
    }

    pub fn read_bits(&mut self, count: u8) -> Result<u32, BitError> {
        if count > 32 {
            return Err(BitError::ExpGolombOverflow);
        }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit()?);
        }
        Ok(value)
    }

    pub fn read_ue(&mut self) -> Result<u32, BitError> {
        let mut leading_zeros = 0_u8;
        while !self.read_bit()? {
            leading_zeros += 1;
            if leading_zeros > 31 {
                return Err(BitError::ExpGolombOverflow);
            }
        }
        if leading_zeros == 0 {
            return Ok(0);
        }
        Ok((1_u32 << leading_zeros) - 1 + self.read_bits(leading_zeros)?)
    }

    pub fn read_se(&mut self) -> Result<i32, BitError> {
        let code = self.read_ue()?;
        let magnitude = code.div_ceil(2) as i32;
        Ok(if code.is_multiple_of(2) {
            -magnitude
        } else {
            magnitude
        })
    }
}

pub fn ebsp_to_rbsp(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut zero_count = 0;
    for byte in input {
        if zero_count >= 2 && *byte == 0x03 {
            zero_count = 0;
            continue;
        }
        output.push(*byte);
        if *byte == 0 {
            zero_count += 1;
        } else {
            zero_count = 0;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_unsigned_and_signed_exp_golomb() {
        let mut reader = BitReader::new(&[0b1010_0110]);
        assert_eq!(reader.read_ue().unwrap(), 0);
        assert_eq!(reader.read_ue().unwrap(), 1);
        assert_eq!(reader.read_se().unwrap(), -1);
    }

    #[test]
    fn removes_emulation_prevention_bytes() {
        assert_eq!(ebsp_to_rbsp(&[0, 0, 3, 1, 0, 0, 3, 2]), [0, 0, 1, 0, 0, 2]);
    }
}
