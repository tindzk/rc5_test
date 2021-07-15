/*
 * RC5 for 32-bit words based on the C implementation by Rivest (1997) [1]
 *
 * [1] https://www.grc.com/r&d/rc5.pdf
 */

mod util;
use util::ArithExt;
use util::CollectRev;

static WORD_SIZE_BITS: usize = 32;
static WORD_SIZE_BYTES: usize = WORD_SIZE_BITS / 8;

/**
 * Magic constants
 *
 * Note: These constants are word-size dependent, see section 4.3.
 */
static P: u32 = 0xb7e15163;
static Q: u32 = 0x9e3779b9;

static ROUNDS: usize = 12;

static KEY_BYTES: usize = 16;

static KEY_TABLE_WORDS: usize = 2 * (ROUNDS + 1);

/**
 * Number of words in key
 *
 * max(1, ceil(8 * KEY_BYTES / WORD_SIZE_BITS))
 */
static KEY_WORDS: usize = 4;

/**
 * Expand key table
 */
fn key_table(key: &Vec<u8>) -> Vec<u32> {
    assert_eq!(key.len(), KEY_BYTES);

    // Step 1: Convert secret key from bytes to words
    let mut key_iter = key.iter().rev();
    let mut key_words: Vec<u32> = (0..KEY_WORDS)
        .map(|_| (0..WORD_SIZE_BYTES).fold(0, |v, _| (v << 8) + (*key_iter.next().unwrap() as u32)))
        .collect_rev();

    // Step 2: Initialise key table to fixed key-independent pseudo-random bit pattern. This is
    // achieved by an arithmetic progression that makes use of the magic onstants P and Q.
    let mut key_table: Vec<u32> = (0..KEY_TABLE_WORDS)
        .scan(0, |v, i| {
            *v = if i == 0 { P } else { (*v).platform_add(Q) };
            Some(*v)
        })
        .collect();

    // Step 3: Mix in the supplied secret key by passing over the key words and the key table three
    // times.
    let (mut key_table_val, mut key_words_val): (u32, u32) = (0, 0);
    let (mut key_table_iter, mut key_words_iter) =
        ((0..key_table.len()).cycle(), (0..key_words.len()).cycle());

    for _ in 0..3 * key_table.len() {
        let key_table_idx = key_table_iter.next().unwrap();
        key_table_val = key_table[key_table_idx]
            .platform_add(key_table_val)
            .platform_add(key_words_val)
            .rotate_left(3);
        let _ = std::mem::replace(&mut key_table[key_table_idx], key_table_val);

        let key_words_idx = key_words_iter.next().unwrap();
        key_words_val = key_words[key_words_idx]
            .platform_add(key_table_val)
            .platform_add(key_words_val)
            .rotate_left(key_table_val.platform_add(key_words_val));
        let _ = std::mem::replace(&mut key_words[key_words_idx], key_words_val);
    }

    key_table
}

/**
 * Return ciphertext for a given key table and plaintext
 */
fn encode(key_table: Vec<u32>, plaintext: Vec<u32>) -> Vec<u32> {
    assert_eq!(key_table.len(), KEY_TABLE_WORDS);
    assert_eq!(plaintext.len(), 2);

    let initial: (u32, u32) = (
        plaintext[0].platform_add(key_table[0]),
        plaintext[1].platform_add(key_table[1]),
    );

    let (a, b) = (1..(ROUNDS + 1)).fold(initial, |acc, i| {
        let (mut a, mut b) = acc;
        a = (a ^ b).rotate_left(b).platform_add(key_table[2 * i]);
        b = (b ^ a).rotate_left(a).platform_add(key_table[2 * i + 1]);
        (a, b)
    });

    vec![a, b]
}

/**
 * Return plaintext for a given key table and ciphertext
 */
fn decode(key_table: Vec<u32>, ciphertext: Vec<u32>) -> Vec<u32> {
    assert_eq!(key_table.len(), KEY_TABLE_WORDS);
    assert_eq!(ciphertext.len(), 2);

    let initial: (u32, u32) = (ciphertext[0], ciphertext[1]);

    let (a, b) = (1..(ROUNDS + 1)).rev().fold(initial, |acc, i| {
        let (mut a, mut b) = acc;
        b = b.platform_sub(key_table[2 * i + 1]).rotate_right(a) ^ a;
        a = a.platform_sub(key_table[2 * i]).rotate_right(b) ^ b;
        (a, b)
    });

    vec![a.platform_sub(key_table[0]), b.platform_sub(key_table[1])]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_u32(v: Vec<u8>) -> Vec<u32> {
        let (head, body, tail) = unsafe { v.align_to::<u32>() };
        assert!(head.is_empty());
        assert!(tail.is_empty());
        body.to_vec()
    }

    #[test]
    fn key_table_a() {
        let key: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let expected: Vec<u32> = vec![
            0xd447e233, 0xd82eec20, 0x84fce219, 0xb93353de, 0x5ac2588f, 0x48e922f1, 0x879f5460,
            0x1a693a4b, 0x5171b55f, 0x9a206e4d, 0x9966c4a0, 0xb166b0d7, 0x89cc6827, 0xcbe1b9b7,
            0x1bb7f44f, 0x638829b4, 0x4da0ab3a, 0x74e54561, 0x5eb4dee9, 0xbef10188, 0x728a511f,
            0x37a8debc, 0x5735676a, 0xf96b764a, 0x7aec5407, 0x15e8e206,
        ];

        assert_eq!(key_table(&key), expected);
    }

    #[test]
    fn encode_a() {
        let key: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let plaintext: Vec<u8> = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ciphertext: Vec<u8> = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];

        let result = encode(key_table(&key), to_u32(plaintext));
        assert_eq!(result, to_u32(ciphertext));
    }

    #[test]
    fn encode_b() {
        let key: Vec<u8> = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];

        let plaintext: Vec<u8> = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ciphertext: Vec<u8> = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];

        let result = encode(key_table(&key), to_u32(plaintext));
        assert_eq!(result, to_u32(ciphertext));
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let plaintext: Vec<u8> = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ciphertext: Vec<u8> = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let result = decode(key_table(&key), to_u32(ciphertext));
        assert_eq!(result, to_u32(plaintext));
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];

        let plaintext: Vec<u8> = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ciphertext: Vec<u8> = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];

        let result = decode(key_table(&key), to_u32(ciphertext));
        assert_eq!(result, to_u32(plaintext));
    }
}
