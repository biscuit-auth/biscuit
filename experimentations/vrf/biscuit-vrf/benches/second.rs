#![feature(test)]
extern crate test;

extern crate biscuit_vrf;
extern crate rand;

use rand::rngs::OsRng;
use biscuit_vrf::second::{KeyPair, Token};
use test::Bencher;

mod bench {
  use super::*;
  use test::Bencher;

  #[bench]
  fn sign_first_block(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    b.iter(||{
      Token::new(&keypair1, &message1[..])
    });
  }

  #[bench]
  fn sign_second_block(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";
    let keypair2 = KeyPair::new(&mut rng);

    let token2 = token1.append(&keypair2, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    b.iter(||{
      token1.append(&keypair2, &message2[..])
    });
  }

  #[bench]
  fn sign_third_block(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";
    let keypair2 = KeyPair::new(&mut rng);

    let token2 = token1.append(&keypair2, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    println!("will derive a third token");

    let message3 = b"!!!";
    let keypair3 = KeyPair::new(&mut rng);

    let token3 = token2.append(&keypair3, &message3[..]);

    assert!(token3.verify(), "cannot verify third token");

    b.iter(||{
      token2.append(&keypair3, &message3[..])
    });
  }

  #[bench]
  fn verify_one_block(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    b.iter(||{
      token1.verify()
    });
  }

  #[bench]
  fn verify_two_blocks(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";
    let keypair2 = KeyPair::new(&mut rng);

    let token2 = token1.append(&keypair2, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    b.iter(||{
      token2.verify()
    });
  }

  #[bench]
  fn verify_three_blocks(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";
    let keypair2 = KeyPair::new(&mut rng);

    let token2 = token1.append(&keypair2, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    println!("will derive a third token");

    let message3 = b"!!!";
    let keypair3 = KeyPair::new(&mut rng);

    let token3 = token2.append(&keypair3, &message3[..]);

    assert!(token3.verify(), "cannot verify third token");

    b.iter(||{
      token3.verify()
    });
  }
}


