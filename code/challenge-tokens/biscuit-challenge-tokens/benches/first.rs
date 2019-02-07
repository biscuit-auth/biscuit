#![allow(deprecated)]
#![feature(test)]
extern crate test;

extern crate biscuit_challenge_tokens;
extern crate rand;

use rand::{Rng, SeedableRng, XorShiftRng, OsRng};
use biscuit_challenge_tokens::{KeyPair, Token, ChallengeToken};
use test::Bencher;

mod bench {
  use super::*;
  use test::Bencher;

  #[bench]
  fn sign_first_block(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    b.iter(||{
      Token::new(&mut rng, &keypair1, &message1[..])
    });
  }

  #[bench]
  fn sign_second_block(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";

    let token2 = token1.append(&mut rng, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    b.iter(||{
      token1.append(&mut rng, &message2[..])
    });
  }

  #[bench]
  fn sign_third_block(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";

    let token2 = token1.append(&mut rng, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    println!("will derive a third token");

    let message3 = b"!!!";

    let token3 = token2.append(&mut rng, &message3[..]);

    assert!(token3.verify(), "cannot verify third token");

    b.iter(||{
      token2.append(&mut rng, &message3[..])
    });
  }

  #[bench]
  fn verify_one_block(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");
    let challenge = token1.challenge(&mut rng, &b"pouet"[..]);
    assert!(challenge.verify(), "cannot verify first challenge token");

    b.iter(||{
      challenge.verify()
    });
  }

  #[bench]
  fn verify_two_blocks(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";

    let token2 = token1.append(&mut rng, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");
    let challenge = token2.challenge(&mut rng, &b"test"[..]);
    assert!(challenge.verify(), "cannot verify second challenge token");

    b.iter(||{
      challenge.verify()
    });
  }

  #[bench]
  fn verify_three_blocks(b: &mut Bencher) {
    let mut rng: OsRng = OsRng::new().unwrap();

    let message1 = b"hello";
    let keypair1 = KeyPair::new(&mut rng);

    let token1 = Token::new(&mut rng, &keypair1, &message1[..]);

    assert!(token1.verify(), "cannot verify first token");

    println!("will derive a second token");

    let message2 = b"world";

    let token2 = token1.append(&mut rng, &message2[..]);

    assert!(token2.verify(), "cannot verify second token");

    println!("will derive a third token");

    let message3 = b"!!!";

    let token3 = token2.append(&mut rng, &message3[..]);

    assert!(token3.verify(), "cannot verify third token");
    let challenge = token3.challenge(&mut rng, &b"time"[..]);
    assert!(challenge.verify(), "cannot verify third challenge token");

    b.iter(||{
      challenge.verify()
    });
  }
}


