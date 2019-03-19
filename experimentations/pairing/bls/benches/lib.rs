#![feature(test)]
extern crate test;

extern crate pairing;
extern crate rand;
extern crate bls;

use rand::{Rand, SeedableRng, XorShiftRng};
use pairing::{CurveAffine, CurveProjective, Engine, Field, PrimeField};
use pairing::bls12_381::Bls12;
use test::Bencher;

type E = Bls12;

#[test]
fn blocksign() {
  let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

  // since G1 and G2 are groups of prime order, any element can be a generator
  let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
  let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

  // verify that they are not trivial elements
  assert_ne!(g1, <Bls12 as Engine>::G1::zero());
  assert_ne!(g1, <Bls12 as Engine>::G1::one());
  assert_ne!(g2, <Bls12 as Engine>::G2::zero());
  assert_ne!(g2, <Bls12 as Engine>::G2::one());

  // let's generate the private keys from the scalar field
  let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);
  let k2 = <Bls12 as Engine>::Fr::rand(&mut rng);

  // let's generate the public keys in G1
  let mut p1 = g1;
  p1.mul_assign(k1);
  let mut p2 = g1;
  p2.mul_assign(k2);

  // let's assume h1 and h2 are respectively the hashes of block 1 and block 2
  let h1 = <Bls12 as Engine>::G2::rand(&mut rng);
  let h2 = <Bls12 as Engine>::G2::rand(&mut rng);

  // calculate the signature for the first block
  let mut s1 = h1;
  s1.mul_assign(k1);

  // let's verify the first signature
  // to verify, we need the following information:
  // * h1 (we will be able to recalculate it from the message)
  // * the public key p1
  // * s1 (of course)
  let verif1 = <Bls12 as Engine>::pairing(g1, s1);
  let verif2 = <Bls12 as Engine>::pairing(p1, h1);

  assert_eq!(verif1, verif2);

  // calculate the signature for the second block
  let mut s2 = h2;
  s2.mul_assign(k2);

  // calculate the aggregated signature
  let mut agg_sig = s1;
  agg_sig.add_assign(&s2);

  // let's verify the second signature
  // to verify, we need the following information:
  // * h1 (we will be able to recalculate it from the message)
  // * h2 (we will be able to recalculate it from the message)
  // * the public key p1
  // * the public key p2
  // * agg_sig
  let verif3 = <Bls12 as Engine>::pairing(g1, agg_sig);
  let mut verif4 = <Bls12 as Engine>::pairing(p1, h1);
  verif4.mul_assign(&<Bls12 as Engine>::pairing(p2, h2));

  assert_eq!(verif3, verif4);
}

mod bench {
  use super::*;
  use test::Bencher;

  #[bench]
  fn sign_one_block(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    // since G1 and G2 are groups of prime order, any element can be a generator
    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    // verify that they are not trivial elements
    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);

    let mut p1 = g1;
    p1.mul_assign(k1);

    let h1 = <Bls12 as Engine>::G2::rand(&mut rng);

    b.iter(||{
      let mut s1 = h1;
      s1.mul_assign(k1);
    });
  }

  #[bench]
  fn verify_one_block(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    // since G1 and G2 are groups of prime order, any element can be a generator
    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    // verify that they are not trivial elements
    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);

    let mut p1 = g1;
    p1.mul_assign(k1);

    let h1 = <Bls12 as Engine>::G2::rand(&mut rng);

    let mut s1 = h1;
    s1.mul_assign(k1);

    b.iter(||{
      let verif1 = <Bls12 as Engine>::pairing(g1, s1);
      let verif2 = <Bls12 as Engine>::pairing(p1, h1);
      assert_eq!(verif1, verif2);
    });
  }

  #[bench]
  fn sign_two_blocks(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    // since G1 and G2 are groups of prime order, any element can be a generator
    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    // verify that they are not trivial elements
    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    // let's generate the private keys from the scalar field
    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k2 = <Bls12 as Engine>::Fr::rand(&mut rng);

    // let's generate the public keys in G1
    let mut p1 = g1;
    p1.mul_assign(k1);
    let mut p2 = g1;
    p2.mul_assign(k2);

    // let's assume h1 and h2 are respectively the hashes of block 1 and block 2
    let h1 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h2 = <Bls12 as Engine>::G2::rand(&mut rng);

    // calculate the signature for the first block
    let mut s1 = h1;
    s1.mul_assign(k1);

    b.iter(||{
      // calculate the signature for the second block
      let mut s2 = h2;
      s2.mul_assign(k2);

      // calculate the aggregated signature
      let mut agg_sig = s1;
      agg_sig.add_assign(&s2);
    });
  }

  #[bench]
  fn verify_two_blocks(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k2 = <Bls12 as Engine>::Fr::rand(&mut rng);

    let mut p1 = g1;
    p1.mul_assign(k1);
    let mut p2 = g1;
    p2.mul_assign(k2);

    let h1 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h2 = <Bls12 as Engine>::G2::rand(&mut rng);

    let mut s1 = h1;
    s1.mul_assign(k1);

    let verif1 = <Bls12 as Engine>::pairing(g1, s1);
    let verif2 = <Bls12 as Engine>::pairing(p1, h1);

    assert_eq!(verif1, verif2);

    let mut s2 = h2;
    s2.mul_assign(k2);

    let mut agg_sig = s1;
    agg_sig.add_assign(&s2);

    b.iter(||{
      let verif3 = <Bls12 as Engine>::pairing(g1, agg_sig);
      let mut verif4 = <Bls12 as Engine>::pairing(p1, h1);
      verif4.mul_assign(&<Bls12 as Engine>::pairing(p2, h2));

      assert_eq!(verif3, verif4);
    });
  }

  #[bench]
  fn verify_two_blocks_cache_first_pairing(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k2 = <Bls12 as Engine>::Fr::rand(&mut rng);

    let mut p1 = g1;
    p1.mul_assign(k1);
    let mut p2 = g1;
    p2.mul_assign(k2);

    let h1 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h2 = <Bls12 as Engine>::G2::rand(&mut rng);

    let mut s1 = h1;
    s1.mul_assign(k1);

    let verif1 = <Bls12 as Engine>::pairing(g1, s1);
    let verif2 = <Bls12 as Engine>::pairing(p1, h1);

    assert_eq!(verif1, verif2);

    let mut s2 = h2;
    s2.mul_assign(k2);

    let mut agg_sig = s1;
    agg_sig.add_assign(&s2);

    let cached = <Bls12 as Engine>::pairing(p1, h1);
    b.iter(||{
      let verif3 = <Bls12 as Engine>::pairing(g1, agg_sig);
      let mut verif4 = cached;
      verif4.mul_assign(&<Bls12 as Engine>::pairing(p2, h2));

      assert_eq!(verif3, verif4);
    });
  }

  #[bench]
  fn verify_three_blocks(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k2 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k3 = <Bls12 as Engine>::Fr::rand(&mut rng);

    let mut p1 = g1;
    p1.mul_assign(k1);
    let mut p2 = g1;
    p2.mul_assign(k2);
    let mut p3 = g1;
    p3.mul_assign(k3);

    let h1 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h2 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h3 = <Bls12 as Engine>::G2::rand(&mut rng);

    let mut s1 = h1;
    s1.mul_assign(k1);

    let verif1 = <Bls12 as Engine>::pairing(g1, s1);
    let verif2 = <Bls12 as Engine>::pairing(p1, h1);

    assert_eq!(verif1, verif2);

    let mut s2 = h2;
    s2.mul_assign(k2);

    let mut s3 = h3;
    s3.mul_assign(k3);

    let mut agg_sig = s1;
    agg_sig.add_assign(&s2);
    agg_sig.add_assign(&s3);

    b.iter(||{
      let verif3 = <Bls12 as Engine>::pairing(g1, agg_sig);
      let mut verif4 = <Bls12 as Engine>::pairing(p1, h1);
      verif4.mul_assign(&<Bls12 as Engine>::pairing(p2, h2));
      verif4.mul_assign(&<Bls12 as Engine>::pairing(p3, h3));

      assert_eq!(verif3, verif4);
    });
  }

  #[bench]
  fn verify_three_blocks_cache_first_pairing(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k2 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k3 = <Bls12 as Engine>::Fr::rand(&mut rng);

    let mut p1 = g1;
    p1.mul_assign(k1);
    let mut p2 = g1;
    p2.mul_assign(k2);
    let mut p3 = g1;
    p3.mul_assign(k3);

    let h1 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h2 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h3 = <Bls12 as Engine>::G2::rand(&mut rng);

    let mut s1 = h1;
    s1.mul_assign(k1);

    let verif1 = <Bls12 as Engine>::pairing(g1, s1);
    let verif2 = <Bls12 as Engine>::pairing(p1, h1);

    assert_eq!(verif1, verif2);

    let mut s2 = h2;
    s2.mul_assign(k2);

    let mut s3 = h3;
    s3.mul_assign(k3);

    let mut agg_sig = s1;
    agg_sig.add_assign(&s2);
    agg_sig.add_assign(&s3);

    let cached = <Bls12 as Engine>::pairing(p1, h1);
    b.iter(||{
      let verif3 = <Bls12 as Engine>::pairing(g1, agg_sig);
      let mut verif4 = cached;
      verif4.mul_assign(&<Bls12 as Engine>::pairing(p2, h2));
      verif4.mul_assign(&<Bls12 as Engine>::pairing(p3, h3));

      assert_eq!(verif3, verif4);
    });
  }

  #[bench]
  fn verify_three_blocks_aggregate_keys(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k2 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k3 = <Bls12 as Engine>::Fr::rand(&mut rng);

    let mut p1 = g1;
    p1.mul_assign(k1);
    let mut p2 = g1;
    p2.mul_assign(k2);
    let mut p3 = g1;
    p3.mul_assign(k3);

    let h1 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h2 = <Bls12 as Engine>::G2::rand(&mut rng);
    let h3 = <Bls12 as Engine>::G2::rand(&mut rng);

    let mut s1 = h1;
    s1.mul_assign(k1);

    let verif1 = <Bls12 as Engine>::pairing(g1, s1);
    let verif2 = <Bls12 as Engine>::pairing(p1, h1);

    assert_eq!(verif1, verif2);

    let mut s2 = h2;
    s2.mul_assign(k2);

    let mut s3 = h3;
    s3.mul_assign(k3);

    let mut agg_sig = s1;
    agg_sig.add_assign(&s2);
    agg_sig.add_assign(&s3);

    let mut sum = p1;
    sum.add_assign(&p2);
    sum.add_assign(&p3);
    b.iter(||{
      let verif3 = <Bls12 as Engine>::pairing(g1, agg_sig);
      let mut verif4 = <Bls12 as Engine>::pairing(sum, h1);
      verif4.mul_assign(&<Bls12 as Engine>::pairing(g1, h2));
      verif4.mul_assign(&<Bls12 as Engine>::pairing(g1, h3));

      assert_eq!(verif3, verif4);
    });
  }

  #[bench]
  fn verify_three_blocks_g2(b: &mut Bencher) {
    let mut rng = XorShiftRng::from_seed([0x12345678, 0x12345678, 0x12345678, 0x12345678]);

    let g1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let g2 = <Bls12 as Engine>::G2::rand(&mut rng);

    assert_ne!(g1, <Bls12 as Engine>::G1::zero());
    assert_ne!(g1, <Bls12 as Engine>::G1::one());
    assert_ne!(g2, <Bls12 as Engine>::G2::zero());
    assert_ne!(g2, <Bls12 as Engine>::G2::one());

    let k1 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k2 = <Bls12 as Engine>::Fr::rand(&mut rng);
    let k3 = <Bls12 as Engine>::Fr::rand(&mut rng);

    let mut p1 = g2;
    p1.mul_assign(k1);
    let mut p2 = g2;
    p2.mul_assign(k2);
    let mut p3 = g2;
    p3.mul_assign(k3);

    let h1 = <Bls12 as Engine>::G1::rand(&mut rng);
    let h2 = <Bls12 as Engine>::G1::rand(&mut rng);
    let h3 = <Bls12 as Engine>::G1::rand(&mut rng);

    let mut s1 = h1;
    s1.mul_assign(k1);

    let verif1 = <Bls12 as Engine>::pairing(s1, g2);
    let verif2 = <Bls12 as Engine>::pairing(h1, p1);

    assert_eq!(verif1, verif2);

    let mut s2 = h2;
    s2.mul_assign(k2);

    let mut s3 = h3;
    s3.mul_assign(k3);

    let mut agg_sig = s1;
    agg_sig.add_assign(&s2);
    agg_sig.add_assign(&s3);

    b.iter(||{
      let verif3 = <Bls12 as Engine>::pairing(agg_sig, g2);
      let mut verif4 = <Bls12 as Engine>::pairing(h1, p1);
      verif4.mul_assign(&<Bls12 as Engine>::pairing(h2, p2));
      verif4.mul_assign(&<Bls12 as Engine>::pairing(h3, p3));

      assert_eq!(verif3, verif4);
    });
  }
}

