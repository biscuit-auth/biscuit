/**
	@file
	@brief a sample of BLS signature
	see https://github.com/herumi/bls
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause

*/
#include <mcl/bn256.hpp>
//#include <mcl/bls12_381.hpp>
#include <cybozu/benchmark.hpp>
#include <iostream>
#include<numeric>
#include<chrono>


using namespace mcl::bn256;
//using namespace mcl::bls12;
using namespace std::chrono;

void Hash(G1& P, const std::string& m)
{
	Fp t;
	t.setHashOf(m);
	mapToG1(P, t);
}

void KeyGen(Fr& s, G2& pub, const G2& Q)
{
	s.setRand();
	G2::mul(pub, Q, s); // pub = sQ
}

void Sign(G1& sign, const Fr& s, const std::string& m)
{
	G1 Hm;
	Hash(Hm, m);
	G1::mul(sign, Hm, s); // sign = s H(m)
}

bool Verify(const G1& sign, const G2& Q, const G2& pub, const std::string& m)
{
	Fp12 e1, e2;
	G1 Hm;
	Hash(Hm, m);
	pairing(e1, sign, Q); // e1 = e(sign, Q)
	pairing(e2, Hm, pub); // e2 = e(Hm, sQ)
	return e1 == e2;
}

void Aggregate(G1& agg, const G1& sign1, const G1&sign2) {
  G1::add(agg, sign1, sign2);
}

bool VerifyAggregate(const G1& aggregated_sig, const G2& Q, const G2& pub1, const G2& pub2, const std::string& m1, const std::string& m2) {
  Fp12 e0, e1, e2, e3;
  G1 h1, h2;
  Hash(h1, m1);
  Hash(h2, m2);

  pairing(e0, aggregated_sig, Q);
  pairing(e1, h1, pub1);
  pairing(e2, h2, pub2);
  Fp12::mul(e3, e1, e2);

  return e0 == e3;
}

bool VerifyAggregate3(const G1& aggregated_sig, const G2& Q,
  const G2& pub1, const G2& pub2, const G2& pub3,
  const std::string& m1, const std::string& m2, const std::string& m3) {

  Fp12 e0, e1, e2, e3, e4, e5;
  G1 h1, h2, h3;
  Hash(h1, m1);
  Hash(h2, m2);
  Hash(h3, m3);

  pairing(e0, aggregated_sig, Q);
  pairing(e1, h1, pub1);
  pairing(e2, h2, pub2);
  pairing(e3, h3, pub3);

  Fp12::mul(e4, e1, e2);
  Fp12::mul(e5, e4, e3);

  return e0 == e5;
}

int main(int argc, char *argv[])
{
	//std::string m = argc == 1 ? "hello mcl" : argv[1];
  std::string m1 = "authentication test caveat 1";
  std::string m2 = "authentication test caveat 2";

	// setup parameter
	initPairing();
	G2 Q;
	mapToG2(Q, 1);

	// generate secret key and public key
	Fr s1, s2;
	G2 pub1, pub2;
	KeyGen(s1, pub1, Q);
	std::cout << "secret key 1: " << s1 << std::endl;
	std::cout << "public key 1: " << pub1 << std::endl;
	KeyGen(s2, pub2, Q);
	std::cout << "secret key 2: " << s2 << std::endl;
	std::cout << "public key 2: " << pub2 << std::endl;

  G1 sign_bench;
  CYBOZU_BENCH("sign one", Sign, sign_bench, s1, m1);

	// sign
	G1 sign1, sign2;
  auto before_sign = high_resolution_clock::now();
	Sign(sign1, s1, m1);
  auto after_sign = high_resolution_clock::now();
	std::cout << "msg1 " << m1 << std::endl;
	std::cout << "sign1 " << sign1 << std::endl;
	Sign(sign2, s2, m2);
	std::cout << "msg2 " << m2 << std::endl;
	std::cout << "sign2 " << sign2 << std::endl;

  CYBOZU_BENCH("verify one", Verify, sign1, Q, pub1, m1);
  auto before_verify_one = high_resolution_clock::now();
  bool b = Verify(sign1, Q, pub1, m1);
  auto after_verify_one = high_resolution_clock::now();

  if(b) {
    std::cout << "verify one succeeded" << std::endl;
  } else {
    std::cout << "verify one failed" << std::endl;
  }

  G1 agg;
  CYBOZU_BENCH("aggregate two", Aggregate, agg, sign1, sign2);
  G1 agg_bench;
  auto before_aggregate_two = high_resolution_clock::now();
  Aggregate(agg_bench, sign1, sign2);
  auto after_aggregate_two = high_resolution_clock::now();

  auto before_verify_aggregate = high_resolution_clock::now();
  bool b2 = VerifyAggregate(agg, Q, pub1, pub2, m1, m2);
  auto after_verify_aggregate = high_resolution_clock::now();

  if(b2) {
    std::cout << "verify aggregate succeeded" << std::endl;
  } else {
    std::cout << "verify aggregate failed" << std::endl;
  }

  CYBOZU_BENCH("verify aggregate", VerifyAggregate, agg, Q, pub1, pub2, m1, m2);

	Fr s3;
	G2 pub3;
	KeyGen(s3, pub3, Q);
  G1 sign3;
  std::string m3 = "authentication test caveat 3";
  Sign(sign3, s3, m3);
  G1 agg3;
  Aggregate(agg3, agg, sign3);
  auto before_verify_aggregate_three = high_resolution_clock::now();
  bool b3 = VerifyAggregate3(agg3, Q, pub1, pub2, pub3, m1, m2, m3);
  auto after_verify_aggregate_three = high_resolution_clock::now();


  std::cout << "serialized pub1: " << pub1.getStr(2048) << std::endl;
  std::cout << "serialized sig: " << agg3.getStr(2048) << std::endl;

  if(b3) {
    std::cout << "verify aggregate 3 succeeded" << std::endl;
  } else {
    std::cout << "verify aggregate 3 failed" << std::endl;
  }

  duration<double> sign_dur = after_sign - before_sign;
  duration<double> verify_one_dur = after_verify_one - before_verify_one;
  duration<double> aggregate_two_dur = after_aggregate_two - before_aggregate_two;
  duration<double> verify_aggregate_dur = after_verify_aggregate - before_verify_aggregate;
  duration<double> verify_aggregate_three_dur = after_verify_aggregate_three - before_verify_aggregate_three;

  std::cout << "time measurements:" << std::endl
    << "sign:\t\t" << sign_dur.count() << std::endl
    << "verify:\t\t" << verify_one_dur.count() << std::endl
    << "aggregate:\t" << aggregate_two_dur.count() << std::endl
    << "verify_aggregate 2:\t" << verify_aggregate_dur.count() << std::endl
    << "verify_aggregate 3:\t" << verify_aggregate_three_dur.count() << std::endl;
}
