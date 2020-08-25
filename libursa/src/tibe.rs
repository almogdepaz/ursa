use rand::Rng;

use CryptoResult;
use keys::{PrivateKey, PublicKey};
use pair::{Pair, PointG1, PointG2};
use sharing::shamir::Polynomial;

pub struct ID(pub Vec<u8>);
impl_bytearray!(ID);

pub struct VerificationKey(pub Vec<u8>);
impl_bytearray!(VerificationKey);

pub struct ShareKey(pub Vec<u8>);
impl_bytearray!(ShareKey);

pub struct PrivateKeyShare(pub Vec<u8>);
impl_bytearray!(PrivateKeyShare);


pub fn setup(n: i32, k: i32, a: i32) -> (PublicKey, VerificationKey, Vec::<ShareKey>) {
    let g = PointG1::new().unwrap();
    let g2 = PointG2::new().unwrap();
    let h1 = PointG2::new().unwrap();
    let mut rng = rand::thread_rng();


    let element = Element {
        modulus: rand::thread_rng(), //random value
        value: rand::thread_rng(), //random value
    };

    //calc polynomial variables
    let polynomial = Polynomial::new(element, (threshold - 1) as usize)?;

    //find value at x==0
    let alpha = polynomial.evaluate(&x)?;

    //compute g1
    let g1 = g ^ alpha;

    // PK = (G, g, g1, g2, h1).

    //VK = (gf(1), . . . , gf(n)


    //SKi = g^f(i)


    return (nil, nli, nil);
}


pub fn shareKeyGen(pk: PublicKey, i: i32, ski: ShareKey, id: ID) -> PrivateKeyShare {}

pub fn shareVerify(pk: PublicKey, vk: VerificationKey, id: ID, ti: PrivateKeyShare) -> bool {}

pub fn combine(pk: PublicKey, vk: String, id: ID, si: &[i32]) -> PrivateKey {}

pub fn encrypt(pk: PublicKey, id: ID, m: String) -> String {}

pub fn decrypt(pk: PublicKey, id: ID, d: String, c: String) -> String {}

pub fn validateCt(pk: PublicKey, id: i32, c: String) -> bool {}



