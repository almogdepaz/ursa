//implementation of the Threshold Identity-Based Encryption scheme presented in the paper
//Chosen Ciphertext Secure Public Key Threshold Encryption Without Random Oracles
//By Dan Boneh, Xavier Boyen, and Shai Halevi
//https://crypto.stanford.edu/~dabo/pubs/papers/ibethresh.pdf


use std::convert::TryFrom;

use amcl_wrapper::{
    group_elem::GroupElement,
    group_elem_g1::G1,
    group_elem_g2::G2,
};
use amcl_wrapper::constants::CurveOrder;
use amcl_wrapper::field_elem::FieldElement;
use rand::{Rng, thread_rng};
use zeroize::Zeroize;

use bn::BigNumber;
use sharing::shamir::{Element, Polynomial};
use signatures::bls::PrivateKey;

pub struct ID(pub Vec<u8>);
impl_bytearray!(ID);

pub struct VerificationKey(pub Vec<u8>);
impl_bytearray!(VerificationKey);


pub struct Share {
    pub j: i32,
    pub value: G2,
}

pub struct PublicKey {
    g: G1,
    g1: G1,
    g2: G2,
    h1: G2,
}


//setup initiate the public parameters used in the scheme
//this implementation of the setup function assumes a single unique trusted party
//that generates the entire system parameters, including the "master" secret key 'a'
// n = #parties ; k = threshold
pub fn setup(n: i32, k: i32) -> (PublicKey, Vec::<G1>, Vec::<Share>) {

    //assert k<=n
    //assert k > 0 and n > 0
    if k <= n && n > 0 {
        panic!("bad input") //todo error handling
    }


    let g: G1 = G1::generator();
    let g2: G2 = G2::generator();
    let h1: G2 = G2::generator();


    let alpha: FieldElement = FieldElement::random();
    let g1: G1 = g.scalar_mul_const_time(&alpha);

    let a: Element = Element {
        //p
        modulus: BigNumber::from_hex(&CurveOrder.tostring()).unwrap(),
        //alpha
        value: BigNumber::from_hex(&alpha.to_bignum().tostring()).unwrap(),
    };


    //random number generator
    let mut rng = thread_rng();
    //compute polynomial evaluations 1..n
    let mut pol_eval: Vec<BigNumber> = Vec::with_capacity(n as usize);
    let polynomial = Polynomial::new(&a, (k - 1) as usize).unwrap();
    for _x in 1..n {
        //todo figure out the correct style for using unwrap
        let el = Element { modulus: a.modulus.try_clone().unwrap(), value: BigNumber::from_u32(rng.gen()).unwrap() };
        let y = polynomial.evaluate(&el).unwrap();
        pol_eval.push(y.value)
    }


    //compute master key share
    let mut sk: Vec<Share> = Vec::with_capacity(n as usize);
    for j in 1..n {
        let b: &BigNumber = pol_eval.get(usize::try_from(j).unwrap()).unwrap();

        sk.push(Share {
            j,
            value: g2.clone().scalar_mul_variable_time(&FieldElement::from_hex(BigNumber::to_hex(b).unwrap()).unwrap()),
        })
    }

    //compute verification key
    let mut vk: Vec<G1> = Vec::with_capacity(n as usize);
    for j in 1..n {
        let b: &BigNumber = pol_eval.get(usize::try_from(j).unwrap()).unwrap();
        //todo need to test that the value exists
        vk.push(g.clone().scalar_mul_variable_time(&FieldElement::from_hex(BigNumber::to_hex(b).unwrap()).unwrap()))
    }

    let pk: PublicKey = PublicKey { g, g1, g2, h1 };
    return (pk, vk, sk);
}


pub fn shareKeyGen(pk: PublicKey, i: i32, ski: Share, id: ID) -> Share { return Share { j: 0, value: Default::default() }; }

pub fn shareVerify(pk: PublicKey, vk: VerificationKey, id: ID, ti: Share) -> bool { return true; }

pub fn combine(pk: PublicKey, vk: String, id: ID, si: &[i32]) -> PrivateKey {
    return PrivateKey::random();
}

pub fn encrypt(pk: PublicKey, id: ID, m: String) -> String { return "".to_string(); }

pub fn decrypt(pk: PublicKey, id: ID, d: String, c: String) -> String { return "".to_string(); }

pub fn validateCt(pk: PublicKey, id: i32, c: String) -> bool { return true; }










