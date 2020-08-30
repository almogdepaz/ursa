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
use amcl_wrapper::field_elem::FieldElement;
use rand::Rng;
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

    //assert k<=n? both greater than 0?
    if n < k {
        panic!("bad input") //todo error handling
    }

    //random number generator
    let mut rng = rand::thread_rng();

    let g = G1::generator();
    let g2 = G2::generator();
    let h1 = G2::generator();
    let p = BigNumber::generate_prime(128).unwrap();
    let alpha: u32 = rng.gen();


    // compute  g1 = g * alpha;
    let scalar = &FieldElement::from(alpha);
    let g1 = g.scalar_mul_const_time(scalar);
    //calc polynomial variables
    //init with a as f(0)

    let a = Element {
        modulus: p,
        value: BigNumber::from_u32(rng.gen()).unwrap(), //convert to BigNumber
    };
    let polynomial = Polynomial::new(&a, (k - 1) as usize).unwrap();


    //compute polynomial evaluations 1..n
    //don't know if we want this to be a map (x,pol(x))
    let mut pol_eval = Vec::with_capacity(n as usize);
    for x in 1..n {
        //todo figure out the correct style for using unwrap
        let t = BigNumber::from_u32(rng.gen()).unwrap();
        let y = polynomial.evaluate(t).unwrap();
        pol_eval.push(y)
    }


    //compute master key share

    let mut sk = Vec::with_capacity(n as usize);
    for j in 1..n {
        //for j in 0..n-1 {   ???
        //let identifier = j + 1;
        let b = pol_eval.get(usize::try_from(j).unwrap()).unwrap();
        sk.push(Share {
            j,
            value: g2.clone().scalar_mul_const_time(&pol_to_field_elem(b)),
        });
    }

    //compute verification key
    let mut vk = Vec::with_capacity(n as usize);
    for j in 1..n {
        //for j in 0..n-1 {   ???
        let b = pol_eval.get(usize::try_from(j).unwrap()).unwrap();
        //todo need to test that the value exists
        vk.push(g.clone().scalar_mul_const_time(&pol_to_field_elem(b)));
    }

    let pk = PublicKey { g, g1, g2, h1 };
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


//convert *numbers* from the shamir.rs representation {modulus:BigNumber,value:BigNumber}
//to a field element {value:BigNum}
//maybe should go through to_bytes() --> from_bytes()
pub fn pol_to_field_elem(pol_elem: &Element) -> FieldElement {
    return FieldElement::from(pol_elem.value);
}



