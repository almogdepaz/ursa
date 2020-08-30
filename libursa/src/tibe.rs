
//implementation of the Threshold Identity-Based Encryption scheme presented in the paper
//Chosen Ciphertext Secure Public Key Threshold Encryption Without Random Oracles
//By Dan Boneh, Xavier Boyen, and Shai Halevi
//https://crypto.stanford.edu/~dabo/pubs/papers/ibethresh.pdf

use rand::Rng;

use CryptoResult;
use keys::{PrivateKey, PublicKey};
use pair::{Pair, PointG1, PointG2};
use sharing::shamir::Polynomial;
use amcl_wrapper::{
    constants::{GroupG1_SIZE, MODBYTES},
    extension_field_gt::GT,
    field_elem::FieldElement,
    group_elem::GroupElement,
    group_elem_g1::G1,
    group_elem_g2::G2,
    types_g2::GroupG2_SIZE,
};

//Do we need this or is it already part of amcl_wrapper (which the following is copied form)?
use crate::constants::{
    //BarrettRedc_k, BarrettRedc_u, BarrettRedc_v, BigNumBits, FieldElement_SIZE, NLEN,
    CurveOrder
};

pub struct ID(pub Vec<u8>);
impl_bytearray!(ID);

pub struct VerificationKey(pub Vec<u8>);
impl_bytearray!(VerificationKey);

pub struct ShareKey(pub Vec<u8>);
impl_bytearray!(ShareKey);

pub struct PrivateKeyShare(pub Vec<u8>);
impl_bytearray!(PrivateKeyShare);

//setup initiate the public parameters used in the scheme
//this implementation of the setup function assumes a single unique trusted party
//that generates the entire system parameters, including the "master" secret key 'a'
// n = #parties ; k = threshold
pub fn setup(n: i32, k: i32) -> (PublicKey, VerificationKey, Vec::<ShareKey>) {

    //assert k<=n? both greater than 0?
    if n < k {
        return Err(CryptoError::GeneralError(
            "#parties cannot be less than the threshold".to_string(),
        ));
    }

    //let g = PointG1::new().unwrap();
    //let g2 = PointG2::new().unwrap();
    //let h1 = PointG2::new().unwrap();
    //let mut rng = rand::thread_rng();

    let a = PolyElement {
        modulus: rand::thread_rng(), //random value
        value: rand::thread_rng(), //random value
    };

    //use pol_to_field_elem()??
    alpha = a.value;

    let g = G1::generator();
    let g2 = G2::generator();
    let h1 = G2::generator();

    let g1 = g * alpha; // or g.scalar_mul_variable_time(&a); see documentation: https://lib.rs/crates/amcl_wrapper 2.Scalar multiplication

    //calc polynomial variables
    let polynomial = Polynomial::new(a, (k - 1) as usize)?;

    // we don't need to find, since we set it to be 'a'
    // maybe we'd like to assert that indeed a=poly(0), though probably it is tested - so only temporarily
    //find value at x==0
    let alpha2 = polynomial.evaluate(&x)?;

    //compute g1
    //let g1 = g ^ alpha;

    //compute polynomial evaluations 1..n
    //don't know if we want this to be a map (x,pol(x))
    let mut pol_eval = Vec::with_capacity(n as usize);
    for x in 1..n {
        //let y = polynomial.evaluate(x)?;
        let y = poly_eval(x)?;
        //let y_val = pol_to_field_elem(y);
        pol_eval.push(y_val)
    }

    //compute master key shares
    let mut SK = Vec::with_capacity(n as usize);
    for j in 1..n {
    //for j in 0..n-1 {   ???
        //let identifier = j + 1;
        let b = pol_eval[j];
        let t = g2 * b;
        SK.push(Share {
            //identifier,
            j,
            G2: t,
        });
    }

    //compute verification key
    let mut VK = Vec::with_capacity(n as usize);
    for j in 1..n {
        //for j in 0..n-1 {   ???
        let b = pol_eval[j];
        let t = g * b;
        VK.push(t);
    }


    PK = (g, g1, g2, h1);
    //VK = (gf(1), . . . , gf(n)
    //SKi = g^f(i)

    return (PK, VK, SK);
}


pub fn shareKeyGen(pk: PublicKey, i: i32, ski: ShareKey, id: ID) -> PrivateKeyShare {}

pub fn shareVerify(pk: PublicKey, vk: VerificationKey, id: ID, ti: PrivateKeyShare) -> bool {}

pub fn combine(pk: PublicKey, vk: String, id: ID, si: &[i32]) -> PrivateKey {}

pub fn encrypt(pk: PublicKey, id: ID, m: String) -> String {}

pub fn decrypt(pk: PublicKey, id: ID, d: String, c: String) -> String {}

pub fn validateCt(pk: PublicKey, id: i32, c: String) -> bool {}


//convert *numbers* from the shamir.rs representation {modulus:BigNumber,value:BigNumber}
//to a field element {value:BigNum}
//maybe should go through to_bytes() --> from_bytes()
pub fn pol_to_field_elem(pol_elem: PolyElement) -> field_element {
    return pol_elem.value;
}

// pub??
pub fn poly_eval(x: PolyElement) -> field_element {

    let elem = PolyElement {
        modulus: CurveOrder,
        value: x,
    };
    let y = polynomial.evaluate(x)?;
    return y.value;
}




