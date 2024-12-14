use core::ec::stark_curve::GEN_X;
use core::ec::stark_curve::GEN_Y;
use core::ec::stark_curve::ORDER;
use core::fmt::{Display, Formatter, Error};

use core::ec::{EcPoint, EcPointTrait, ec_point_unwrap, NonZeroEcPoint, EcState, EcStateTrait};
use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait,};
use core::math::u256_mul_mod_n;

pub impl EcPointDisplay of Display<EcPoint> {
    fn fmt(self: @EcPoint, ref f: Formatter) -> Result<(), Error> {
        let non_zero: NonZeroEcPoint = (*self).try_into().unwrap();
        let (x, y): (felt252, felt252) = ec_point_unwrap(non_zero);
        writeln!(f, "Point ({x}, {y})")
    }
}

fn main() {
    let generator: EcPoint = EcPointTrait::new(GEN_X, GEN_Y).unwrap();
    //let g_hash: felt252 = PoseidonTrait::new().update(GEN_X).finalize();
    //println!("Generator: {}", generator);
    let H: EcPoint = hash_to_curve().unwrap();
    println!("Generator H: {}", H);

    let value: felt252 = 77777;
    let salt: felt252 = 228282189421094;
    let c = pedersen_commit(value, salt, H);

    println!("Commitment: {}", c);
    
}

//We are working with the STARK Elliptic Curve.
fn pedersen_commit(value: felt252, salt: felt252, H: EcPoint) -> EcPoint{
    //TODO: do it like Monero hash_to_curve(poseidon_hash(G))
    let generator: EcPoint = EcPointTrait::new(GEN_X, GEN_Y).unwrap();
    let c_1 = generator.mul(value);
    let c_2 = H.mul(salt);
    
    c_1 + c_2 //Elliptic curve point addition
}

//Takes the hash of the message and maps it on the STARK curve.
//Credit: https://github.com/AbdelStark/cashu-zk-engine/blob/main/src/core.cairo
fn hash_to_curve() -> Option<EcPoint>{
    let g_hash = PoseidonTrait::new().update(GEN_X);
    let mut counter = 0;
    loop {
        // 2^16 is the maximum number of attempts we allow to find a valid point
        if counter == 65536_u32 {
            break Option::None;
        }

        let _hash: felt252 = g_hash.update_with(counter).finalize();

        println!("Hash_to_curve counter: {}", counter);

        // Check if the point is on the curve
        match EcPointTrait::new_from_x(_hash) {
            // If the point is on the curve, return it
            Option::Some(point) => {
                break Option::Some(point);
            },
            // If the point is not on the curve, try again
            Option::None(_) => { counter += 1; }
        }
    }
}