// input.rs ---



pub type OutputOf<T> = <T as Input>::Output;

pub trait Input {
    type Output;
}
