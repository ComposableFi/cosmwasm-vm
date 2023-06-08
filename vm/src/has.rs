// has.rs ---



pub trait Has<T> {
    fn get(&self) -> T;
}
