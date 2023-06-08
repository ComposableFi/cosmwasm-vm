// transaction.rs ---



pub type TransactionalErrorOf<T> = <T as Transactional>::Error;

pub trait Transactional {
    type Error;
    fn transaction_begin(&mut self) -> Result<(), Self::Error>;
    fn transaction_commit(&mut self) -> Result<(), Self::Error>;
    fn transaction_rollback(&mut self) -> Result<(), Self::Error>;
}
