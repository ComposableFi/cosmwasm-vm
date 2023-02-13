use super::Account;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use cosmwasm_std::Coin;

pub type Denom = String;
pub type Supply = BTreeMap<Denom, u128>;
pub type Balances = BTreeMap<Account, Supply>;

#[derive(Default, Debug, Clone)]
pub struct Bank {
    pub supply: Supply,
    pub balances: Balances,
}

impl Bank {
    pub fn new(supply: Supply, initial_balances: Balances) -> Self {
        Self {
            supply,
            balances: initial_balances,
        }
    }

    pub fn transfer(&mut self, from: &Account, to: &Account, coins: &[Coin]) -> Result<(), Error> {
        for Coin { denom, amount } in coins {
            let amount: u128 = (*amount).into();
            let from_balance = {
                let Some(from_coins) = self.balances.get(from) else {
                    return Err(Error::InsufficientBalance);
                };
                let Some(from_balance) = from_coins.get(denom) else {
                    return Err(Error::InsufficientBalance);
                };
                *from_balance
            };

            if from_balance < amount {
                return Err(Error::InsufficientBalance);
            }

            self.balances
                .entry(to.clone())
                .and_modify(|balance| {
                    balance
                        .entry(denom.clone())
                        .and_modify(|balance| *balance += amount)
                        .or_insert_with(|| amount);
                })
                .or_insert_with(|| [(denom.clone(), amount)].into());

            *self.balances.get_mut(from).unwrap().get_mut(denom).unwrap() -= amount;
        }

        Ok(())
    }

    pub fn burn(&mut self, account: &Account, coins: &[Coin]) -> Result<(), Error> {
        for Coin { denom, amount } in coins {
            let amount: u128 = (*amount).into();
            {
                let Some(coins) = self.balances.get_mut(account) else {
                    return Err(Error::InsufficientBalance);
                };
                let Some(balance) = coins.get_mut(denom) else {
                    return Err(Error::InsufficientBalance);
                };

                if *balance < amount {
                    return Err(Error::InsufficientBalance);
                }
                *balance -= amount;
            }

            *self.supply.get_mut(denom).unwrap() -= amount;
        }

        Ok(())
    }

    pub fn balance<S: AsRef<str>>(&mut self, account: &Account, denom: S) -> u128 {
        *match self.balances.get(account) {
            Some(balance) => balance.get(denom.as_ref()).unwrap_or(&0),
            None => &0,
        }
    }

    pub fn all_balances(&mut self, account: &Account) -> Vec<Coin> {
        match self.balances.get(account) {
            Some(coins) => coins
                .iter()
                .map(|(denom, amount)| Coin::new(*amount, denom))
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn supply<S: AsRef<str>>(&self, denom: S) -> u128 {
        *self.supply.get(denom.as_ref()).unwrap_or(&0)
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Error {
    InsufficientBalance,
}
