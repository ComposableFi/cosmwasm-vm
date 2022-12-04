# `Direct` and `Dispatch` API's 

Sometimes, it might be not required to do a complete simulation of an entrypoint.
For example, you might wanna execute `instantiate` entrypoint but you might just wanna
get the `instantiate` functions result and don't proceed to sub-message execution.
Therefore, there are two execution types that handles exactly this: `Direct` and `Dispatch`.


## Dispatch

When you want to simulate a complete execution like how a transaction is handled in a real environment, `Dispatch` is used.
`Dispatch` executes the entrypoint you call and also handles the sub-messages. It commits the transaction
changes when the execution succeeds and aborts it when the execution fails.

Note that the same error handling mechanism is valid here as well. In the case of an error in the top-level contract,
the transaction will be reverted, otherwise, the behavior will be up to the user (catching errors with `Reply`).

`Dispatch` is the default execution type of `Api`'s. So you don't need to specify `Dispatch`
like `JunoApi::<Dispatch>::..`. But note that, because of the limitations of rust's type
inference, you can't do `JunoApi::instantiate`, but need to use it like `<JunoApi>::instantiate` for
Rust to infer the generic types for you.


## Direct

Some entrypoints like `query` are not meant to be `Dispatch` and also sometimes you might to just 
run an entrypoint and get the `Response` without running and sub-messages or creating a transaction. 
`Direct` is used in this case. Running a dispatchable entrypoint(eg. `instantiate`) with `Direct` is like a unit-test.

But the notable thing is some entrypoints like `instantiate` might modify the storage. And since they are not
handled like `Dispatch`, the changes won't get reverted if the execution fails. It is not a big deal since
you will probably want to abort the test in case of failure anyways. But if for some reason you want to call
a dispatchable entrypoint and make sure that the storage modifications are not persisted, you can just create
a seperate state for each run.

You can set the execution type to `Direct` by specifying it during the call:

```rust
JunoApi::<Direct>::instantiate();
// or
<JunoApi<Direct>>::instantiate();
```
