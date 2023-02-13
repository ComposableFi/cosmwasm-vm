
# Cosmwasm Orchestrate

CosmWasm Orchestrate is a tool for simulating and testing CosmWasm contracts on a virtual machine. Although this is the first version of the tool, it already provides a very close simulation experience to running your contracts on an actual chain.

## Why use this?

- **Complete simulation on a VM**: Your contracts do not run in a mock environment but actually in a complete VM, therefor your `CosmosMsg`'s, queries, and sub-messages run properly.

- **IBC capable**: You don't need to spin up a few chains to simulate IBC. You can just start a few VM instances on our framework and run IBC contracts in memory. This means that you will be able to test your IBC contracts really fast and correctly.
    
- **Easy to use**: Talking about VMs might sound frustrating but there is almost no setup necessary to run a test. Just provide the wasm contract that you want to test and call the entry point that you wanna test.

- **Flexible**: The framework is also very flexible and lets you define your own mechanism to handle custom messages, handle different address formats and even implement your own host functions and VM.


To learn more, go to the [documentation](https://docs.composable.finance/developer-guides/cosmwasm-orchestrate).