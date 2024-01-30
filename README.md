# SUI proof of concept framework

The SUI POC Framework is a Rust library created to help security researchers interact with SUI packages in a local simulated environment. Inspired by the Solana POC Framework.

## Features

- Clone objects from an rpc client
- Publish packages from a local directory
- Easily track coin balances through transactions

## Installation

You can install the SUI POC Framework by adding the following line to your Cargo.toml file:

```
[dependencies]
sui-poc-framework = { git = "https://github.com/Garrett-Weber/sui-poc-framework" }
```

## Usage

Building a local enviroment using the EnviromentBuilder

```rust
let env = Environment::builder()
            .fund_key(researcher_address)
            .publish_package(path)
            .unwrap()
            .clone_objects_from_owner(owner_address, rpc_client)
            .unwrap()
            .build();
```

Interacting with the enviroment

```rust
let bal_before = env.get_balance(researcher_address);
env.execute_transaction(tx).unwrap();
let bal_after = env.get_balance(researcher_address);
if bal_after > bal_before {
    println!("Success!");
}
```

# License

This project is licensed under the terms of the MIT License.
