# csgo internal dumper

This project aims to be a small example on how to use memflow in a real-world application.

It is able to dump various CS:GO internal cheats from outside of the target machine. Since it operates on the [memflow physical memory introspection](https://github.com/memflow/memflow) framework it can be used either from a virtual-machine host (like [kvm](https://github.com/memflow/memflow-kvm), [qemu](https://github.com/memflow/memflow-qemu-procfs)) or directly from hardware ([pcileech](https://github.com/memflow/memflow-pcileech)).

## how does it work?

The basic mode of operation has 3 stages.

### 1. collecting data from the game

The first stage just collects data from the game by parsing Interfaces, RecvProps and ConVars. In the first stage all of those potential functions are collected and stored for later use.

### 2. determining hooks

The second stage uses the individual `collectors` to find potentially hooked functions in the previously determined functions.

### 3. mapping out the target module sections

The third stage disassembles all the potential hooks and maps out most of the mapped sections from the cheat. Through the use of the [iced](https://github.com/0xd4d/iced) disassembler we are following all references to other functions and potential data (jumps, calls, movs, etc).

Since we know the entry point of each function (from when they are called in the game) we know the proper alignment of the cheat (even if it is miss-aligned by a few bytes for 'obfuscation' reasons).

After everything has been mapped out we are dumping all those memory sections to disc.

## License

Licensed under MIT License, see [LICENSE](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
