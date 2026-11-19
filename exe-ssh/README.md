# exe-ssh

An experimental SSH-like interactive terminal for [exe.dev](https://exe.dev)
VMs. It connects over HTTPS rather than port 22 and supports persistent named
sessions and automatic reconnection.

Run it directly from the Git repository with
[uv](https://docs.astral.sh/uv/):

```sh
uvx --from 'exe-ssh @ git+https://github.com/boldsoftware/exe.dev.git#subdirectory=exe-ssh' exe-ssh VM
```

For example:

```sh
uvx --from 'exe-ssh @ git+https://github.com/boldsoftware/exe.dev.git#subdirectory=exe-ssh' exe-ssh willow-wind
```

`uvx` caches the Git checkout and installed environment. Add `--refresh` when
you want it to check the default branch for a newer revision:

```sh
uvx --refresh --from 'exe-ssh @ git+https://github.com/boldsoftware/exe.dev.git#subdirectory=exe-ssh' exe-ssh willow-wind
```

Pass a second argument to use a named persistent session, or `--list` to list
sessions:

```sh
uvx --from 'exe-ssh @ git+https://github.com/boldsoftware/exe.dev.git#subdirectory=exe-ssh' exe-ssh willow-wind work
uvx --from 'exe-ssh @ git+https://github.com/boldsoftware/exe.dev.git#subdirectory=exe-ssh' exe-ssh willow-wind --list
```

The client uses the SSH identity selected by `ssh -G` by default. Pass
`--key PATH` to select one explicitly.

## exe-clone: throwaway clones

`exe-clone` clones a VM, opens a terminal on the clone, and asks whether to
remove the clone when you exit its shell (Ctrl-D or `exit`). A dropped
connection reconnects as usual and never triggers the prompt.

```sh
uvx --from 'exe-ssh @ git+https://github.com/boldsoftware/exe.dev.git#subdirectory=exe-ssh' exe-clone willow-wind
```

The clone is named after its source with a random suffix, e.g.
`willow-wind-k3f9`, and the command to remove it by hand is printed before
connecting. The prompt defaults to keeping the clone; pass `--rm` to remove it
without asking. The clone is always kept if exe-clone is interrupted or killed.
