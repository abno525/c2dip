<p align="center"><img src="assets/logo.svg" alt="c2dip" width="440" height="154"></p>

# c2dip

c2dip is an encrypted two-way command and small-file channel over the DeepSeek Files API. Each channel uses separate asymmetric keys, and runtime HTTP connects directly only to `api.deepseek.com`.

Build the static Linux binary with `bash scripts/build-linux.sh`, then create a channel with `./c2dip init --channel lab`. Give each endpoint only its own generated key bundle.

Set `DEEPSEEK_API_KEY` on both endpoints. Start the receiver with `./c2dip recv --channel lab` and the client with `./c2dip send --channel lab`.
