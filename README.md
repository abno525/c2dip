<p align="center"><img src="assets/logo.svg" alt="c2dip" width="440" height="154"></p>

# c2dip

c2dip is an encrypted two-way command and small-file channel over the DeepSeek Files API. Each channel uses separate asymmetric keys, and runtime HTTP connects directly only to `api.deepseek.com`.

Messages are encrypted and signed with the channel's keys, split into chunks, and exchanged in the filenames of tiny PNG files stored in the shared DeepSeek Files API store.

`./c2dip-sender upload --channel lab FILE` sends a file to the receiver; `./c2dip-sender download --channel lab FILE` fetches one back and saves it under `downloads/`.

Build the sender with `bash scripts/build-sender.sh`, then create a channel with `./c2dip-sender init --channel lab`. Give each endpoint only its own generated bundle from `keys/lab/`.

Build a zero-setup receiver with `DEEPSEEK_API_KEY='key' bash scripts/build-receiver.sh lab`, then run `./c2dip-receiver`; embedded credentials are extractable from the binary. Set `DEEPSEEK_API_KEY` on the client and run `./c2dip-sender --channel lab`.
