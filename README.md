<p align="center">
  <img src="assets/logo.svg" alt="c2dip" width="440" height="154">
</p>

# c2dip

Communication is possible.

Two-way command console over the DeepSeek Files API:

```
./files_api.py recv
./files_api.py send
./files_api.py upload ./some_file
./files_api.py download
```

- `recv` runs received commands and saves received files in its current
  directory (`--out DIR` to change).
- `send` is a console. `upload <path>` sends a local file; `download <path>`
  fetches a file from recv (relative to recv's directory, or absolute).
- `download` with no path saves any pending files to `downloads/`.

Set `DEEPSEEK_API_KEY`, or put it in `key.txt`.
