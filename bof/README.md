# CDP Toolkit BOF

This directory contains a native x64 Windows client for one-shot CDP operations. The same source builds a standalone validation executable and a Beacon Object File.

```sh
make
```

The standalone syntax is:

```text
cdptk-c.exe <command> [port] [arg1] [arg2] [flags]
```

The Aggressor command is:

```text
cdptk <command> [port] [arg1] [arg2] [flags]
```

Supported commands are `discover`, `tabs`, `screenshot`, `cookies`, `page-new`, `page-close`, `contexts`, `context-dispose`, `snapshot`, `extensions-load`, `bookmarks`, `history`, `saved-passwords`, and `extensions`.

For `screenshot`, `arg1` selects a page by one-based index, target ID prefix, title, or URL text. Set `flags=1` for a full-page capture. For `page-new`, `arg1` is the URL and `arg2` is `visible`, `background`, `hidden`, or `isolated`. For `snapshot`, `arg1` is the target selector and `arg2` is `ax` or `dom`. For `extensions-load`, `arg1` is the absolute directory path and `flags=1` enables incognito access.

Screenshot, snapshot, and WebUI collector results are returned with `BeaconDownload`; other JSON results are emitted as UTF-8 output. No target-side output files are created by the BOF.

For TrustedSec COFFLoader testing, generate the packed argument blob with:

```sh
python3 pack_args.py discover --port 9333
```

The stock compatibility layer does not implement `BeaconDownload`. Add a
compatibility implementation and resolver entry before building the loader so
download-producing commands can be exercised with the same production object.
