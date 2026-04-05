# agscan

`agscan` is a C++20 file carving utility for scanning binary blobs and extracting embedded files.

## Features

- Signature-dispatched scanning to avoid trying every handler at every byte
- Stream scanning with carry-over for cross-chunk detections
- Full-buffer extraction mode
- Per-file analysis output for metadata and suspicious cases

## Supported Formats

- GIF
- BMP
- CAB
- ICO
- PNG
- JPEG/JPG
- WEBP
- WAV
- AVI
- FLV
- OGG
- PDF
- RTF
- ZIP
- 7z
- PE (Portable Executable)
- ELF
- WASM
- Java class
- DEX
- pcap
- SQLite
- pcapng

## Hit Modes

`scan` reports both confirmed hits and suspicious hits.

- Confirmed hits are printed as `<type> at 0x... size ...` and can be extracted.
- Suspicious hits are printed as `possible <type> at 0x... size ...` when the header and part of the structure match, but the payload looks truncated or the expected trailer, end marker, or directory is missing.

`extract` only writes confirmed hits to disk, but still prints suspicious hits in the terminal output for review.

## Analysis

`scan` and `extract` print lightweight metadata for recognized files. Depending on format, the tool can report:

- Image dimensions, color mode, bit depth, interlace, and CRC anomalies
- Audio format, sample rate, channel count, duration, and byte rate
- Video/container flags, frame counts, timestamps, and stream hints
- Archive entry counts, compression methods, encryption hints, and timestamps
- Executable architecture, subsystem, entry point, and header timestamps
- Database page size, encoding, schema format, and application id
- Packet capture timestamp ranges, link type, packet counts, and IPv4 peers

Some formats also expose suspicious-case metadata. For example:

- PNG reports IHDR CRC mismatches and brute-forced dimension candidates
- ZIP suspicious hits still show local-header method, encryption flag, and timestamp
- CAB / JPEG / pcap suspicious hits retain whatever header metadata is still trustworthy

## Usage

```powershell
agscan <file> scan
agscan <file> extract
```

`scan` prints file type, offset, size, and analysis metadata.

`extract` writes recovered confirmed files into an `out` directory in the current working directory.
