# Change Log

## 3.1.4 (Mar 23, 2025)

- Increased reliability of DHT rendezvous.

## 3.1.3 (Mar 8, 2025)

- Fixed handshake race when using DHT rendezvous.

## 3.1.2 (Feb 26, 2025)

- The CMake project has been reorganized.

## 3.1.1 (Nov 17, 2024)

- Link with opendht version 3.2 to stabilize the DHT rendezvous

## 3.1.0 (Aug 1, 2024)

- The ability to use DHT as the rendezvous.

## 3.0.1 (May 31, 2024)

- Build with default boost library.
- S/MIME mailing fix.

## 3.0.0 (March 30, 2024)

- Added the ability to accept several peers. Implemented the library build.

## 2.2.1 (December 18, 2023)

- Added the debian build package files and improved CMake build scripts.

## 2.2.0 (October 8, 2023)

- Updating `wormhole` tool to 1.1.0 version.

## 2.1.2 (May 13, 2023)

- Updating `wormhole` tool to 1.0.2 version.

## 2.1.1 (February 20, 2023)

- The `wormhole` tool is integrated to provide the possibility of forwarding a remote TCP service to a local interface.
- The ability to specify an custom arguments for executable command, including using *plexus* wildcards.
- Support for ini-like configuration files.

## 2.1.0 (September 2, 2022)

- Upgraded handshake message format and added the experimental ability to punch TCP hole by SYN packet tracing.

## 2.0.1 (August 15, 2022)

- Accumulated fixes and improvements.

## 2.0.0 (August 4, 2022)

- Altered the procedure for punching a *passage* between peers and changed the format of plexus messages.

## 1.0.0 (July 15, 2022)

- First release of the `plexus`. This tool is designed to make the possibility of establishing a direct network connection between applications running on machines located behind NATs.
