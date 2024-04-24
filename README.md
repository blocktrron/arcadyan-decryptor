# arcadyan-decryptor

Extractor for Firmware images from Arcadyan devices.


## Supported Devices

 - [Telekom Speedport 5G Empfänger SE](http://firmware.acs.t-online.de/tftpboot/cpe/DT5GR2A/DTAG-CPE-Information.xml)


## Required dependencies

```bash
apt-get install build-essential cmake libssl-dev
```


## Decryption Keys

In the `contrib` directory you can find decryption keys extracted from the device.
They are not covered by the license of this project.


## Usage

```bash
arcadyan-decryptor <public_key_file> <input_file> <output-path>
```