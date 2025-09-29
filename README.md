
# EMG - Evasive Malware Generator

## Overview

**EMG (Evasive Malware Generator)** is a research-focused tool designed for educational and cybersecurity research purposes.  
It generates malware samples with a range of evasion techniques aimed at bypassing static and dynamic analysis methods, helping defenders and analysts better understand, detect, and protect against modern threats.

⚠️ **Important:**  
This tool is intended strictly for **educational**, **research**, and **defensive security** purposes. Unauthorized use against systems without explicit permission is illegal.

---

## Modifications

# Modifications

| Modification                     | Description                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| `pad_overlay`                    | Pads the file’s overlay with additional bytes.                              |
| `append_benign_data_overlay`     | Appends harmless data to the overlay section.                               |
| `append_benign_binary_overlay`   | Appends a benign binary blob to the overlay.                                |
| `add_bytes_to_section_cave`      | Injects extra bytes into unused space (cave) of a section.                  |
| `add_section_strings`            | Creates a new section filled with benign strings.                           |
| `add_section_benign_data`        | Adds a section containing benign/random data.                               |
| `add_strings_to_overlay`         | Appends benign strings to the overlay area.                                 |
| `add_imports`                    | Adds extra harmless imports to the import table.                            |
| `rename_section`                 | Renames one or more sections to different labels.                           |
| `remove_debug`                   | Removes debug information from the binary.                                  |
| `modify_optional_header`         | Alters non-critical fields in the PE optional header.                       |
| `modify_timestamp`               | Modifies the file’s timestamp metadata.                                     |
| `break_optional_header_checksum` | Corrupts or invalidates the optional header checksum.                        |
| `upx_unpack`                     | Unpacks the binary if it is UPX-compressed.                                 |
| `upx_pack`                       | Re-packs the binary using UPX compression.                                  |

---
## Project Directory Structure
```
EMG/
├─ good_strings/ # Collection of benign string samples
│ ├─ good1.txt
│ └─ good2.txt
├─ trusted/ # Trusted binaries or reference binaries
├─ feature_extraction2.py # Script for feature extraction
├─ malconv.py # Implementation / interface for MalConv model
├─ malconv.h5 # Pretrained MalConv model weights
├─ modifier.py # Binary modification utilities
├─ optimised_miniproject_code3.py# Main/optimized project script
├─ requirements.txt # Python dependencies
├─ section_names.txt # List of PE section names
├─ small_dll_imports.json # JSON with sample DLL imports
└─ README.md # Project documentation
```
---

---

## Installation

```bash
git clone https://github.com/RaghavanSV/EMG.git
cd EMG
pip install -r requirements.txt
```

---

## Flags

```bash
tail emg.py
```
---

## Training

```bash
python3 emg.py --path <path to malware_samples>
```
---

### Example:

```bash
python3 emg.py --path malware_samples --num_episodes 5 --output_dir .
```

---

## Usage

```bash
python3 emg.py 
```

### Main Options:

| Argument         | Description                            |
| ---------------- | -------------------------------------- |
| `--path`          | Path to the malware samples |
| `--num_episode`   | Number of Episodes for a single exe during training | 
| `--lr`            | This tells how fast a model should learn |
| `--use_cuda`      | To use the gpu |
| `--output_dir`    | directory to store the trained model |

---

## Legal Disclaimer

> This tool is developed solely for educational and authorized testing environments.  
> **The developer is not responsible for any misuse of this tool.**  
>  
> Always ensure you have explicit permission before deploying payloads on any system.

---

## Contribution

Contributions are welcome!  
Feel free to submit a pull request or open an issue for feature requests, bug reports, or ideas.

---

## Contact

- Author: [Lalith Raghavan]
- GitHub: [RaghavanSV](https://github.com/RaghavanSV)

