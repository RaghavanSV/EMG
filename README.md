
# EMG - Evasive Malware Generator

## Overview

**EMG (Evasive Malware Generator)** is a research-focused tool designed for educational and cybersecurity research purposes.  
It generates malware samples with a range of evasion techniques aimed at bypassing static and dynamic analysis methods, helping defenders and analysts better understand, detect, and protect against modern threats.

⚠️ **Important:**  
This tool is intended strictly for **educational**, **research**, and **defensive security** purposes. Unauthorized use against systems without explicit permission is illegal.

---

## Modifications

| "pad_overlay" |
| "append_benign_data_overlay" |
| "append_benign_binary_overlay" |
| "add_bytes_to_section_cave" |
| "add_section_strings" |
| "add_section_benign_data" |
| "add_strings_to_overlay" |
| "add_imports" |
| "rename_section" |
| "remove_debug" |
| "modify_optional_header" |
| "modify_timestamp" |
| "break_optional_header_checksum" |
| "upx_unpack" |
| "upx_pack" |

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
python3 emg.py --path <samples>
```
---

### Example:

```bash
python emg.py --path malware_samples --num_episodes 5 --output_dir .
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

