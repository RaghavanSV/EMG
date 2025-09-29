import lief
import hashlib
import pandas as pd
import numpy as np
import os
import re
from sklearn.feature_extraction import FeatureHasher

def get_file_hashes(file_path):
    return {
        "md5": hashlib.md5(file_path).hexdigest(),
        "sha1": hashlib.sha1(file_path).hexdigest(),
        "sha256": hashlib.sha256(file_path).hexdigest()
    }

def sections_info(file_path,name):
    try:
        pe = lief.parse(file_path)
        if not pe:
            return None
    except Exception:
        return None  # Skip invalid PE files

    features = {"file_name": os.path.basename(name)}
    features.update(get_file_hashes(file_path))
    
    # General Info
    features["Machine"] = pe.header.machine
    features["Number_of_Sections"] = len(pe.sections)
    features["TimeDateStamp"] = pe.header.time_date_stamps
    features["EntryPoint"] = hex(pe.optional_header.addressof_entrypoint)
    features["ImageBase"] = hex(pe.optional_header.imagebase)

    # Sections
    raw_obj={}
    raw_obj["sections"] = [{
        'name': s.name,
        'size': s.size,
        'entropy': s.entropy,
        'vsize': s.virtual_size,
        'props': [str(c).split('.')[-1] for c in s.characteristics_lists]
    } for s in pe.sections]
    sections=raw_obj["sections"]
    general=[len(sections),sum(1 for s in sections if s['size']==0),sum(1 for s in sections if s['name']==""),sum(1 for s in sections if 'MEM_READ' in s['props'] and 'MEM_EXECUTE' in s['props']),sum(1 for s in sections if 'MEM_WRITE' in s['props'])]

    # hashing

    sec_size=[(s['name'],s['size']) for s in sections]
    sec_entropy=[(s['name'],s['entropy']) for s in sections]
    sec_vsize=[(s['name'],s['vsize']) for s in sections]
    section_sizes_hashed = FeatureHasher(50, input_type="pair").transform([sec_size]).toarray()[0]
    section_entropy_hashed = FeatureHasher(50, input_type="pair").transform([sec_entropy]).toarray()[0]
    section_vsize_hashed = FeatureHasher(50, input_type="pair").transform([sec_vsize]).toarray()[0]
    characteristics = [p for s in sections for p in s['props']]
    print(characteristics)
    characteristics_hashed = FeatureHasher(50, input_type="string").transform([characteristics]).toarray()[0]
    features["general"]=general
    features["sec_size_hash"]=section_sizes_hashed
    features["sec_entropy_hash"]=section_entropy_hashed
    features["sec_vsize_hash"]=section_vsize_hashed
    features["characteristics_hashed"]=characteristics_hashed
    return features


def Import_features(bytes,pe):
    imports = {}
    library=[]
    lib_fun=[]
    if pe is None:
        return imports# Extract import features using Import Address Table (IAT)
    for lib in pe.imports:
        library.append(lib.name)
        if lib not in imports:
            imports[lib.name]=[]
    #lib_fun.append(f"{lib.name}:{[fun.name or fun.ordinal for fun in lib.entries]}")
        for fun in lib.entries:
            imports[lib.name].append(fun.name)
    imports_redefined=[f"{lib.lower()}:{funi}" for lib,fun in imports.items() for funi in fun]

    library_hashed=FeatureHasher(256,input_type="string").transform([library]).toarray()[0]
    lib_fun_hashed=FeatureHasher(1024,input_type="string").transform([imports_redefined]).toarray()[0]

    return np.hstack([library_hashed,lib_fun_hashed]).astype(np.float32)

def Export_features(bytes,pe):
    if pe is None:
        return []
    clipped_exports=[export.name[:10000] for export in pe.exported_functions]
    hashed_exports=FeatureHasher(128,input_type="string").transform([clipped_exports]).toarray()[0]
    return hashed_exports.astype(np.float32)

def general_Info(byte,lief_binary):

    if lief_binary is None:
        raw_obj={
            'size': len(byte),
            'vsize': 0,
            'has_debug': 0,
            'exports': 0,
            'imports': 0,
            'has_relocations': 0,
            'has_resources': 0,
            'has_signature': 0,
            'has_tls': 0,
            'symbols': 0
        }
    else:
        raw_obj={
            'size': len(byte),
            'vsize': lief_binary.virtual_size,
            'has_debug': int(lief_binary.has_debug),
            'exports': len(lief_binary.exported_functions),
            'imports': len(lief_binary.imported_functions),
            'has_relocations': int(lief_binary.has_relocations),
            'has_resources': int(lief_binary.has_resources),
            'has_signature': int(lief_binary.has_signatures),
            'has_tls': int(lief_binary.has_tls),
            'symbols': len(lief_binary.symbols)
        }
    return np.asarray([raw_obj['size'], raw_obj['vsize'], raw_obj['has_debug'], raw_obj['exports'], raw_obj['imports'],raw_obj['has_relocations'], raw_obj['has_resources'], raw_obj['has_signature'], raw_obj['has_tls'],raw_obj['symbols']],dtype=np.float32)

def Header_File_Info(byte,lief_binary):
    raw_obj = {}
    raw_obj['coff'] = {'timestamp': 0, 'machine': "", 'characteristics': []}
    raw_obj['optional'] = {
        'subsystem': "",
        'dll_characteristics': [],
        'magic': "",
        'major_image_version': 0,
        'minor_image_version': 0,
        'major_linker_version': 0,
        'minor_linker_version': 0,
        'major_operating_system_version': 0,
        'minor_operating_system_version': 0,
        'major_subsystem_version': 0,
        'minor_subsystem_version': 0,
        'sizeof_code': 0,
        'sizeof_headers': 0,
        'sizeof_heap_commit': 0
        }
    if lief_binary is None:
        return raw_obj
        
    raw_obj['coff']['timestamp'] = lief_binary.header.time_date_stamps
    raw_obj['coff']['machine'] = str(lief_binary.header.machine).split('.')[-1]
    raw_obj['coff']['characteristics'] = [str(c).split('.')[-1] for c in lief_binary.header.characteristics_list]
    raw_obj['optional']['subsystem'] = str(lief_binary.optional_header.subsystem).split('.')[-1]
    raw_obj['optional']['dll_characteristics'] = [str(c).split('.')[-1] for c in lief_binary.optional_header.dll_characteristics_lists]
    raw_obj['optional']['magic'] = str(lief_binary.optional_header.magic).split('.')[-1]
    raw_obj['optional']['major_image_version'] = lief_binary.optional_header.major_image_version
    raw_obj['optional']['minor_image_version'] = lief_binary.optional_header.minor_image_version
    raw_obj['optional']['major_linker_version'] = lief_binary.optional_header.major_linker_version
    raw_obj['optional']['minor_linker_version'] = lief_binary.optional_header.minor_linker_version
    raw_obj['optional']['major_operating_system_version'] = lief_binary.optional_header.major_operating_system_version
    raw_obj['optional']['minor_operating_system_version'] = lief_binary.optional_header.minor_operating_system_version
    raw_obj['optional']['major_subsystem_version'] = lief_binary.optional_header.major_subsystem_version
    raw_obj['optional']['minor_subsystem_version'] = lief_binary.optional_header.minor_subsystem_version
    raw_obj['optional']['sizeof_code'] = lief_binary.optional_header.sizeof_code
    raw_obj['optional']['sizeof_headers'] = lief_binary.optional_header.sizeof_headers
    raw_obj['optional']['sizeof_heap_commit'] = lief_binary.optional_header.sizeof_heap_commit

    return np.hstack([
        raw_obj['coff']['timestamp'],
        FeatureHasher(10, input_type="string").transform([[raw_obj['coff']['machine']]]).toarray()[0],
        FeatureHasher(10, input_type="string").transform([raw_obj['coff']['characteristics']]).toarray()[0],
        FeatureHasher(10, input_type="string").transform([[raw_obj['optional']['subsystem']]]).toarray()[0],
        FeatureHasher(10, input_type="string").transform([raw_obj['optional']['dll_characteristics']]).toarray()[0],
        FeatureHasher(10, input_type="string").transform([[raw_obj['optional']['magic']]]).toarray()[0],
        raw_obj['optional']['major_image_version'],
        raw_obj['optional']['minor_image_version'],
        raw_obj['optional']['major_linker_version'],
        raw_obj['optional']['minor_linker_version'],
        raw_obj['optional']['major_operating_system_version'],
        raw_obj['optional']['minor_operating_system_version'],
        raw_obj['optional']['major_subsystem_version'],
        raw_obj['optional']['minor_subsystem_version'],
        raw_obj['optional']['sizeof_code'],
        raw_obj['optional']['sizeof_headers'],
        raw_obj['optional']['sizeof_heap_commit']]).astype(np.float32)

def String_Extractor(byte,lief_binary):
    allstrings_ex=re.compile(b'[\x20-\x7f]{5,}')
    paths_ex=re.compile(b'c:\\\\',re.IGNORECASE)
    urls_ex=re.compile(b'https?://',re.IGNORECASE)
    registry_ex=re.compile(b'HKEY_')
    mz_ex=re.compile(b'MZ')

    allstrings=allstrings_ex.findall(byte)
    if allstrings:
        string_lengths=[len(s) for s in allstrings]
        avglength=sum(string_lengths) / len(string_lengths)
        as_shifted_string = [b - ord(b'\x20') for b in b''.join(allstrings)]
        c = np.bincount(as_shifted_string, minlength=96)  # histogram count
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh]))  # entropy
    else:
        avglength=0
        H=0
        c=np.zeros((96,),dtype=np.float32)
        csum=0

    raw_obj={
            'numstrings': len(allstrings),
            'avlength': avglength,
            'printabledist': c.tolist(),  # store non-normalized histogram
            'printables': int(csum),
            'entropy': float(H),
            'paths': len(paths_ex.findall(byte)),
            'urls': len(urls_ex.findall(byte)),
            'registry': len(registry_ex.findall(byte)),
            'MZ': len(mz_ex.findall(byte))
        }

    hist_divisor=float(raw_obj['printables']) if raw_obj['printables'] > 0 else 1.0
    return np.hstack([
            raw_obj['numstrings'], raw_obj['avlength'], raw_obj['printables'],
            np.asarray(raw_obj['printabledist']) / hist_divisor, raw_obj['entropy'], raw_obj['paths'], raw_obj['urls'],
            raw_obj['registry'], raw_obj['MZ']
        ]).astype(np.float32)


def Data_Directories(byte,lief_binary):
    output=[]
    name_order=["EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE", "CERTIFICATE_TABLE",
            "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE",
            "BOUND_IMPORT", "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER"]
    if lief_binary is None:
        return output
    for d in lief_binary.data_directories:
        output.append({
            "name":str(d.type).replace("DATA_DIRECTORY.",""),
            "size":d.size,
            "virtual_address":d.rva
            })
    dir_features = np.zeros(2 * len(name_order), dtype=np.float32)
    for i in range(len(name_order)):
        if i < len(output):
            dir_features[2 * i] = output[i]["size"]
            dir_features[2 * i + 1] = output[i]["virtual_address"]
    return dir_features


def bytes_read(file_path):
    with open(file_path,'rb') as f:
        b=f.read()
        return b

def read_exe(file_name):
    with open(file_name, 'rb') as f:
        bytes_data = f.read()
    return ByteHistogram(bytes_data)

def ByteHistogram(bytes_data):
    a = np.bincount(np.frombuffer(bytes_data, dtype=np.uint8), minlength=256)
    count_sum = a.sum()
    normalised = a / count_sum
    return normalised

def Entropy_histogram(histogram):
    entropy = -np.sum(histogram[histogram > 0] * np.log2(histogram[histogram > 0]))
    return entropy
    
# [Your existing functions like get_file_hashes, sections_info, Import_features, etc., remain unchanged until process_files]

def process_files(file_path,file):
      #file_path -> refers the bytes
      #file -> file path
    pe = lief.parse(file)
    by = file_path     # Extract features from all functions
    section_features = sections_info(file_path,file)
    import_features = Import_features(file_path, pe)
    export_features = Export_features(by, pe)
    general_features = general_Info(by, pe)
    header_features = Header_File_Info(by, pe)
    string_features = String_Extractor(by, pe)
    dir_features = Data_Directories(by, pe)
    byte_histogram = read_exe(file)
    histogram_entropy = Entropy_histogram(byte_histogram)

            # Skip if parsing failed
    if section_features is None or pe is None:
        print(f"Skipping {file} due to parsing failure")

            # Combine section-related arrays into a single 1D array
    section_combined = np.hstack([
        section_features["general"],
        section_features["sec_size_hash"],
        section_features["sec_entropy_hash"],
        section_features["sec_vsize_hash"],
        section_features["characteristics_hashed"]
    ])

            # Create a dictionary with one column per function's output
    file_features = {
        "file_name": section_features["file_name"],  # Optional metadata
        "sections": section_combined,                # 200 elements (4 x 50) + 5
        "imports": import_features,                  # 1280 elements (256 + 1024)
        "exports": export_features,                  # 128 elements
        "general": general_features,                 # 10 elements
        "header": header_features,                   # 62 elements
        "strings": string_features,                  # 104 elements
        "directories": dir_features,                 # 30 elements
        "byte_histogram": byte_histogram,            # 256 elements
        "histogram_entropy": np.array([histogram_entropy])  # 1 element
    }

            # Append this file's features to the list
    return file_features

