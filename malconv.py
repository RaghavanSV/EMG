from keras.models import load_model
def classifier(file_name):
    model = load_model('/kaggle/input/classifier/keras/default/1/malconv.h5',compile=False)
    
    # To predict on an EXE file:
    file_path="/kaggle/input/input-exe/"+file_name
    with open(file_path, 'rb') as f:
        bytez = f.read()
    
    import numpy as np
    
    padding_char = 256
    maxlen = 2**20  # 1MB
    
    def bytez_to_numpy(bytez, maxlen=maxlen):
        b = np.ones((maxlen,), dtype=np.uint16) * padding_char
        bytez = np.frombuffer(bytez[:maxlen], dtype=np.uint8)
        b[:len(bytez)] = bytez
        return b
    
    X = np.expand_dims(bytez_to_numpy(bytez), axis=0)
    
    output = model.predict(X)
    return output