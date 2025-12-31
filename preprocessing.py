import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
import pickle
import os

# Define column names for NSL-KDD dataset
COL_NAMES = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]

# Path configs
DATA_PATH = os.path.join(os.path.dirname(__file__), 'data')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model')
ENCODER_PATH = os.path.join(MODEL_PATH, 'encoders.pkl')
SCALER_PATH = os.path.join(MODEL_PATH, 'scaler.pkl')

def load_data(file_name='KDDTrain+.txt'):
    """Loads the dataset from the data directory."""
    file_path = os.path.join(DATA_PATH, file_name)
    if not os.path.exists(file_path):
        # Fallback to dummy data if main file doesn't exist
        print(f"Dataset not found at {file_path}. Looking for dummy.csv...")
        file_path = os.path.join(DATA_PATH, 'dummy.csv')
        if not os.path.exists(file_path):
            create_dummy_data()
    
    print(f"Loading data from {file_path}...")
    df = pd.read_csv(file_path, names=COL_NAMES, index_col=False)
    return df

def create_dummy_data():
    """Creates a small dummy dataset for testing functionality."""
    print("Creating dummy dataset...")
    if not os.path.exists(DATA_PATH):
        os.makedirs(DATA_PATH)
    
    # generate random data
    rows = 100
    data = {col: np.random.randint(0, 100, rows) for col in COL_NAMES}
    df = pd.DataFrame(data)
    
    # Fix categorical columns
    df['protocol_type'] = np.random.choice(['tcp', 'udp', 'icmp'], rows)
    df['service'] = np.random.choice(['http', 'private', 'domain_u', 'smtp', 'ftp_data'], rows)
    df['flag'] = np.random.choice(['SF', 'S0', 'REJ'], rows)
    df['label'] = np.random.choice(['normal', 'neptune', 'warezclient', 'ipsweep'], rows)
    
    df.to_csv(os.path.join(DATA_PATH, 'dummy.csv'), index=False, header=False)
    print("Dummy dataset created at data/dummy.csv")

def preprocess_data(df, is_training=True):
    """
    Preprocesses the dataframe: encoding, scaling.
    If is_training=True, fits and saves encoders/scalers.
    If is_training=False, loads and applies encoders/scalers.
    """
    # 1. Encoding Labels (Binary Classification: Normal vs Attack)
    # We map 'normal' to 0, anything else to 1
    labels = df['label'].apply(lambda x: 0 if x == 'normal' else 1).values
    df = df.drop('label', axis=1)
    
    # 2. Handle Categorical Features using Label Encoding
    # In a real rigorous production system, OneHotEncoding is often better for CNNs, 
    # but LabelEncoding works okay for this demo and keeps dimensions manageable.
    cat_cols = ['protocol_type', 'service', 'flag']
    
    if is_training:
        encoders = {}
        for col in cat_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le
        
        # Save encoders
        if not os.path.exists(MODEL_PATH):
            os.makedirs(MODEL_PATH)
        with open(ENCODER_PATH, 'wb') as f:
            pickle.dump(encoders, f)
    else:
        # Load encoders
        with open(ENCODER_PATH, 'rb') as f:
            encoders = pickle.load(f)
        for col in cat_cols:
            le = encoders[col]
            # Handle unseen labels by mapping to a default or skipping (simplified here)
            # using map and fillna for safety
            df[col] = df[col].map(lambda s: le.transform([s])[0] if s in le.classes_ else 0)
            
            
    # 3. Scale Numerical Features
    if is_training:
        scaler = StandardScaler()
        df = pd.DataFrame(scaler.fit_transform(df), columns=df.columns)
        with open(SCALER_PATH, 'wb') as f:
            pickle.dump(scaler, f)
    else:
        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
        df = pd.DataFrame(scaler.transform(df), columns=df.columns)
        
    # Reshape for CNN (samples, features, 1)
    X = df.values
    X = np.reshape(X, (X.shape[0], X.shape[1], 1))
    
    return X, labels
