import pandas as pd
from sklearn.preprocessing import StandardScaler

def preprocess_data(file_path):
    data = pd.read_csv(file_path)

    # Select numerical features
    features = data[['packet_count', 'failed_logins', 'session_duration']]

    # Normalize features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    return scaled_features, data
