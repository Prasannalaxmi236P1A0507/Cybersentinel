import pandas as pd
from sklearn.preprocessing import StandardScaler

def preprocess_data(file):

    # Handle both uploaded file (Streamlit) and file path
    if hasattr(file, "read"):
        data = pd.read_csv(file)
    else:
        data = pd.read_csv(file)

    # Keep original data
    original_data = data.copy()

    # Select only numeric columns for ML
    numeric_data = data.select_dtypes(include=['number'])

    # Handle case if no numeric data
    if numeric_data.empty:
        raise ValueError("No numeric columns found in dataset")

    # Fill missing values
    numeric_data = numeric_data.fillna(numeric_data.mean())

    # Scale data
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(numeric_data)

    return scaled_data, original_data